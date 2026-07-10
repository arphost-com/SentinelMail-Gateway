package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Handlers struct {
	DB     *pgxpool.Pool
	Store  *Store
	Secure bool // set Secure on session cookie (true in prod, false in plain HTTP dev)
	// AuditWrite optionally records auth events. nil = disabled (e.g. in
	// tests). Wired by the server with internal/audit.Write to keep this
	// package import-free of audit (avoids cycle if audit ever imports auth).
	AuditWrite func(action string, userID, orgID uuid.UUID, ip string, detail map[string]any)
	// ChallengeKey signs the short-lived MFA challenge tokens. Reuses
	// SMG_SESSION_SECRET. Must be >= 32 bytes for the path to engage.
	ChallengeKey []byte
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type meResp struct {
	UserID            string `json:"user_id"`
	OrganizationID    string `json:"organization_id"`
	Email             string `json:"email"`
	Role              string `json:"role"`
	Impersonating     bool   `json:"impersonating,omitempty"`
	ImpersonatorEmail string `json:"impersonator_email,omitempty"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	var (
		userID, orgID uuid.UUID
		hash          string
		active        bool
		mfaEnrolled   *time.Time
	)
	err := h.DB.QueryRow(r.Context(),
		`SELECT id, organization_id, password_hash, is_active, mfa_enrolled_at FROM users WHERE email = $1`,
		req.Email).Scan(&userID, &orgID, &hash, &active, &mfaEnrolled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Run a dummy verify to keep timing roughly equal.
			_ = VerifyPassword(req.Password, "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if !active {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err := VerifyPassword(req.Password, hash); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// MFA enrolled → don't issue a session yet. Hand the client a signed
	// short-lived challenge; they post it back to /auth/mfa/verify with
	// a TOTP code to complete login.
	if mfaEnrolled != nil && len(h.ChallengeKey) >= 32 {
		ch := IssueMFAChallenge(h.ChallengeKey, userID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "mfa_required",
			"challenge":  ch.Challenge,
			"expires_at": ch.ExpiresAt,
		})
		return
	}

	sess, err := h.Store.Create(r.Context(), userID, orgID, r.UserAgent(), clientIP(r))
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	// Secure is wired from cfg.Env != "dev". Production deploys set SMG_ENV=prod
	// so this is always true outside an explicit local-HTTP dev loop.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	_, _ = h.DB.Exec(r.Context(),
		`UPDATE users SET last_login_at = now(), failed_login_count = 0 WHERE id = $1`, userID)

	// Audit hook — best effort; never gates the response.
	if h.AuditWrite != nil {
		h.AuditWrite("auth.login", userID, orgID, clientIPString(r), nil)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// MFAVerifyLogin completes a login that returned mfa_required. Caller posts
// {challenge, code}; we verify both and then issue the real session cookie.
func (h *Handlers) MFAVerifyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userID, err := ParseMFAChallenge(h.ChallengeKey, req.Challenge)
	if err != nil {
		http.Error(w, "invalid challenge: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if err := MFAVerify(r.Context(), h.DB, userID, req.Code); err != nil {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	var orgID uuid.UUID
	if err := h.DB.QueryRow(r.Context(),
		`SELECT organization_id FROM users WHERE id = $1`, userID).Scan(&orgID); err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	sess, err := h.Store.Create(r.Context(), userID, orgID, r.UserAgent(), clientIP(r))
	if err != nil {
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	_, _ = h.DB.Exec(r.Context(),
		`UPDATE users SET last_login_at = now(), failed_login_count = 0 WHERE id = $1`, userID)
	if h.AuditWrite != nil {
		h.AuditWrite("auth.mfa.login", userID, orgID, clientIPString(r), nil)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

type impersonateReq struct {
	TargetUserID string `json:"target_user_id"`
}

// StartImpersonating mints a new session as the target user and stamps it
// with the current super_admin's id so /me can show the banner and
// /auth/impersonate/stop can swap back. Refuses to nest — you can't
// impersonate from inside an already-impersonated session.
func (h *Handlers) StartImpersonating(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if ident.Role != "super_admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if ident.Impersonator != nil {
		http.Error(w, "already impersonating; stop first", http.StatusConflict)
		return
	}
	var req impersonateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	targetID, err := uuid.Parse(req.TargetUserID)
	if err != nil {
		http.Error(w, "invalid target_user_id", http.StatusBadRequest)
		return
	}
	if targetID == ident.UserID {
		http.Error(w, "cannot impersonate yourself", http.StatusBadRequest)
		return
	}
	var targetOrg uuid.UUID
	var targetEmail string
	if err := h.DB.QueryRow(r.Context(),
		`SELECT organization_id, email FROM users WHERE id = $1 AND is_active = true`,
		targetID).Scan(&targetOrg, &targetEmail); err != nil {
		http.Error(w, "target not found or inactive", http.StatusNotFound)
		return
	}
	// Revoke the admin's current session so they can't sneak back via a stale cookie.
	if c, err := r.Cookie(SessionCookieName); err == nil {
		_ = h.Store.Revoke(r.Context(), c.Value)
	}
	sess, err := h.Store.CreateImpersonated(r.Context(), targetID, targetOrg, ident.UserID, r.UserAgent(), clientIP(r))
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	if h.AuditWrite != nil {
		h.AuditWrite("admin.impersonate.start", ident.UserID, ident.OrganizationID, clientIPString(r), map[string]any{
			"target_user_id": targetID.String(),
			"target_email":   targetEmail,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		// Resolve the identity from the cookie before revoking so the audit
		// entry actually has an actor. Logout sits outside the auth middleware
		// so IdentityFrom(ctx) would be empty here.
		if ident, lookupErr := h.Store.Lookup(r.Context(), c.Value); lookupErr == nil && h.AuditWrite != nil {
			h.AuditWrite("auth.logout", ident.UserID, ident.OrganizationID, clientIPString(r), nil)
		}
		_ = h.Store.Revoke(r.Context(), c.Value)
	}
	// Same Secure-flag rationale as Login above; this cookie has empty value
	// and a -1 MaxAge so it expires immediately regardless.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResp{
		UserID:            ident.UserID.String(),
		OrganizationID:    ident.OrganizationID.String(),
		Email:             ident.Email,
		Role:              ident.Role,
		Impersonating:     ident.Impersonator != nil,
		ImpersonatorEmail: ident.ImpersonatorEmail,
	})
}

// StopImpersonating revokes the current impersonated session and issues a
// fresh session for the original admin. Refuses (409) if the current session
// isn't an impersonated one — that way the button only shows up + works when
// it's actually safe.
func (h *Handlers) StopImpersonating(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if ident.Impersonator == nil {
		http.Error(w, "not impersonating", http.StatusConflict)
		return
	}
	// Look up the admin's org so the new session has the right org context.
	var orgID uuid.UUID
	if err := h.DB.QueryRow(r.Context(),
		`SELECT organization_id FROM users WHERE id = $1 AND is_active = true`,
		*ident.Impersonator).Scan(&orgID); err != nil {
		http.Error(w, "impersonator no longer active", http.StatusGone)
		return
	}
	// Revoke the impersonation session.
	if c, err := r.Cookie(SessionCookieName); err == nil {
		_ = h.Store.Revoke(r.Context(), c.Value)
	}
	// Mint a fresh ordinary session for the admin.
	sess, err := h.Store.Create(r.Context(), *ident.Impersonator, orgID, r.UserAgent(), clientIP(r))
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// clientIPString returns the client IP as a string (or "") for use in audit
// rows that store inet text rather than the binary net.IP form.
func clientIPString(r *http.Request) string {
	if ip := clientIP(r); ip != nil {
		return ip.String()
	}
	return ""
}

func clientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma > 0 {
			xff = xff[:comma]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
