// Package users implements /api/v1/users — user administration UI.
package users

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type User struct {
	ID                     uuid.UUID  `json:"id"`
	OrganizationID         uuid.UUID  `json:"organization_id"`
	Email                  string     `json:"email"`
	Role                   string     `json:"role"`
	DisplayName            *string    `json:"display_name,omitempty"`
	IsActive               bool       `json:"is_active"`
	MFAEnrolled            bool       `json:"mfa_enrolled"`
	PhishingAlertFrequency string     `json:"phishing_alert_frequency"`
	BulkCompletionNotify   string     `json:"bulk_completion_notification"`
	LastLoginAt            *time.Time `json:"last_login_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

const cols = `id, organization_id, email, role::text, display_name,
              is_active, (mfa_enrolled_at IS NOT NULL) AS mfa_enrolled,
              phishing_alert_frequency, bulk_completion_notification, last_login_at, created_at, updated_at`

func scan(row pgx.Row, u *User) error {
	return row.Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.DisplayName,
		&u.IsActive, &u.MFAEnrolled, &u.PhishingAlertFrequency, &u.BulkCompletionNotify, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Get("/{id}", h.read)
	r.Patch("/{id}", h.update)
	r.Delete("/{id}", h.del)
	r.Post("/{id}/password", h.setPassword)
	r.Post("/{id}/mfa/disable", h.adminDisableMFA)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	// org_user must not be able to enumerate other people in the org.
	// The UI hides the Users page from them already; this is defence
	// in depth so the API matches.
	if ident.Role == "org_user" {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	page := httpx.ParsePage(r)
	q := r.URL.Query()

	var (
		clauses []string
		args    []any
	)
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("organization_id = ANY($%d)", len(args)))
	}
	if oid := q.Get("organization_id"); oid != "" {
		if id, err := uuid.Parse(oid); err == nil {
			args = append(args, id)
			clauses = append(clauses, fmt.Sprintf("organization_id = $%d", len(args)))
		}
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` is built from clause strings that only contain $N placeholders;
	// user values flow via `args...`.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM users`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// Sprintf inputs are integer parameter indices + our own placeholder
	// strings. User values flow via `args...`.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+cols+` FROM users%s ORDER BY email LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))
	items, err := queryAll(r.Context(), h.DB, sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[User]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

type writeReq struct {
	OrganizationID         *uuid.UUID `json:"organization_id,omitempty"`
	Email                  string     `json:"email,omitempty"`
	Role                   string     `json:"role,omitempty"`
	DisplayName            *string    `json:"display_name,omitempty"`
	IsActive               *bool      `json:"is_active,omitempty"`
	Password               string     `json:"password,omitempty"`
	PhishingAlertFrequency string     `json:"phishing_alert_frequency,omitempty"`
	BulkCompletionNotify   string     `json:"bulk_completion_notification,omitempty"`
}

var validRoles = map[string]bool{
	"super_admin": true, "msp_admin": true, "org_admin": true, "org_user": true,
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		httpx.WriteError(w, http.StatusBadRequest, "valid email required")
		return
	}
	if len(req.Password) < 12 {
		httpx.WriteError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}
	if req.Role == "" {
		req.Role = "org_user"
	}
	if !validRoles[req.Role] {
		httpx.WriteError(w, http.StatusBadRequest, "invalid role")
		return
	}
	orgID := ident.OrganizationID
	if req.OrganizationID != nil {
		orgID = *req.OrganizationID
	}
	if !scope.CanAdmin(ident.Role, orgID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden for that organization")
		return
	}
	if !canAssignRole(ident.Role, req.Role) {
		httpx.WriteError(w, http.StatusForbidden, "cannot assign that role")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}

	var u User
	err = scan(h.DB.QueryRow(r.Context(), `
		INSERT INTO users (organization_id, email, password_hash, role, display_name, is_active)
		VALUES ($1, $2, $3, $4::user_role, $5, COALESCE($6, true))
		RETURNING `+cols,
		orgID, req.Email, hash, req.Role, req.DisplayName, req.IsActive), &u)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			httpx.WriteError(w, http.StatusConflict, "user already exists for that organization")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	// org_user can only read their own row (Settings → Account uses this
	// to fetch mfa_enrolled). Higher tiers can read anyone in scope.
	if ident.Role == "org_user" && id != ident.UserID {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	var u User
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM users WHERE id = $1`, id), &u); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.Allows(u.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var u User
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM users WHERE id = $1`, id), &u); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	selfPreferenceUpdate := id == ident.UserID && (req.PhishingAlertFrequency != "" || req.BulkCompletionNotify != "") &&
		req.Email == "" && req.Role == "" && req.DisplayName == nil && req.IsActive == nil
	if !selfPreferenceUpdate && !scope.CanAdmin(ident.Role, u.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if req.Role != "" && !validRoles[req.Role] {
		httpx.WriteError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if req.Role != "" && !canAssignRole(ident.Role, req.Role) {
		httpx.WriteError(w, http.StatusForbidden, "cannot assign that role")
		return
	}
	if req.PhishingAlertFrequency != "" && !validPhishingAlertFrequency(req.PhishingAlertFrequency) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid phishing alert frequency")
		return
	}
	if req.BulkCompletionNotify != "" && !validBulkCompletionNotification(req.BulkCompletionNotify) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid bulk completion notification preference")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `
		UPDATE users SET
		  email        = COALESCE(NULLIF($1,''), email),
		  role         = COALESCE(NULLIF($2,'')::user_role, role),
		  display_name = COALESCE($3, display_name),
		  is_active    = COALESCE($4, is_active),
		  phishing_alert_frequency = COALESCE(NULLIF($5,''), phishing_alert_frequency),
		  bulk_completion_notification = COALESCE(NULLIF($6,''), bulk_completion_notification),
		  updated_at   = now()
		WHERE id = $7
	`, strings.ToLower(req.Email), req.Role, req.DisplayName, req.IsActive, req.PhishingAlertFrequency, req.BulkCompletionNotify, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update failed: "+err.Error())
		return
	}
	h.read(w, r)
}

func validPhishingAlertFrequency(value string) bool {
	switch value {
	case "off", "immediate", "daily", "weekly":
		return true
	default:
		return false
	}
}

func validBulkCompletionNotification(value string) bool {
	switch value {
	case "email", "in_app", "both", "off":
		return true
	default:
		return false
	}
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	if id == ident.UserID {
		httpx.WriteError(w, http.StatusForbidden, "cannot delete yourself")
		return
	}
	var u User
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM users WHERE id = $1`, id), &u); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, u.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM users WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type passwordReq struct {
	Password string `json:"password"`
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var u User
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM users WHERE id = $1`, id), &u); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	// Users can change their own password; admins can change anyone's in their scope.
	if id != ident.UserID && !scope.CanAdmin(ident.Role, u.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req passwordReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 12 {
		httpx.WriteError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hash error")
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, hash, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}
	// Invalidate other sessions for this user (the current one stays valid).
	_, _ = h.DB.Exec(r.Context(),
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, id)
	w.WriteHeader(http.StatusNoContent)
}

// adminDisableMFA clears the target user's MFA enrollment + pending secret
// without requiring a TOTP code. Recovery path for "user lost their phone"
// scenarios. Cannot be used to disable your own MFA — use Settings → Account
// for that (where a code is required).
func (h *Handler) adminDisableMFA(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	if id == ident.UserID {
		httpx.WriteError(w, http.StatusForbidden, "use Settings → Account to manage your own MFA")
		return
	}
	var u User
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM users WHERE id = $1`, id), &u); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, u.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !canAssignRole(ident.Role, u.Role) {
		httpx.WriteError(w, http.StatusForbidden, "cannot reset MFA on a higher-tier admin")
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE users SET mfa_secret = NULL, mfa_enrolled_at = NULL, updated_at = now() WHERE id = $1`,
		id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}
	// Revoke all existing sessions so the user has to re-authenticate.
	_, _ = h.DB.Exec(r.Context(),
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, id)
	w.WriteHeader(http.StatusNoContent)
}

// canAssignRole enforces that admins can only assign roles at or below their own tier.
func canAssignRole(actorRole, targetRole string) bool {
	tier := map[string]int{
		"org_user": 1, "org_admin": 2, "msp_admin": 3, "super_admin": 4,
	}
	return tier[actorRole] >= tier[targetRole]
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]User, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := scan(rows, &u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Errors helper used by tests.
var ErrInvalidPassword = errors.New("password too short")
