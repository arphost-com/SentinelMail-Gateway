package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

const (
	MFAIssuer        = "SentinelMail Gateway"
	MFAPendingTTL    = 5 * time.Minute
	mfaPendingCookie = "smg_mfa"
)

// ---------- enrollment ----------

// MFASetup generates a fresh TOTP secret, stores it in mfa_secret (NOT yet
// enrolled — that happens after MFAConfirm), and returns the otpauth URL,
// raw base32 secret, and a base64-encoded PNG QR code.
func MFASetup(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, accountName string) (otpauth, secret, qrB64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      MFAIssuer,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		return "", "", "", err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return "", "", "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", "", err
	}
	if _, err := db.Exec(ctx,
		`UPDATE users SET mfa_secret = $1, mfa_enrolled_at = NULL, updated_at = now() WHERE id = $2`,
		key.Secret(), userID); err != nil {
		return "", "", "", err
	}
	return key.URL(), key.Secret(), base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// MFAConfirm validates a code against the user's pending secret and, on
// success, marks them enrolled.
func MFAConfirm(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, code string) error {
	secret, _, err := loadMFA(ctx, db, userID)
	if err != nil {
		return err
	}
	if secret == "" {
		return errors.New("no pending MFA secret; call setup first")
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	_, err = db.Exec(ctx,
		`UPDATE users SET mfa_enrolled_at = now(), updated_at = now() WHERE id = $1`, userID)
	return err
}

// MFADisable validates a code then clears the secret + enrolled_at.
func MFADisable(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, code string) error {
	secret, enrolled, err := loadMFA(ctx, db, userID)
	if err != nil {
		return err
	}
	if !enrolled || secret == "" {
		return errors.New("MFA not enrolled")
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	_, err = db.Exec(ctx,
		`UPDATE users SET mfa_secret = NULL, mfa_enrolled_at = NULL, updated_at = now() WHERE id = $1`, userID)
	return err
}

// MFAVerify checks a code at login. Used by the verify step after
// password authentication.
func MFAVerify(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, code string) error {
	secret, enrolled, err := loadMFA(ctx, db, userID)
	if err != nil {
		return err
	}
	if !enrolled || secret == "" {
		return errors.New("MFA not enrolled")
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	return nil
}

func loadMFA(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) (secret string, enrolled bool, err error) {
	var sec *string
	var enrolledAt *time.Time
	err = db.QueryRow(ctx,
		`SELECT mfa_secret, mfa_enrolled_at FROM users WHERE id = $1`, userID).Scan(&sec, &enrolledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, errors.New("user not found")
		}
		return "", false, err
	}
	if sec != nil {
		secret = *sec
	}
	enrolled = enrolledAt != nil
	return
}

// ---------- pending-MFA cookie (short-lived bearer) ----------

// MFAPendingChallenge is the body returned by /auth/login when the user has
// MFA enrolled. Client posts the same challenge back to /auth/mfa/verify
// along with the TOTP code.
type MFAPendingChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueMFAChallenge mints a short-lived signed token bound to the user. The
// token has the user_id and an expiration timestamp; signed with sha256(secret)
// truncated to 32 bytes (the same SMG_SESSION_SECRET we already require to be
// >= 32 chars).
func IssueMFAChallenge(secret []byte, userID uuid.UUID) MFAPendingChallenge {
	exp := time.Now().Add(MFAPendingTTL)
	body := fmt.Sprintf("%s:%d", userID.String(), exp.Unix())
	mac := signChallenge(secret, body)
	tok := base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString(mac)
	return MFAPendingChallenge{Challenge: tok, ExpiresAt: exp}
}

// ParseMFAChallenge returns the user_id from a challenge if it's signed by us
// and not expired.
func ParseMFAChallenge(secret []byte, token string) (uuid.UUID, error) {
	parts := bytes.SplitN([]byte(token), []byte("."), 2)
	if len(parts) != 2 {
		return uuid.Nil, errors.New("malformed challenge")
	}
	body, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return uuid.Nil, errors.New("bad challenge body")
	}
	mac, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return uuid.Nil, errors.New("bad challenge mac")
	}
	want := signChallenge(secret, string(body))
	if !bytes.Equal(want, mac) {
		return uuid.Nil, errors.New("challenge signature mismatch")
	}
	var uidStr string
	var exp int64
	if _, err := fmt.Sscanf(string(body), "%36s:%d", &uidStr, &exp); err != nil {
		return uuid.Nil, errors.New("malformed challenge payload")
	}
	if time.Now().Unix() >= exp {
		return uuid.Nil, errors.New("challenge expired")
	}
	return uuid.Parse(uidStr)
}

func signChallenge(secret []byte, body string) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte("|mfa|"))
	h.Write([]byte(body))
	return h.Sum(nil)
}

// ---------- HTTP handlers (mounted by server.go inside auth group) ----------

type MFAHandlers struct {
	DB             *pgxpool.Pool
	ChallengeKey   []byte // session secret reused
	AuditWrite     func(action string, userID, orgID uuid.UUID, ip string, detail map[string]any)
}

type mfaSetupResp struct {
	OTPAuthURL string `json:"otpauth_url"`
	Secret     string `json:"secret_base32"`
	QRPNG      string `json:"qr_png_base64"`
}

func (h *MFAHandlers) Setup(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	otp, secret, qr, err := MFASetup(r.Context(), h.DB, ident.UserID, ident.Email)
	if err != nil {
		http.Error(w, "setup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if h.AuditWrite != nil {
		h.AuditWrite("auth.mfa.setup", ident.UserID, ident.OrganizationID, clientIPString(r), nil)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mfaSetupResp{OTPAuthURL: otp, Secret: secret, QRPNG: qr})
}

type codeReq struct {
	Code string `json:"code"`
}

func (h *MFAHandlers) Confirm(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var req codeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := MFAConfirm(r.Context(), h.DB, ident.UserID, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if h.AuditWrite != nil {
		h.AuditWrite("auth.mfa.enrolled", ident.UserID, ident.OrganizationID, clientIPString(r), nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *MFAHandlers) Disable(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFrom(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var req codeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := MFADisable(r.Context(), h.DB, ident.UserID, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if h.AuditWrite != nil {
		h.AuditWrite("auth.mfa.disabled", ident.UserID, ident.OrganizationID, clientIPString(r), nil)
	}
	w.WriteHeader(http.StatusNoContent)
}
