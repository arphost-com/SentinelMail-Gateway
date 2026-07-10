package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SessionCookieName = "smg_session"
	SessionTTL        = 12 * time.Hour
	tokenBytes        = 32
)

type Session struct {
	Token          string // raw token, only returned at create time
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	ExpiresAt      time.Time
}

type Identity struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	Email          string
	Role           string
	// Impersonator is the super_admin who started this session via
	// /users/{id}/impersonate. Nil for ordinary sessions.
	Impersonator      *uuid.UUID
	ImpersonatorEmail string
}

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func (s *Store) Create(ctx context.Context, userID, orgID uuid.UUID, ua string, ip net.IP) (*Session, error) {
	return s.createWithImpersonator(ctx, userID, orgID, nil, ua, ip)
}

// CreateImpersonated mints a session for targetUserID but stamps it with the
// originating admin's id, so /me can show the impersonation banner and
// /auth/impersonate/stop can restore the admin's own session.
func (s *Store) CreateImpersonated(ctx context.Context, targetUserID, targetOrgID, impersonatorID uuid.UUID, ua string, ip net.IP) (*Session, error) {
	return s.createWithImpersonator(ctx, targetUserID, targetOrgID, &impersonatorID, ua, ip)
}

func (s *Store) createWithImpersonator(ctx context.Context, userID, orgID uuid.UUID, impersonator *uuid.UUID, ua string, ip net.IP) (*Session, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(SessionTTL)

	var impUUID any
	if impersonator != nil {
		impUUID = *impersonator
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, organization_id, user_agent, ip_addr, expires_at, impersonator_user_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		hash[:], userID, orgID, nullableString(ua), nullableIP(ip), expires, impUUID)
	if err != nil {
		return nil, err
	}
	return &Session{Token: token, UserID: userID, OrganizationID: orgID, ExpiresAt: expires}, nil
}

func (s *Store) Lookup(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, errors.New("empty token")
	}
	hash := sha256.Sum256([]byte(token))
	var ident Identity
	var imp *uuid.UUID
	var impEmail *string
	err := s.db.QueryRow(ctx, `
		SELECT u.id, u.organization_id, u.email, u.role::text,
		       s.impersonator_user_id, imp.email
		FROM   sessions s
		JOIN   users u ON u.id = s.user_id
		LEFT JOIN users imp ON imp.id = s.impersonator_user_id
		WHERE  s.token_hash = $1
		  AND  s.revoked_at IS NULL
		  AND  s.expires_at > now()
		  AND  u.is_active = true
	`, hash[:]).Scan(&ident.UserID, &ident.OrganizationID, &ident.Email, &ident.Role, &imp, &impEmail)
	if err != nil {
		return nil, err
	}
	ident.Impersonator = imp
	if impEmail != nil {
		ident.ImpersonatorEmail = *impEmail
	}
	return &ident, nil
}

func (s *Store) Revoke(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	_, err := s.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hash[:])
	return err
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableIP(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}
