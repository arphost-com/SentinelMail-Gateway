package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
)

// resetAdmin rewrites an admin's password (and optionally their email).
// Used to recover from a lost seed password, rotate an admin out of band,
// or rename the default admin@sentinelmail.local account.
//
// Usage:
//
//	migrate reset-admin <current-email> [new-email]
//
// Behavior:
//   - password is taken from SMG_RESET_PASSWORD, or generated and printed
//   - if [new-email] is provided, the email column is rewritten
//   - MFA enrollment is cleared (forces re-enrollment after recovery)
func resetAdmin(ctx context.Context, db *sql.DB, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: migrate reset-admin <current-email> [new-email]")
	}
	current := strings.ToLower(strings.TrimSpace(args[0]))
	if current == "" {
		return errors.New("reset-admin: empty current email")
	}
	newEmail := current
	if len(args) == 2 {
		newEmail = strings.ToLower(strings.TrimSpace(args[1]))
		if newEmail == "" {
			return errors.New("reset-admin: empty new email")
		}
	}

	password := os.Getenv("SMG_RESET_PASSWORD")
	generated := false
	if password == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		password = hex.EncodeToString(buf)
		generated = true
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	res, err := db.ExecContext(ctx,
		`UPDATE users
		    SET password_hash    = $1,
		        email            = $2,
		        mfa_secret       = NULL,
		        mfa_enrolled_at  = NULL
		  WHERE lower(email) = $3`,
		hash, newEmail, current)
	if err != nil {
		return fmt.Errorf("reset-admin: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("reset-admin: no user with email %q", current)
	}

	if generated {
		fmt.Println("reset-admin: generated password:", password)
	}
	if newEmail != current {
		fmt.Printf("reset-admin: %s renamed to %s (password + MFA reset)\n", current, newEmail)
	} else {
		fmt.Printf("reset-admin: password reset for %s (MFA cleared)\n", current)
	}
	return nil
}
