// Package bootstrap runs database migrations and the initial admin seed.
// Callers can either invoke each step individually (used by the migrate CLI)
// or call MigrateAndSeed which opens its own *sql.DB and chains them.
//
// The api serve loop calls MigrateAndSeed before opening its pgxpool so a
// fresh `docker compose up -d` lands at a working login screen — no
// `/app/migrate up && /app/migrate seed` second step required.
package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/migrations"
)

// Migrate applies all pending goose migrations against db.
func Migrate(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("bootstrap: goose dialect: %w", err)
	}
	if err := goose.RunContext(ctx, "up", db, "sql"); err != nil {
		return fmt.Errorf("bootstrap: migrate up: %w", err)
	}
	return nil
}

// SeedIfEmpty creates the System organization and a super_admin user when
// the organizations table is empty. No-op on subsequent calls — safe to run
// on every startup. The admin email/password come from SMG_SEED_ADMIN_EMAIL
// / SMG_SEED_ADMIN_PASSWORD, otherwise email defaults to admin@sentinelmail.local
// and the password is randomly generated and printed on stdout.
func SeedIfEmpty(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM organizations").Scan(&count); err != nil {
		return fmt.Errorf("bootstrap: count orgs: %w", err)
	}
	if count > 0 {
		return nil
	}

	email := strings.TrimSpace(strings.ToLower(os.Getenv("SMG_SEED_ADMIN_EMAIL")))
	if email == "" {
		email = "admin@sentinelmail.local"
	}
	password := os.Getenv("SMG_SEED_ADMIN_PASSWORD")
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

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var orgID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO organizations (name, slug, is_system) VALUES ($1, $2, true) RETURNING id`,
		"System", "system").Scan(&orgID); err != nil {
		return fmt.Errorf("bootstrap: create org: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (organization_id, email, password_hash, role, is_active)
		 VALUES ($1, $2, $3, 'super_admin', true)`,
		orgID, email, hash); err != nil {
		return fmt.Errorf("bootstrap: create user: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if generated {
		fmt.Println("bootstrap: generated admin password:", password)
	}
	fmt.Printf("bootstrap: admin user created: %s\n", email)
	return nil
}

// MigrateAndSeed opens its own database/sql connection (separate from any
// pgxpool the caller is using), runs Migrate + SeedIfEmpty, and closes the
// connection. Intended for the api serve loop.
func MigrateAndSeed(ctx context.Context, dbURL string) error {
	if dbURL == "" {
		return errors.New("bootstrap: empty database url")
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("bootstrap: sql.Open: %w", err)
	}
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		return err
	}
	return SeedIfEmpty(ctx, db)
}
