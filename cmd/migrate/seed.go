package main

import (
	"context"
	"database/sql"

	"github.com/arphost/sentinelmail-gateway/internal/bootstrap"
)

// seedDefaults is kept as a thin wrapper so the `migrate seed` subcommand
// still works. The real implementation lives in internal/bootstrap so the
// api serve loop can call the same code on startup.
func seedDefaults(ctx context.Context, db *sql.DB) error {
	return bootstrap.SeedIfEmpty(ctx, db)
}
