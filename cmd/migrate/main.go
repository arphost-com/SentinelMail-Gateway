// migrate is a thin wrapper around goose, embedding the SQL migrations
// so the binary can be invoked inside the API container as `/app/migrate up`.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/arphost/sentinelmail-gateway/internal/config"
	"github.com/arphost/sentinelmail-gateway/internal/migrations"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		args = []string{"up"}
	}

	ctx := context.Background()
	cfg, err := config.Load(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Error("db.open", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		log.Error("goose.dialect", "err", err)
		os.Exit(1)
	}

	cmd := args[0]
	rest := args[1:]
	if err := runGoose(ctx, db, cmd, rest); err != nil {
		log.Error("migrate", "cmd", cmd, "err", err)
		os.Exit(1)
	}
	log.Info("migrate.done", "cmd", cmd)
}

func runGoose(ctx context.Context, db *sql.DB, cmd string, rest []string) error {
	dir := "sql"
	switch cmd {
	case "up", "up-by-one", "down", "down-to", "redo", "reset", "status", "version", "create", "fix", "validate":
		return goose.RunContext(ctx, cmd, db, dir, rest...)
	case "seed":
		return seedDefaults(ctx, db)
	case "reset-admin":
		return resetAdmin(ctx, db, rest)
	default:
		return errors.New("unknown subcommand: " + cmd)
	}
}
