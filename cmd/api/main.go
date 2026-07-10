package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/arphost/sentinelmail-gateway/internal/bootstrap"
	"github.com/arphost/sentinelmail-gateway/internal/config"
	"github.com/arphost/sentinelmail-gateway/internal/db"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi"
	"github.com/arphost/sentinelmail-gateway/internal/threatfeed"
)

// version is injected at build time via -ldflags="-X main.version=..."
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "serve":
		return serve()
	case "healthcheck":
		return healthcheck()
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (expected: serve|healthcheck|version)", cmd)
	}
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	log.Info("api.start", slog.String("version", version), slog.String("env", cfg.Env), slog.String("addr", cfg.HTTPAddr))

	// Apply schema + seed admin before opening the pgxpool so the first
	// `docker compose up -d` lands at a working login. SeedIfEmpty no-ops
	// when an org already exists.
	if os.Getenv("SMG_AUTO_MIGRATE") != "false" {
		if err := bootstrap.MigrateAndSeed(ctx, cfg.DatabaseURL); err != nil {
			return fmt.Errorf("auto-migrate: %w", err)
		}
	}

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("redis url: %w", err)
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()

	// Threat-feed registry — runs as a background goroutine, lookups are
	// non-blocking, and per-feed errors NEVER block mail flow (the registry
	// downgrades them to misses).
	feedRegistry := threatfeed.NewRegistry(log, pool, rdb)
	feedRegistry.Add(threatfeed.NewDNSBL("spamhaus_zen", "zen.spamhaus.org"))
	feedRegistry.Add(threatfeed.NewDNSBL("spamhaus_dbl", "dbl.spamhaus.org"))
	feedRegistry.Add(threatfeed.NewDNSBL("spamcop", "bl.spamcop.net"))
	feedRegistry.Add(threatfeed.NewURLhaus(nil))
	feedRegistry.Start(ctx)
	defer feedRegistry.Stop()

	startMessageRetentionPurgeLoop(ctx, log, pool)

	// In prod we expect to sit behind TLS termination (nginx/web container or external LB).
	// Honor X-Forwarded-Proto via middleware.RealIP; mark cookies Secure unless explicit dev.
	secureCookies := cfg.Env != "dev"

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpapi.New(log, pool, rdb, version, secureCookies, []byte(cfg.IngestHMACKey), []byte(cfg.SessionSecret)).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("api.shutdown")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func startMessageRetentionPurgeLoop(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool) {
	run := func() {
		purgeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var purgedEntries, purgedBlobs, purgedMailbox int64
		err := pool.QueryRow(purgeCtx, `
			WITH org_retention AS (
				SELECT o.id AS organization_id,
				       GREATEST(1, LEAST(365, COALESCE(
				         (SELECT (s.value #>> '{}')::int
				            FROM system_settings s
				           WHERE s.organization_id = o.id
				             AND s.key = 'message.retention_days'),
				         (SELECT (s.value #>> '{}')::int
				            FROM system_settings s
				           WHERE s.organization_id = o.id
				             AND s.key = 'quarantine.retention_days'),
				         (SELECT (s.value #>> '{}')::int
				            FROM system_settings s
				           WHERE s.organization_id IS NULL
				             AND s.key = 'message.retention_days'),
				         (SELECT (s.value #>> '{}')::int
				            FROM system_settings s
				           WHERE s.organization_id IS NULL
				             AND s.key = 'quarantine.retention_days'),
				         90
				       ))) AS retention_days
				  FROM organizations o
			),
			quarantine_candidates AS (
				SELECT qe.id
				  FROM quarantine_entries qe
				  JOIN org_retention r ON r.organization_id = qe.organization_id
				 WHERE (qe.expires_at IS NOT NULL AND qe.expires_at <= now())
				    OR qe.received_at < now() - (r.retention_days * interval '1 day')
			),
			deleted_blobs AS (
				DELETE FROM quarantine_blobs
				 WHERE quarantine_entry_id IN (SELECT id FROM quarantine_candidates)
				RETURNING 1
			),
			deleted_entries AS (
				DELETE FROM quarantine_entries
				 WHERE id IN (SELECT id FROM quarantine_candidates)
				RETURNING 1
			),
			mailbox_candidates AS (
				SELECT mm.id
				  FROM mailbox_messages mm
				  JOIN org_retention r ON r.organization_id = mm.organization_id
				 WHERE mm.received_at < now() - (r.retention_days * interval '1 day')
			),
			deleted_mailbox AS (
				DELETE FROM mailbox_messages
				 WHERE id IN (SELECT id FROM mailbox_candidates)
				RETURNING 1
			)
			SELECT (SELECT count(*) FROM deleted_entries)::bigint,
			       (SELECT count(*) FROM deleted_blobs)::bigint,
			       (SELECT count(*) FROM deleted_mailbox)::bigint
		`).Scan(&purgedEntries, &purgedBlobs, &purgedMailbox)
		if err != nil {
			log.Warn("message_retention.purge_failed", slog.String("error", err.Error()))
			return
		}
		if purgedEntries > 0 || purgedBlobs > 0 || purgedMailbox > 0 {
			log.Info("message_retention.purge_ok",
				slog.Int64("quarantine_entries", purgedEntries),
				slog.Int64("quarantine_blobs", purgedBlobs),
				slog.Int64("mailbox_messages", purgedMailbox))
		}
	}
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run()
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

// healthcheck is invoked by Docker HEALTHCHECK; bypasses full config to avoid
// requiring DB creds inside the healthcheck context. Just hits /healthz on the
// configured port (or default 8080).
func healthcheck() error {
	addr := os.Getenv("SMG_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	port := addr
	if strings.HasPrefix(addr, ":") {
		port = addr
	} else if _, p, err := net.SplitHostPort(addr); err == nil {
		port = ":" + p
	}
	url := "http://127.0.0.1" + port + "/healthz"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("healthcheck status %d", resp.StatusCode)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
