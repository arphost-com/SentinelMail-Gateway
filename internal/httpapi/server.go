// Package httpapi exposes the chi-based HTTP server for the gateway control plane.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/arphost/sentinelmail-gateway/internal/audit"
	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/billing"
	"github.com/arphost/sentinelmail-gateway/internal/cluster"
	"github.com/arphost/sentinelmail-gateway/internal/domains"
	"github.com/arphost/sentinelmail-gateway/internal/gateways"
	"github.com/arphost/sentinelmail-gateway/internal/mail"
	"github.com/arphost/sentinelmail-gateway/internal/mailbox"
	"github.com/arphost/sentinelmail-gateway/internal/maillogs"
	"github.com/arphost/sentinelmail-gateway/internal/orgs"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
	"github.com/arphost/sentinelmail-gateway/internal/quarantine"
	"github.com/arphost/sentinelmail-gateway/internal/reports"
	"github.com/arphost/sentinelmail-gateway/internal/scan"
	"github.com/arphost/sentinelmail-gateway/internal/senderlists"
	"github.com/arphost/sentinelmail-gateway/internal/sentemails"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
	"github.com/arphost/sentinelmail-gateway/internal/smtpevents"
	"github.com/arphost/sentinelmail-gateway/internal/threatfeed"
	"github.com/arphost/sentinelmail-gateway/internal/users"
)

type Server struct {
	log           *slog.Logger
	db            *pgxpool.Pool
	rdb           *redis.Client
	version       string
	secure        bool
	ingestSecret  []byte
	sessionSecret []byte // reused as MFA challenge signer
	router        *chi.Mux
}

func New(log *slog.Logger, db *pgxpool.Pool, rdb *redis.Client, version string, secure bool, ingestSecret, sessionSecret []byte) *Server {
	s := &Server{log: log, db: db, rdb: rdb, version: version, secure: secure, ingestSecret: ingestSecret, sessionSecret: sessionSecret}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) routes() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger(s.log))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealth)

	store := auth.NewStore(s.db)
	db := s.db
	auditFn := func(action string, userID, orgID uuid.UUID, ip string, detail map[string]any) {
		audit.WriteAsync(db, audit.Event{
			OrganizationID: orgID,
			ActorUserID:    userID,
			ActorIP:        ip,
			Action:         action,
			Detail:         detail,
		})
	}
	handlers := &auth.Handlers{
		DB:           s.db,
		Store:        store,
		Secure:       s.secure,
		AuditWrite:   auditFn,
		ChallengeKey: s.sessionSecret,
	}
	mfaHandlers := &auth.MFAHandlers{DB: s.db, ChallengeKey: s.sessionSecret, AuditWrite: auditFn}
	authMW := auth.Middleware(store)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/healthz", s.handleAPIHealth)

		r.Post("/auth/login", handlers.Login)
		r.Post("/auth/logout", handlers.Logout)
		r.Post("/auth/mfa/verify", handlers.MFAVerifyLogin) // unauthenticated — signed challenge proves prior password

		// HMAC-authenticated callbacks (rspamd, worker) — no session.
		if len(s.ingestSecret) >= 16 {
			r.Route("/mail", func(r chi.Router) { mail.MountIngest(r, s.db, s.rdb, s.ingestSecret) })
			r.Route("/smtp", func(r chi.Router) { smtpevents.MountPublic(r, s.db, s.ingestSecret) })
			r.Route("/scan-callback", func(r chi.Router) { scan.MountWorker(r, s.db, s.ingestSecret) })
			r.Route("/billing-webhooks", func(r chi.Router) { billing.MountPublic(r, s.db, s.ingestSecret) })
		}

		r.Group(func(r chi.Router) {
			r.Use(authMW)
			r.Get("/me", handlers.Me)
			r.Post("/auth/mfa/setup", mfaHandlers.Setup)
			r.Post("/auth/mfa/confirm", mfaHandlers.Confirm)
			r.Post("/auth/mfa/disable", mfaHandlers.Disable)
			r.Post("/auth/impersonate/start", handlers.StartImpersonating)
			r.Post("/auth/impersonate/stop", handlers.StopImpersonating)
			r.Route("/orgs", func(r chi.Router) { orgs.Mount(r, s.db) })
			r.Route("/domains", func(r chi.Router) { domains.Mount(r, s.db) })
			r.Route("/gateways", func(r chi.Router) { gateways.Mount(r, s.db) })
			r.Route("/policies", func(r chi.Router) { policies.Mount(r, s.db) })
			r.Route("/quarantine", func(r chi.Router) { quarantine.Mount(r, s.db) })
			r.Route("/mailbox", func(r chi.Router) { mailbox.Mount(r, s.db) })
			r.Route("/mail-logs", func(r chi.Router) { maillogs.Mount(r, s.db) })
			r.Route("/reports", func(r chi.Router) { reports.Mount(r, s.db) })
			r.Route("/billing", func(r chi.Router) { billing.Mount(r, s.db) })
			r.Route("/cluster", func(r chi.Router) { cluster.Mount(r, s.db, s.version) })
			r.Route("/users", func(r chi.Router) { users.Mount(r, s.db) })
			r.Route("/system/settings", func(r chi.Router) { settings.Mount(r, s.db) })
			r.Route("/org-settings", func(r chi.Router) { settings.MountOrg(r, s.db) })
			r.Route("/sender-lists", func(r chi.Router) { senderlists.Mount(r, s.db) })
			r.Route("/threat-feeds", func(r chi.Router) { threatfeed.MountHandler(r, s.db) })
			r.Route("/scan", func(r chi.Router) { scan.MountSession(r, s.db, s.rdb, s.ingestSecret) })
			r.Route("/audit-log", func(r chi.Router) { audit.Mount(r, s.db) })
			r.Route("/smtp-events", func(r chi.Router) { smtpevents.Mount(r, s.db) })
			r.Route("/sent-emails", func(r chi.Router) { sentemails.Mount(r, s.db) })
		})
	})

	s.router = r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "ok",
		"version": s.version,
		"checks":  map[string]string{},
	}
	checks := resp["checks"].(map[string]string)

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.Ping(ctx); err != nil {
		checks["db"] = "error: " + err.Error()
		resp["status"] = "degraded"
	} else {
		checks["db"] = "ok"
	}

	if err := s.rdb.Ping(ctx).Err(); err != nil {
		checks["redis"] = "error: " + err.Error()
		resp["status"] = "degraded"
	} else {
		checks["redis"] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	if resp["status"] != "ok" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.LogAttrs(r.Context(), slog.LevelInfo, "http",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("took", time.Since(start)),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)
		})
	}
}
