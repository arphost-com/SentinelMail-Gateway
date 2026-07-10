package threatfeed

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
)

type Handler struct{ DB *pgxpool.Pool }

func MountHandler(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Patch("/{feed}", h.update)
}

type configDTO struct {
	Feed             string  `json:"feed"`
	Kind             string  `json:"kind"`
	Enabled          bool    `json:"enabled"`
	RefreshSeconds   int     `json:"refresh_seconds"`
	SourceURL        *string `json:"source_url,omitempty"`
	HasAPIKey        bool    `json:"has_api_key"`
	LastRefreshAt    *time.Time `json:"last_refresh_at,omitempty"`
	LastRefreshOK    *bool      `json:"last_refresh_ok,omitempty"`
	LastRefreshErr   *string    `json:"last_refresh_err,omitempty"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok || (ident.Role != "super_admin" && ident.Role != "msp_admin") {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	configs, err := LoadConfigs(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	out := make([]configDTO, 0, len(configs))
	for _, c := range configs {
		out = append(out, configDTO{
			Feed:           c.Feed,
			Kind:           c.Kind,
			Enabled:        c.Enabled,
			RefreshSeconds: int(c.RefreshInterval.Seconds()),
			SourceURL:      c.SourceURL,
			HasAPIKey:      c.APIKey != nil && *c.APIKey != "",
			LastRefreshAt:  c.LastRefreshAt,
			LastRefreshOK:  c.LastRefreshOK,
			LastRefreshErr: c.LastRefreshErr,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type updateReq struct {
	Enabled        *bool   `json:"enabled,omitempty"`
	RefreshSeconds *int    `json:"refresh_seconds,omitempty"`
	SourceURL      *string `json:"source_url,omitempty"`
	APIKey         *string `json:"api_key,omitempty"`
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok || ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "super_admin required")
		return
	}
	feed := chi.URLParam(r, "feed")
	if feed == "" {
		httpx.WriteError(w, http.StatusBadRequest, "feed required")
		return
	}
	var req updateReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.RefreshSeconds != nil && (*req.RefreshSeconds < 30 || *req.RefreshSeconds > 86_400) {
		httpx.WriteError(w, http.StatusBadRequest, "refresh_seconds out of range [30, 86400]")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `
		UPDATE threat_feed_config SET
		  enabled          = COALESCE($1, enabled),
		  refresh_interval = COALESCE(make_interval(secs => $2::int)::interval, refresh_interval),
		  source_url       = COALESCE($3, source_url),
		  api_key          = COALESCE(NULLIF($4,''), api_key),
		  updated_at       = now()
		WHERE feed = $5
	`, req.Enabled, req.RefreshSeconds, req.SourceURL, req.APIKey, feed); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update: "+err.Error())
		return
	}
	h.list(w, r)
}
