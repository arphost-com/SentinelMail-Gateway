package brandintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/audit"
	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
)

type Handler struct {
	DB      *pgxpool.Pool
	Catalog *Catalog
	Feed    *PhishTankFeed

	refreshMu  sync.Mutex
	refreshing bool
}

type BrandDTO struct {
	Slug               string          `json:"slug"`
	Name               string          `json:"name"`
	Aliases            []string        `json:"aliases"`
	OfficialDomains    []string        `json:"official_domains"`
	Cues               []string        `json:"cues"`
	Protected          bool            `json:"protected"`
	Priority           int             `json:"priority"`
	Active             bool            `json:"active"`
	Evidence           json.RawMessage `json:"evidence"`
	ManuallyReviewedAt *time.Time      `json:"manually_reviewed_at,omitempty"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type SourceDTO struct {
	Feed           string     `json:"feed"`
	Enabled        bool       `json:"enabled"`
	RefreshSeconds int        `json:"refresh_seconds"`
	SourceURL      *string    `json:"source_url,omitempty"`
	HasAPIKey      bool       `json:"has_api_key"`
	LastRefreshAt  *time.Time `json:"last_refresh_at,omitempty"`
	LastRefreshOK  *bool      `json:"last_refresh_ok,omitempty"`
	LastRefreshErr *string    `json:"last_refresh_err,omitempty"`
	ObservedBrands int        `json:"observed_brands"`
	Refreshing     bool       `json:"refreshing"`
}

type updateBrandRequest struct {
	Name            *string   `json:"name,omitempty"`
	Aliases         *[]string `json:"aliases,omitempty"`
	OfficialDomains *[]string `json:"official_domains,omitempty"`
	Cues            *[]string `json:"cues,omitempty"`
	Protected       *bool     `json:"protected,omitempty"`
	Priority        *int      `json:"priority,omitempty"`
	Active          *bool     `json:"active,omitempty"`
}

type auditHistoryDTO struct {
	Action    string          `json:"action"`
	ActorID   *string         `json:"actor_user_id,omitempty"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

func Mount(r chi.Router, db *pgxpool.Pool, catalog *Catalog) {
	h := &Handler{DB: db, Catalog: catalog, Feed: NewPhishTankFeed(db, nil)}
	r.Get("/", h.list)
	r.Post("/refresh", h.refresh)
	r.Patch("/{slug}", h.update)
	r.Get("/{slug}/history", h.history)
}

func requireBrandAdmin(w http.ResponseWriter, r *http.Request, superOnly bool) (auth.Identity, bool) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok || (superOnly && ident.Role != "super_admin") ||
		(!superOnly && ident.Role != "super_admin" && ident.Role != "msp_admin") {
		message := "admin required"
		if superOnly {
			message = "super_admin required"
		}
		httpx.WriteError(w, http.StatusForbidden, message)
		return auth.Identity{}, false
	}
	return *ident, true
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireBrandAdmin(w, r, false); !ok {
		return
	}
	page := httpx.ParsePage(r)
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	args := []any{}
	where := ""
	if query != "" {
		args = append(args, "%"+strings.ToLower(query)+"%")
		where = ` WHERE lower(pb.name) LIKE $1
			OR lower(pb.slug) LIKE $1
			OR EXISTS (SELECT 1 FROM unnest(pb.aliases) alias WHERE lower(alias) LIKE $1)
			OR EXISTS (SELECT 1 FROM unnest(pb.official_domains) domain_name WHERE lower(domain_name) LIKE $1)`
	}
	var total int
	// The WHERE fragment contains fixed SQL and user input remains parameterized.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM phishing_brands pb`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand count failed")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// The WHERE fragment contains fixed SQL and user input remains parameterized.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`
		SELECT pb.slug, pb.name, pb.aliases, pb.official_domains, pb.cues,
		       pb.protected, pb.priority, pb.active,
		       COALESCE((
		         SELECT jsonb_agg(jsonb_build_object(
		           'source', pbe.source,
		           'source_brand_name', pbe.source_brand_name,
		           'observation_count', pbe.observation_count,
		           'source_rank', pbe.source_rank,
		           'first_seen', pbe.first_seen,
		           'last_seen', pbe.last_seen,
		           'source_url', pbe.source_url,
		           'license_note', pbe.license_note,
		           'refreshed_at', pbe.refreshed_at
		         ) ORDER BY pbe.source_rank NULLS LAST, pbe.source)
		         FROM phishing_brand_evidence pbe
		        WHERE pbe.brand_id = pb.id
		       ), '[]'::jsonb),
		       pb.manually_reviewed_at, pb.updated_at
		  FROM phishing_brands pb
		  %s
		 ORDER BY pb.protected DESC, pb.priority DESC, pb.name
		 LIMIT $%d OFFSET $%d
	`, where, len(args)-1, len(args))
	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand list failed")
		return
	}
	defer rows.Close()
	items := make([]BrandDTO, 0, page.Limit)
	for rows.Next() {
		var item BrandDTO
		if err := rows.Scan(&item.Slug, &item.Name, &item.Aliases, &item.OfficialDomains,
			&item.Cues, &item.Protected, &item.Priority, &item.Active,
			&item.Evidence, &item.ManuallyReviewedAt, &item.UpdatedAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "brand scan failed")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand list failed")
		return
	}
	source, err := h.sourceStatus(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand source status failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "limit": page.Limit, "offset": page.Offset, "sources": source,
	})
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	ident, ok := requireBrandAdmin(w, r, true)
	if !ok {
		return
	}
	slug := normalizeSlug(chi.URLParam(r, "slug"))
	if slug == "" || slug != chi.URLParam(r, "slug") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid brand slug")
		return
	}
	current, err := h.loadBrand(r.Context(), slug)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "brand not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand read failed")
		return
	}
	var req updateBrandRequest
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := mergeBrandUpdate(current, req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.DB.Exec(r.Context(), `
		UPDATE phishing_brands
		   SET name = $2, aliases = $3, official_domains = $4, cues = $5,
		       protected = $6, priority = $7, active = $8,
		       manually_reviewed_at = now(), updated_at = now()
		 WHERE slug = $1
	`, slug, updated.Name, updated.Aliases, updated.OfficialDomains, updated.Cues,
		updated.Protected, updated.Priority, updated.Active)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand update failed")
		return
	}
	if h.Catalog != nil {
		h.Catalog.Invalidate()
	}
	event := audit.FromRequest(r, "phishing_brand.update")
	event.TargetKind = "phishing_brand"
	event.TargetID = slug
	event.Detail = map[string]any{
		"name": updated.Name, "aliases": updated.Aliases, "official_domains": updated.OfficialDomains,
		"cues": updated.Cues, "protected": updated.Protected, "priority": updated.Priority,
		"active": updated.Active, "actor_role": ident.Role,
	}
	audit.WriteAsync(h.DB, event)
	updated.ManuallyReviewedAt = timePointer(time.Now())
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireBrandAdmin(w, r, false); !ok {
		return
	}
	slug := normalizeSlug(chi.URLParam(r, "slug"))
	if slug == "" || slug != chi.URLParam(r, "slug") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid brand slug")
		return
	}
	rows, err := h.DB.Query(r.Context(), `
		SELECT action, actor_user_id::text, COALESCE(detail, '{}'::jsonb), created_at
		  FROM audit_log
		 WHERE target_kind = 'phishing_brand' AND target_id = $1
		 ORDER BY id DESC
		 LIMIT 100
	`, slug)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "brand history failed")
		return
	}
	defer rows.Close()
	items := []auditHistoryDTO{}
	for rows.Next() {
		var item auditHistoryDTO
		if err := rows.Scan(&item.Action, &item.ActorID, &item.Detail, &item.CreatedAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "brand history scan failed")
			return
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	ident, ok := requireBrandAdmin(w, r, true)
	if !ok {
		return
	}
	if !h.beginRefresh() {
		httpx.WriteError(w, http.StatusConflict, "brand refresh already running")
		return
	}
	event := audit.FromRequest(r, "phishing_brand.refresh")
	event.TargetKind = "threat_feed"
	event.TargetID = phishTankFeedName
	event.Detail = map[string]any{"requested_by_role": ident.Role}
	audit.WriteAsync(h.DB, event)
	go h.runRefresh()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"status": "refreshing", "feed": phishTankFeedName,
	})
}

func (h *Handler) beginRefresh() bool {
	h.refreshMu.Lock()
	defer h.refreshMu.Unlock()
	if h.refreshing {
		return false
	}
	h.refreshing = true
	return true
}

func (h *Handler) isRefreshing() bool {
	h.refreshMu.Lock()
	defer h.refreshMu.Unlock()
	return h.refreshing
}

func (h *Handler) runRefresh() {
	defer func() {
		h.refreshMu.Lock()
		h.refreshing = false
		h.refreshMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	err := h.Feed.Refresh(ctx)
	cancel()
	ok := err == nil
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	statusCtx, statusCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer statusCancel()
	_, _ = h.DB.Exec(statusCtx, `
		UPDATE threat_feed_config
		   SET last_refresh_at = now(), last_refresh_ok = $2,
		       last_refresh_err = NULLIF($3, ''), updated_at = now()
		 WHERE feed = $1
	`, phishTankFeedName, ok, errorText)
	if ok && h.Catalog != nil {
		h.Catalog.Invalidate()
	}
}

func (h *Handler) loadBrand(ctx context.Context, slug string) (BrandDTO, error) {
	var item BrandDTO
	err := h.DB.QueryRow(ctx, `
		SELECT slug, name, aliases, official_domains, cues, protected, priority,
		       active, '[]'::jsonb, manually_reviewed_at, updated_at
		  FROM phishing_brands
		 WHERE slug = $1
	`, slug).Scan(&item.Slug, &item.Name, &item.Aliases, &item.OfficialDomains,
		&item.Cues, &item.Protected, &item.Priority, &item.Active,
		&item.Evidence, &item.ManuallyReviewedAt, &item.UpdatedAt)
	return item, err
}

func mergeBrandUpdate(current BrandDTO, req updateBrandRequest) (BrandDTO, error) {
	if req.Name != nil {
		current.Name = strings.TrimSpace(*req.Name)
	}
	if req.Aliases != nil {
		current.Aliases = normalizeValues(*req.Aliases)
	}
	if req.OfficialDomains != nil {
		current.OfficialDomains = normalizeValues(*req.OfficialDomains)
	}
	if req.Cues != nil {
		current.Cues = normalizeValues(*req.Cues)
	}
	if req.Protected != nil {
		current.Protected = *req.Protected
	}
	if req.Priority != nil {
		current.Priority = *req.Priority
	}
	if req.Active != nil {
		current.Active = *req.Active
	}
	if current.Name == "" || len(current.Name) > 128 {
		return BrandDTO{}, errors.New("name must be 1 to 128 characters")
	}
	if current.Priority < 0 || current.Priority > 10_000 {
		return BrandDTO{}, errors.New("priority must be between 0 and 10000")
	}
	if len(current.Aliases) > 100 || len(current.OfficialDomains) > 100 || len(current.Cues) > 100 {
		return BrandDTO{}, errors.New("aliases, domains, and cues are limited to 100 values each")
	}
	for _, domain := range current.OfficialDomains {
		if !validDomain(domain) {
			return BrandDTO{}, fmt.Errorf("invalid official domain %q", domain)
		}
	}
	if current.Active && current.Protected && (len(current.Aliases) == 0 || len(current.OfficialDomains) == 0) {
		return BrandDTO{}, errors.New("protected brands require at least one alias and official domain")
	}
	return current, nil
}

func normalizeValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || len(value) > 253 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func validDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") ||
		strings.ContainsAny(domain, "/:@ \t\r\n") || strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r < 'a' || r > 'z' {
				if r < '0' || r > '9' {
					if r != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func timePointer(value time.Time) *time.Time { return &value }

func (h *Handler) sourceStatus(r *http.Request) ([]SourceDTO, error) {
	rows, err := h.DB.Query(r.Context(), `
		SELECT tf.feed, tf.enabled, EXTRACT(EPOCH FROM tf.refresh_interval)::int,
		       tf.source_url, COALESCE(tf.api_key, '') <> '',
		       tf.last_refresh_at, tf.last_refresh_ok, tf.last_refresh_err,
		       (SELECT count(DISTINCT pbe.brand_id)::int
		          FROM phishing_brand_evidence pbe
		         WHERE pbe.source = tf.feed)
		  FROM threat_feed_config tf
		 WHERE tf.kind = 'brand'
		 ORDER BY tf.feed
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceDTO{}
	for rows.Next() {
		var item SourceDTO
		if err := rows.Scan(&item.Feed, &item.Enabled, &item.RefreshSeconds,
			&item.SourceURL, &item.HasAPIKey, &item.LastRefreshAt,
			&item.LastRefreshOK, &item.LastRefreshErr, &item.ObservedBrands); err != nil {
			return nil, err
		}
		item.Refreshing = item.Feed == phishTankFeedName && h.isRefreshing()
		out = append(out, item)
	}
	return out, rows.Err()
}
