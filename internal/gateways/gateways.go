// Package gateways implements /api/v1/gateways — backend MX targets per domain.
package gateways

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Gateway struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	DomainID       uuid.UUID `json:"domain_id"`
	Kind           string    `json:"kind"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	UseTLS         bool      `json:"use_tls"`
	Priority       int       `json:"priority"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const cols = `id, organization_id, domain_id, kind::text, host, port, use_tls, priority, is_active, created_at, updated_at`

func scan(row pgx.Row, g *Gateway) error {
	return row.Scan(&g.ID, &g.OrganizationID, &g.DomainID, &g.Kind, &g.Host, &g.Port, &g.UseTLS, &g.Priority, &g.IsActive, &g.CreatedAt, &g.UpdatedAt)
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Get("/{id}", h.read)
	r.Patch("/{id}", h.update)
	r.Delete("/{id}", h.del)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	page := httpx.ParsePage(r)
	q := r.URL.Query()

	var (
		clauses []string
		args    []any
	)
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("organization_id = ANY($%d)", len(args)))
	}
	if did := q.Get("domain_id"); did != "" {
		if id, err := uuid.Parse(did); err == nil {
			args = append(args, id)
			clauses = append(clauses, fmt.Sprintf("domain_id = $%d", len(args)))
		}
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` is built from our own clause strings that only contain $N
	// placeholders (never user data); user values flow through `args...`.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM gateways`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// Sprintf inputs: `where` (our own placeholder strings) + integer
	// parameter indices. No user data is substituted into the SQL.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	listSQL := fmt.Sprintf(
		`SELECT `+cols+` FROM gateways%s ORDER BY priority, host LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))

	items, err := queryAll(r.Context(), h.DB, listSQL, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Gateway]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

type writeReq struct {
	DomainID *uuid.UUID `json:"domain_id,omitempty"`
	Kind     string     `json:"kind"`
	Host     string     `json:"host"`
	Port     int        `json:"port"`
	UseTLS   *bool      `json:"use_tls,omitempty"`
	Priority *int       `json:"priority,omitempty"`
	IsActive *bool      `json:"is_active,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DomainID == nil || req.Host == "" {
		httpx.WriteError(w, http.StatusBadRequest, "domain_id and host required")
		return
	}
	// Look up domain to learn org and authorize.
	var orgID uuid.UUID
	if err := h.DB.QueryRow(r.Context(),
		`SELECT organization_id FROM domains WHERE id = $1`, req.DomainID).Scan(&orgID); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "domain not found")
		return
	}
	if !scope.CanAdmin(ident.Role, orgID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden for that organization")
		return
	}
	if req.Port == 0 {
		req.Port = 25
	}
	if req.Kind == "" {
		req.Kind = "smtp_relay"
	}
	useTLS := true
	if req.UseTLS != nil {
		useTLS = *req.UseTLS
	}
	prio := 10
	if req.Priority != nil {
		prio = *req.Priority
	}
	var g Gateway
	err = scan(h.DB.QueryRow(r.Context(), `
		INSERT INTO gateways (organization_id, domain_id, kind, host, port, use_tls, priority)
		VALUES ($1, $2, $3::gateway_kind, $4, $5, $6, $7)
		RETURNING `+cols,
		orgID, req.DomainID, req.Kind, req.Host, req.Port, useTLS, prio), &g)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var g Gateway
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM gateways WHERE id = $1`, id), &g); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.Allows(g.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var g Gateway
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM gateways WHERE id = $1`, id), &g); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, g.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.DB.Exec(r.Context(), `
		UPDATE gateways
		   SET kind     = COALESCE(NULLIF($1,'')::gateway_kind, kind),
		       host     = COALESCE(NULLIF($2,''), host),
		       port     = COALESCE(NULLIF($3,0), port),
		       use_tls  = COALESCE($4, use_tls),
		       priority = COALESCE($5, priority),
		       is_active = COALESCE($6, is_active),
		       updated_at = now()
		 WHERE id = $7
	`, req.Kind, req.Host, req.Port, req.UseTLS, req.Priority, req.IsActive, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update failed: "+err.Error())
		return
	}
	h.read(w, r)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var g Gateway
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM gateways WHERE id = $1`, id), &g); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, g.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM gateways WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Gateway, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Gateway{}
	for rows.Next() {
		var g Gateway
		if err := scan(rows, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

