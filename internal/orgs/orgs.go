// Package orgs implements the /api/v1/orgs REST resource.
package orgs

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Organization struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	ParentID  *uuid.UUID `json:"parent_id,omitempty"`
	IsSystem  bool       `json:"is_system"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
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

const orgColumns = `id, name, slug, parent_id, is_system, is_active, created_at, updated_at`

func scanOrg(row pgx.Row, o *Organization) error {
	return row.Scan(&o.ID, &o.Name, &o.Slug, &o.ParentID, &o.IsSystem, &o.IsActive, &o.CreatedAt, &o.UpdatedAt)
}

func queryOrgs(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Organization, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Organization{}
	for rows.Next() {
		var o Organization
		if err := scanOrg(rows, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope error")
		return
	}
	page := httpx.ParsePage(r)

	var (
		total int
		items []Organization
	)
	if scope.IsSuperAdmin {
		if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM organizations`).Scan(&total); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "db error")
			return
		}
		items, err = queryOrgs(r.Context(), h.DB,
			`SELECT `+orgColumns+` FROM organizations ORDER BY name LIMIT $1 OFFSET $2`,
			page.Limit, page.Offset)
	} else {
		if err := h.DB.QueryRow(r.Context(),
			`SELECT count(*) FROM organizations WHERE id = ANY($1)`, scope.VisibleOrgIDs).Scan(&total); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "db error")
			return
		}
		items, err = queryOrgs(r.Context(), h.DB,
			`SELECT `+orgColumns+` FROM organizations WHERE id = ANY($1) ORDER BY name LIMIT $2 OFFSET $3`,
			scope.VisibleOrgIDs, page.Limit, page.Offset)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db error: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Organization]{
		Items: items, Total: total, Limit: page.Limit, Offset: page.Offset,
	})
}

type orgWriteReq struct {
	Name     string     `json:"name"`
	Slug     string     `json:"slug"`
	ParentID *uuid.UUID `json:"parent_id,omitempty"`
	IsActive *bool      `json:"is_active,omitempty"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope error")
		return
	}
	if !scope.IsSuperAdmin && ident.Role != "msp_admin" {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req orgWriteReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	if req.Name == "" || !slugRE.MatchString(req.Slug) {
		httpx.WriteError(w, http.StatusBadRequest, "name and valid slug required")
		return
	}
	if !scope.IsSuperAdmin {
		parent := ident.OrganizationID
		if req.ParentID != nil {
			parent = *req.ParentID
		}
		if !scope.CanAdmin(ident.Role, parent) {
			httpx.WriteError(w, http.StatusForbidden, "cannot create under that parent")
			return
		}
		req.ParentID = &parent
	}

	var org Organization
	err = scanOrg(h.DB.QueryRow(r.Context(), `
		INSERT INTO organizations (name, slug, parent_id)
		VALUES ($1, $2, $3)
		RETURNING `+orgColumns,
		req.Name, req.Slug, req.ParentID), &org)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, org)
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil || !scope.Allows(id) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	var org Organization
	err = scanOrg(h.DB.QueryRow(r.Context(),
		`SELECT `+orgColumns+` FROM organizations WHERE id = $1`, id), &org)
	if httpx.IsNotFound(err) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, org)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil || !scope.CanAdmin(ident.Role, id) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req orgWriteReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.DB.Exec(r.Context(), `
		UPDATE organizations
		   SET name       = COALESCE(NULLIF($1,''), name),
		       slug       = COALESCE(NULLIF($2,''), slug),
		       is_active  = COALESCE($3, is_active),
		       updated_at = now()
		 WHERE id = $4
	`, req.Name, req.Slug, req.IsActive, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}
	h.read(w, r)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	_, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil || ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "super_admin required")
		return
	}
	res, err := h.DB.Exec(r.Context(),
		`DELETE FROM organizations WHERE id = $1 AND is_system = false`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if res.RowsAffected() == 0 {
		httpx.WriteError(w, http.StatusNotFound, "not found or system org")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
