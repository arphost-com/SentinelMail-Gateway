// Package policies implements /api/v1/policies (CRUD + /resolve).
package policies

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Policy struct {
	ID                  uuid.UUID      `json:"id"`
	OrganizationID      *uuid.UUID     `json:"organization_id,omitempty"`
	DomainID            *uuid.UUID     `json:"domain_id,omitempty"`
	Name                string         `json:"name"`
	SpamThreshold       float64        `json:"spam_threshold"`
	QuarantineThreshold float64        `json:"quarantine_threshold"`
	RejectThreshold     float64        `json:"reject_threshold"`
	DMARCEnforce        bool           `json:"dmarc_enforce"`
	EnableGreylist      bool           `json:"enable_greylist"`
	QuarantineAction    string         `json:"quarantine_action"`
	Settings            map[string]any `json:"settings"`
	IsDefault           bool           `json:"is_default"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

func (p *Policy) SenderBlacklistEnabled() bool {
	return p.boolSetting("sender_blacklist_enabled", true)
}

func (p *Policy) ChallengeResponseEnabled() bool {
	return p.boolSetting("challenge_response_enabled", false)
}

func (p *Policy) BrandImpersonationEnabled() bool {
	return p.boolSetting("brand_impersonation_enabled", true)
}

func (p *Policy) BrandImpersonationDisplayNameEnabled() bool {
	return p.boolSetting("brand_impersonation_display_name_enabled", true)
}

func (p *Policy) BrandImpersonationSubjectEnabled() bool {
	return p.boolSetting("brand_impersonation_subject_enabled", true)
}

func (p *Policy) BrandImpersonationLinkMismatchEnabled() bool {
	return p.boolSetting("brand_impersonation_link_mismatch_enabled", true)
}

func (p *Policy) BrandImpersonationThirdPartyReceiptsEnabled() bool {
	return p.boolSetting("brand_impersonation_third_party_receipts_enabled", true)
}

func (p *Policy) CommonScamDetectionEnabled() bool {
	return p.boolSetting("common_scam_detection_enabled", true)
}

func (p *Policy) CommonScamCategoryEnabled(slug string) bool {
	return p.boolSetting("common_scam_"+slug+"_enabled", true)
}

func (p *Policy) boolSetting(key string, fallback bool) bool {
	if p == nil || p.Settings == nil {
		return fallback
	}
	raw, ok := p.Settings[key]
	if !ok {
		return fallback
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		switch value {
		case "false", "0", "off":
			return false
		case "true", "1", "on":
			return true
		default:
			return fallback
		}
	default:
		return fallback
	}
}

const cols = `id, organization_id, domain_id, name, spam_threshold, quarantine_threshold, reject_threshold,
              dmarc_enforce, enable_greylist, quarantine_action::text, settings, is_default, created_at, updated_at`

func scan(row pgx.Row, p *Policy) error {
	return row.Scan(&p.ID, &p.OrganizationID, &p.DomainID, &p.Name,
		&p.SpamThreshold, &p.QuarantineThreshold, &p.RejectThreshold,
		&p.DMARCEnforce, &p.EnableGreylist, &p.QuarantineAction,
		&p.Settings, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt)
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Post("/resolve", h.resolve)
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
	var (
		total int
		items []Policy
	)
	if scope.IsSuperAdmin {
		if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM policies`).Scan(&total); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "db")
			return
		}
		items, err = queryAll(r.Context(), h.DB,
			`SELECT `+cols+` FROM policies ORDER BY is_default DESC, name LIMIT $1 OFFSET $2`,
			page.Limit, page.Offset)
	} else {
		if err := h.DB.QueryRow(r.Context(),
			`SELECT count(*) FROM policies WHERE organization_id = ANY($1) OR is_default`,
			scope.VisibleOrgIDs).Scan(&total); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "db")
			return
		}
		items, err = queryAll(r.Context(), h.DB,
			`SELECT `+cols+` FROM policies
			 WHERE organization_id = ANY($1) OR is_default
			 ORDER BY is_default DESC, name LIMIT $2 OFFSET $3`,
			scope.VisibleOrgIDs, page.Limit, page.Offset)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Policy]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

type writeReq struct {
	OrganizationID      *uuid.UUID     `json:"organization_id,omitempty"`
	DomainID            *uuid.UUID     `json:"domain_id,omitempty"`
	Name                string         `json:"name"`
	SpamThreshold       *float64       `json:"spam_threshold,omitempty"`
	QuarantineThreshold *float64       `json:"quarantine_threshold,omitempty"`
	RejectThreshold     *float64       `json:"reject_threshold,omitempty"`
	DMARCEnforce        *bool          `json:"dmarc_enforce,omitempty"`
	EnableGreylist      *bool          `json:"enable_greylist,omitempty"`
	QuarantineAction    string         `json:"quarantine_action,omitempty"`
	Settings            map[string]any `json:"settings,omitempty"`
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
	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name required")
		return
	}
	orgID := ident.OrganizationID
	if req.OrganizationID != nil {
		orgID = *req.OrganizationID
	}
	if !scope.CanAdmin(ident.Role, orgID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden for that organization")
		return
	}
	if req.QuarantineAction == "" {
		req.QuarantineAction = "tag"
	}
	if req.Settings == nil {
		req.Settings = map[string]any{}
	}

	var p Policy
	err = scan(h.DB.QueryRow(r.Context(), `
		INSERT INTO policies (organization_id, domain_id, name,
		                     spam_threshold, quarantine_threshold, reject_threshold,
		                     dmarc_enforce, enable_greylist, quarantine_action, settings)
		VALUES ($1, $2, $3,
		        COALESCE($4, 5.0), COALESCE($5, 10.0), COALESCE($6, 15.0),
		        COALESCE($7, false), COALESCE($8, true),
		        COALESCE(NULLIF($9,'')::policy_action, 'quarantine'),
		        $10::jsonb)
		RETURNING `+cols,
		orgID, req.DomainID, req.Name,
		req.SpamThreshold, req.QuarantineThreshold, req.RejectThreshold,
		req.DMARCEnforce, req.EnableGreylist, req.QuarantineAction, req.Settings), &p)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
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
	var p Policy
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM policies WHERE id = $1`, id), &p); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !p.IsDefault && p.OrganizationID != nil && !scope.Allows(*p.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
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
	var p Policy
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM policies WHERE id = $1`, id), &p); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if p.IsDefault && ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "default policies require super_admin")
		return
	}
	if p.OrganizationID != nil && !scope.CanAdmin(ident.Role, *p.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.DB.Exec(r.Context(), `
		UPDATE policies SET
		  name = COALESCE(NULLIF($1,''), name),
		  spam_threshold       = COALESCE($2, spam_threshold),
		  quarantine_threshold = COALESCE($3, quarantine_threshold),
		  reject_threshold     = COALESCE($4, reject_threshold),
		  dmarc_enforce        = COALESCE($5, dmarc_enforce),
		  enable_greylist      = COALESCE($6, enable_greylist),
		  quarantine_action    = COALESCE(NULLIF($7,'')::policy_action, quarantine_action),
		  settings             = COALESCE($8::jsonb, settings),
		  updated_at           = now()
		WHERE id = $9
	`, req.Name, req.SpamThreshold, req.QuarantineThreshold, req.RejectThreshold,
		req.DMARCEnforce, req.EnableGreylist, req.QuarantineAction, req.Settings, id)
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
	var p Policy
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM policies WHERE id = $1`, id), &p); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if p.IsDefault {
		httpx.WriteError(w, http.StatusForbidden, "cannot delete default policy")
		return
	}
	if p.OrganizationID != nil && !scope.CanAdmin(ident.Role, *p.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM policies WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolve returns the effective policy for a (domain | org) query.
// Resolution order: domain-level → org-level → default.
type resolveReq struct {
	DomainID       *uuid.UUID `json:"domain_id,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req resolveReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Authorize the caller can read the org context they're asking about.
	orgID := ident.OrganizationID
	if req.OrganizationID != nil {
		orgID = *req.OrganizationID
	}
	if req.DomainID != nil {
		if err := h.DB.QueryRow(r.Context(),
			`SELECT organization_id FROM domains WHERE id = $1`, req.DomainID).Scan(&orgID); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "domain not found")
			return
		}
	}
	if !scope.Allows(orgID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	p, err := Resolve(r.Context(), h.DB, req.DomainID, &orgID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "resolve failed: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Policy, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		var p Policy
		if err := scan(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
