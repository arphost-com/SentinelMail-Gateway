package settings

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
)

// OrgHandler serves /api/v1/org-settings. Reads + writes the rows in
// system_settings WHERE organization_id = caller's org. Access requires
// org_admin or higher; org_user can't see the org-level keys.
type OrgHandler struct{ DB *pgxpool.Pool }

func MountOrg(r chi.Router, db *pgxpool.Pool) {
	h := &OrgHandler{DB: db}
	r.Get("/", h.list)
	r.Get("/schema", h.schema)
	r.Patch("/", h.patch)
}

func (h *OrgHandler) schema(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, DefaultOrgKeys)
}

func (h *OrgHandler) list(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	if !isAdmin(ident.Role) {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	rows, err := h.DB.Query(r.Context(),
		`SELECT key, value, updated_by, updated_at
		 FROM system_settings WHERE organization_id = $1 ORDER BY key`, ident.OrganizationID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	defer rows.Close()
	out := []Setting{}
	for rows.Next() {
		var s Setting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedBy, &s.UpdatedAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, s)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":  out,
		"schema": DefaultOrgKeys,
	})
}

func (h *OrgHandler) patch(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	if !isAdmin(ident.Role) {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	var body map[string]json.RawMessage
	if err := httpx.DecodeJSON(r, w, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "empty body")
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "tx")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	for k, v := range body {
		if err := validateOrgValue(k, v); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, k+": "+err.Error())
			return
		}
		// system_settings_org_key is a partial unique index — uses inferred
		// conflict spec WHERE organization_id IS NOT NULL.
		_, err := tx.Exec(r.Context(), `
			INSERT INTO system_settings (organization_id, key, value, updated_by, updated_at)
			VALUES ($1, $2, $3::jsonb, $4, now())
			ON CONFLICT (organization_id, key) WHERE organization_id IS NOT NULL
			DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
		`, ident.OrganizationID, k, string(v), ident.UserID)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "save "+k+": "+err.Error())
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "commit")
		return
	}
	h.list(w, r)
}

// validateOrgValue is the per-org analog of validateValue. Unknown keys
// pass through (forward-compat).
func validateOrgValue(key string, raw json.RawMessage) error {
	var meta *SettingMeta
	for i := range DefaultOrgKeys {
		if DefaultOrgKeys[i].Key == key {
			meta = &DefaultOrgKeys[i]
			break
		}
	}
	if meta == nil {
		return nil
	}
	switch meta.Kind {
	case KindString:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return errors.New("expected string")
		}
	case KindInt:
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return errors.New("expected integer")
		}
		if meta.Min != nil && n < *meta.Min {
			return errors.New("below minimum")
		}
		if meta.Max != nil && n > *meta.Max {
			return errors.New("above maximum")
		}
	case KindBool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return errors.New("expected bool")
		}
	case KindEnum:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return errors.New("expected string")
		}
		ok := false
		for _, o := range meta.Options {
			if o == s {
				ok = true
				break
			}
		}
		if !ok {
			return errors.New("not in allowed options")
		}
	}
	return nil
}
