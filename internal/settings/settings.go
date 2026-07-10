// Package settings implements /api/v1/system/settings.
//
// Storage is generic key/value (JSONB) so the UI can render a dynamic form
// without us minting a column for every operator preference. Known keys are
// listed in DefaultKeys — the UI uses that list to render labeled controls,
// and unknown keys are still readable/writable as raw JSON for forward-compat.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
)

type SettingKind string

const (
	KindString SettingKind = "string"
	KindInt    SettingKind = "int"
	KindBool   SettingKind = "bool"
	KindEnum   SettingKind = "enum"
)

type SettingMeta struct {
	Key         string      `json:"key"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Kind        SettingKind `json:"kind"`
	Options     []string    `json:"options,omitempty"`
	Group       string      `json:"group"`
	Min         *int        `json:"min,omitempty"`
	Max         *int        `json:"max,omitempty"`
}

var (
	retentionMinDays = 1
	retentionMaxDays = 365
)

// DefaultKeys is the catalogue surfaced to the UI for system-scope
// (organization_id IS NULL) settings. Editable by super_admin only.
// New keys: add here + seed a default row in a migration.
var DefaultKeys = []SettingMeta{
	{Key: "ui.brand_name", Label: "Brand name", Description: "Shown in headers and emails.", Kind: KindString, Group: "ui"},

	{Key: "mail.hostname", Label: "MX hostname", Description: "Postfix myhostname value. Restart postfix to apply.", Kind: KindString, Group: "mail"},
	{Key: "mail.mynetworks", Label: "Trusted networks", Description: "Postfix mynetworks (space-separated CIDRs).", Kind: KindString, Group: "mail"},
	{Key: "mail.outbound_relay_host", Label: "Outbound relay host", Description: "Smarthost for outbound mail (blank = direct MX delivery).", Kind: KindString, Group: "mail"},
	{Key: "mail.outbound_relay_port", Label: "Outbound relay port", Description: "Default 25 if relay host is set.", Kind: KindInt, Group: "mail"},

	{Key: "message.retention_days", Label: "Inbox and quarantine retention (days)", Description: "Days before inbox copies and quarantined messages are automatically purged. Default is 90; maximum is 365.", Kind: KindInt, Group: "retention", Min: &retentionMinDays, Max: &retentionMaxDays},
	{Key: "quarantine.default_action", Label: "Default action over threshold", Description: "Action taken when score crosses the quarantine threshold.", Kind: KindEnum, Options: []string{"deliver", "tag", "quarantine", "reject"}, Group: "quarantine"},

	// TLS termination handled by the Caddy front-end (see deploy task).
	// Changing tls.mode requires a stack restart to take effect.
	{Key: "tls.mode", Label: "TLS mode", Description: "off = plain HTTP. self_signed = local cert (browsers will warn). lets_encrypt = automatic certificate from Let's Encrypt (requires public DNS + port 80 reachable).", Kind: KindEnum, Options: []string{"off", "self_signed", "lets_encrypt"}, Group: "tls"},
	{Key: "tls.hostname", Label: "Public hostname", Description: "FQDN the UI is served as (used as the SAN on self-signed certs and the ACME challenge identifier).", Kind: KindString, Group: "tls"},
	{Key: "tls.acme_email", Label: "Let's Encrypt contact email", Description: "Required by ACME for expiry warnings.", Kind: KindString, Group: "tls"},

	{Key: "link_rewrite.enabled", Label: "Enable link rewriting", Description: "Reserved MVP 3 switch for click-time URL protection. Requires a configured public base URL before mail-plane rewriting is enabled.", Kind: KindBool, Group: "link_rewrite"},
	{Key: "link_rewrite.public_base_url", Label: "Public click URL", Description: "HTTPS base URL that rewritten links will use.", Kind: KindString, Group: "link_rewrite"},
	{Key: "sso.enabled", Label: "Enable SSO", Description: "Reserved MVP 3 switch for external identity provider login.", Kind: KindBool, Group: "sso"},
	{Key: "sso.provider", Label: "SSO provider type", Description: "OIDC or SAML provider family. Secrets stay in environment variables, not the settings table.", Kind: KindEnum, Options: []string{"oidc", "saml"}, Group: "sso"},
	{Key: "sso.issuer_url", Label: "Issuer URL", Description: "Trusted IdP issuer URL.", Kind: KindString, Group: "sso"},
	{Key: "sso.client_id", Label: "Client ID", Description: "Public client identifier for the IdP app registration.", Kind: KindString, Group: "sso"},
	{Key: "billing.provider", Label: "Billing provider", Description: "Reserved MVP 3 billing integration selector.", Kind: KindEnum, Options: []string{"none", "whmcs", "custom"}, Group: "billing"},
	{Key: "billing.webhooks_enabled", Label: "Enable billing webhooks", Description: "Reserved MVP 3 switch for account lifecycle webhooks.", Kind: KindBool, Group: "billing"},
	{Key: "cluster.mode", Label: "Cluster mode", Description: "single keeps one-node behavior; multi is reserved for coordinated multi-node deployments.", Kind: KindEnum, Options: []string{"single", "multi"}, Group: "cluster"},
	{Key: "cluster.node_id", Label: "Node ID", Description: "Stable identifier for this gateway node.", Kind: KindString, Group: "cluster"},
}

// DefaultOrgKeys is the catalogue for per-organization settings (org_id NOT
// NULL). Editable by org_admin within their own org.
var DefaultOrgKeys = []SettingMeta{
	{Key: "brand.name", Label: "Organization name (for emails)", Description: "Overrides ui.brand_name for messages on behalf of this org.", Kind: KindString, Group: "brand"},
	{Key: "brand.support_email", Label: "Support email", Description: "Shown to end users on quarantine release confirmations.", Kind: KindString, Group: "brand"},
	{Key: "alerts.admin_email", Label: "Admin alerts address", Description: "Where this org receives gateway notifications (suspicious mail, feed outages).", Kind: KindString, Group: "alerts"},
	{Key: "message.retention_days", Label: "Inbox and quarantine retention (days)", Description: "Override the system default for this org. Default is 90; maximum is 365.", Kind: KindInt, Group: "retention", Min: &retentionMinDays, Max: &retentionMaxDays},
	{Key: "digest.frequency", Label: "End-user digest frequency", Description: "How often end users get a quarantine summary email.", Kind: KindEnum, Options: []string{"off", "daily", "weekly"}, Group: "digest"},
	{Key: "billing.customer_ref", Label: "Billing customer reference", Description: "External customer/account identifier for billing hooks.", Kind: KindString, Group: "billing"},
}

type Setting struct {
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	UpdatedBy *uuid.UUID      `json:"updated_by,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Get("/schema", h.schema)
	r.Patch("/", h.patch)
}

func (h *Handler) schema(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, DefaultKeys)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	// Only admin-tier roles can read system settings.
	if !isAdmin(ident.Role) {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	rows, err := h.DB.Query(r.Context(),
		`SELECT key, value, updated_by, updated_at
		 FROM system_settings WHERE organization_id IS NULL ORDER BY key`)
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
		"schema": DefaultKeys,
	})
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	if ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "super_admin required")
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
		if err := validateValue(k, v); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, k+": "+err.Error())
			return
		}
		_, err := tx.Exec(r.Context(), `
			INSERT INTO system_settings (organization_id, key, value, updated_by, updated_at)
			VALUES (NULL, $1, $2::jsonb, $3, now())
			ON CONFLICT (key) WHERE organization_id IS NULL
			DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
		`, k, string(v), ident.UserID)
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

// validateValue does shape checks based on DefaultKeys; unknown keys pass
// through (forward-compat, but no UI surface).
func validateValue(key string, raw json.RawMessage) error {
	var meta *SettingMeta
	for i := range DefaultKeys {
		if DefaultKeys[i].Key == key {
			meta = &DefaultKeys[i]
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

func isAdmin(role string) bool {
	return role == "super_admin" || role == "msp_admin" || role == "org_admin"
}

// Lookup is a programmatic helper for other packages to read a global setting.
// Returns nil RawMessage if absent. Errors only on DB failure.
func Lookup(ctx context.Context, db *pgxpool.Pool, key string) (json.RawMessage, error) {
	var v json.RawMessage
	err := db.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE organization_id IS NULL AND key = $1`, key).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// MessageRetentionDays returns the org override when present, otherwise the
// system default. The legacy quarantine-only setting remains a fallback so
// existing installs keep their configured retention after upgrading.
func MessageRetentionDays(ctx context.Context, db rowQuerier, orgID uuid.UUID) int {
	days := 90
	var value int
	err := db.QueryRow(ctx, `
		SELECT (value #>> '{}')::int
		  FROM system_settings
		 WHERE key IN ('message.retention_days', 'quarantine.retention_days')
		   AND (organization_id = $1 OR organization_id IS NULL)
		 ORDER BY organization_id IS NULL,
		          CASE key
		            WHEN 'message.retention_days' THEN 0
		            ELSE 1
		          END
		 LIMIT 1
	`, orgID).Scan(&value)
	if err == nil {
		days = value
	}
	if days < retentionMinDays {
		return retentionMinDays
	}
	if days > retentionMaxDays {
		return retentionMaxDays
	}
	return days
}

// QuarantineRetentionDays is kept for callers that still create quarantine
// expiry timestamps; it now uses the combined message-retention setting.
func QuarantineRetentionDays(ctx context.Context, db rowQuerier, orgID uuid.UUID) int {
	return MessageRetentionDays(ctx, db, orgID)
}
