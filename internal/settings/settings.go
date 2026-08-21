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
	"strings"
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
	KindSecret SettingKind = "secret"
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
	{Key: "mail.system_from_address", Label: "Automated sender address", Description: "From address for abuse reports and system email. Its domain must authorize the configured relay with aligned SPF or DKIM.", Kind: KindString, Group: "mail"},
	{Key: "mail.outbound_relay_host", Label: "Outbound relay host", Description: "Smarthost for outbound mail (blank = direct MX delivery).", Kind: KindString, Group: "mail"},
	{Key: "mail.outbound_relay_port", Label: "Outbound relay port", Description: "Default 25 if relay host is set.", Kind: KindInt, Group: "mail"},

	{Key: "message.retention_days", Label: "Inbox and quarantine retention (days)", Description: "Days before inbox copies and quarantined messages are automatically purged. Default is 90; maximum is 365.", Kind: KindInt, Group: "retention", Min: &retentionMinDays, Max: &retentionMaxDays},
	{Key: "quarantine.default_action", Label: "Default action over threshold", Description: "Action taken when score crosses the quarantine threshold.", Kind: KindEnum, Options: []string{"deliver", "tag", "quarantine", "reject"}, Group: "quarantine"},

	{Key: "ai.mode", Label: "AI analysis mode", Description: "Disabled uses no AI API calls. Suspicious only analyzes held or tagged mail. All messages analyzes every readable inbound message.", Kind: KindEnum, Options: []string{"disabled", "suspicious", "all"}, Group: "ai"},
	{Key: "ai.provider", Label: "AI provider", Description: "Asynchronous analysis provider. Changes apply to the next AI scan.", Kind: KindEnum, Options: []string{"anthropic", "openai"}, Group: "ai"},
	{Key: "ai.model", Label: "AI model", Description: "Optional model override. Blank uses the selected provider default.", Kind: KindString, Group: "ai"},
	{Key: "ai.anthropic_api_key", Label: "Anthropic API key", Description: "Encrypted at rest. Leave unchanged to keep the stored key.", Kind: KindSecret, Group: "ai"},
	{Key: "ai.openai_api_key", Label: "OpenAI API key", Description: "Encrypted at rest. Leave unchanged to keep the stored key.", Kind: KindSecret, Group: "ai"},
	{Key: "deep_analysis.enabled", Label: "Hold borderline mail for deep analysis", Description: "Withholds suspicious score-band mail until asynchronous analysis releases it or confirms a threat. Keep disabled until Docker02 validation is complete.", Kind: KindBool, Group: "ai"},
	{Key: "deep_analysis.min_score", Label: "Deep-analysis minimum score", Description: "Lowest Rspamd score eligible for a temporary deep-analysis hold.", Kind: KindInt, Group: "ai", Min: intPtr(0), Max: intPtr(30)},
	{Key: "deep_analysis.timeout_minutes", Label: "Deep-analysis timeout (minutes)", Description: "Maximum pending time before the message remains held as unavailable for manual review.", Kind: KindInt, Group: "ai", Min: intPtr(1), Max: intPtr(120)},

	{Key: "threat_intel.cached_enforcement", Label: "Enforce cached threat intelligence", Description: "Uses only local Redis-cached reputation results in the SMTP decision path; external lookups run asynchronously.", Kind: KindBool, Group: "threat_intel"},

	// TLS termination handled by the Caddy front-end (see deploy task).
	// Changing tls.mode requires a stack restart to take effect.
	{Key: "tls.mode", Label: "TLS mode", Description: "off = plain HTTP. self_signed = local cert (browsers will warn). lets_encrypt = automatic certificate from Let's Encrypt (requires public DNS + port 80 reachable).", Kind: KindEnum, Options: []string{"off", "self_signed", "lets_encrypt"}, Group: "tls"},
	{Key: "tls.hostname", Label: "Public hostname", Description: "FQDN the UI is served as (used as the SAN on self-signed certs and the ACME challenge identifier).", Kind: KindString, Group: "tls"},
	{Key: "tls.acme_email", Label: "Let's Encrypt contact email", Description: "Required by ACME for expiry warnings.", Kind: KindString, Group: "tls"},

	{Key: "link_rewrite.public_base_url", Label: "Public application URL", Description: "HTTPS base URL used in quarantine and review links sent by SentinelMail.", Kind: KindString, Group: "ui"},
	{Key: "billing.webhooks_enabled", Label: "Enable billing webhooks", Description: "Accept HMAC-signed billing events at the provider webhook endpoint.", Kind: KindBool, Group: "billing"},
	{Key: "cluster.node_id", Label: "Node ID", Description: "Stable identifier for this gateway node.", Kind: KindString, Group: "cluster"},
}

// DefaultOrgKeys is the catalogue for per-organization settings (org_id NOT
// NULL). Editable by org_admin within their own org.
var DefaultOrgKeys = []SettingMeta{
	{Key: "brand.name", Label: "Organization name (for emails)", Description: "Overrides ui.brand_name for messages on behalf of this org.", Kind: KindString, Group: "brand"},
	{Key: "brand.support_email", Label: "Support email", Description: "Used as the tenant reply/contact address; automated mail uses the system sender.", Kind: KindString, Group: "brand"},
	{Key: "alerts.admin_email", Label: "Admin alerts address", Description: "Where this org receives gateway notifications (suspicious mail, feed outages).", Kind: KindString, Group: "alerts"},
	{Key: "message.retention_days", Label: "Inbox and quarantine retention (days)", Description: "Override the system default for this org. Default is 90; maximum is 365.", Kind: KindInt, Group: "retention", Min: &retentionMinDays, Max: &retentionMaxDays},
	{Key: "digest.frequency", Label: "End-user digest frequency", Description: "How often end users get a quarantine summary email.", Kind: KindEnum, Options: []string{"off", "daily", "weekly"}, Group: "digest"},
	{Key: "billing.customer_ref", Label: "Billing customer reference", Description: "External customer/account identifier for billing hooks.", Kind: KindString, Group: "billing"},
}

type Setting struct {
	Key        string          `json:"key"`
	Value      json.RawMessage `json:"value"`
	Inherited  bool            `json:"inherited,omitempty"`
	UpdatedBy  *uuid.UUID      `json:"updated_by,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Configured bool            `json:"configured,omitempty"`
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
		maskSecretSetting(&s)
		out = append(out, s)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":  out,
		"schema": DefaultKeys,
	})
}

func maskSecretSetting(setting *Setting) {
	if setting == nil {
		return
	}
	meta := settingMeta(setting.Key)
	if meta == nil || meta.Kind != KindSecret {
		return
	}
	var stored string
	_ = json.Unmarshal(setting.Value, &stored)
	setting.Configured = stored != ""
	setting.Value = json.RawMessage(`""`)
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
		storedValue := string(v)
		if meta := settingMeta(k); meta != nil && meta.Kind == KindSecret {
			var plaintext string
			if err := json.Unmarshal(v, &plaintext); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, k+": expected string")
				return
			}
			encrypted, err := encryptSecret(plaintext)
			if err != nil {
				httpx.WriteError(w, http.StatusServiceUnavailable, "secret encryption is not configured")
				return
			}
			encoded, _ := json.Marshal(encrypted)
			storedValue = string(encoded)
		}
		_, err := tx.Exec(r.Context(), `
			INSERT INTO system_settings (organization_id, key, value, updated_by, updated_at)
			VALUES (NULL, $1, $2::jsonb, $3, now())
			ON CONFLICT (key) WHERE organization_id IS NULL
			DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
		`, k, storedValue, ident.UserID)
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
	meta := settingMeta(key)
	if meta == nil {
		return nil
	}
	switch meta.Kind {
	case KindString, KindSecret:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return errors.New("expected string")
		}
		if meta.Kind == KindSecret && len(s) > 16384 {
			return errors.New("secret is too long")
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

func settingMeta(key string) *SettingMeta {
	for i := range DefaultKeys {
		if DefaultKeys[i].Key == key {
			return &DefaultKeys[i]
		}
	}
	return nil
}

type AIConfig struct {
	Mode               string `json:"mode"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	APIKey             string `json:"api_key,omitempty"`
	Available          bool   `json:"available"`
	AvailabilityReason string `json:"availability_reason,omitempty"`
}

func LookupAIConfig(ctx context.Context, db rowQuerier) AIConfig {
	values := map[string]string{}
	for _, key := range []string{"ai.mode", "ai.provider", "ai.model", "ai.anthropic_api_key", "ai.openai_api_key"} {
		var value string
		if err := db.QueryRow(ctx, `SELECT value #>> '{}' FROM system_settings WHERE organization_id IS NULL AND key = $1`, key).Scan(&value); err == nil {
			values[key] = value
		}
	}
	provider := values["ai.provider"]
	if provider == "" {
		provider = "anthropic"
	}
	defaults := map[string]string{"anthropic": "claude-haiku-4-5-20251001", "openai": "gpt-5-mini"}
	model, supported := defaults[provider]
	if values["ai.model"] != "" {
		model = values["ai.model"]
	}
	mode := normalizeAIMode(values["ai.mode"])
	config := AIConfig{Mode: mode, Provider: provider, Model: model}
	if mode == "disabled" {
		config.AvailabilityReason = "AI analysis is disabled"
		return config
	}
	if !supported {
		config.AvailabilityReason = "unsupported AI provider"
		return config
	}
	encrypted := values["ai."+provider+"_api_key"]
	if encrypted == "" {
		config.AvailabilityReason = provider + " API key is not configured"
		return config
	}
	apiKey, err := decryptSecret(encrypted)
	if err != nil {
		config.AvailabilityReason = "stored AI key is unavailable"
		return config
	}
	config.APIKey = apiKey
	config.Available = true
	return config
}

func normalizeAIMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "suspicious", "all":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "disabled"
	}
}

// ShouldQueueAI keeps provider calls out of the SMTP hot path unless the
// operator explicitly enables them. Suspicious mode is intentionally narrow:
// mail must already be tagged or held by deterministic policy.
func ShouldQueueAI(ctx context.Context, db rowQuerier, disposition string) bool {
	config := LookupAIConfig(ctx, db)
	if !config.Available {
		return false
	}
	switch config.Mode {
	case "all":
		return true
	case "suspicious":
		return disposition == "tagged" || disposition == "quarantined"
	default:
		return false
	}
}

type DeepAnalysisConfig struct {
	Enabled        bool
	MinScore       float64
	TimeoutMinutes int
}

func LookupDeepAnalysisConfig(ctx context.Context, db rowQuerier) DeepAnalysisConfig {
	config := DeepAnalysisConfig{MinScore: 4, TimeoutMinutes: 15}
	_ = db.QueryRow(ctx, `SELECT COALESCE((value #>> '{}')::boolean, false) FROM system_settings WHERE organization_id IS NULL AND key = 'deep_analysis.enabled'`).Scan(&config.Enabled)
	_ = db.QueryRow(ctx, `SELECT COALESCE((value #>> '{}')::double precision, 4) FROM system_settings WHERE organization_id IS NULL AND key = 'deep_analysis.min_score'`).Scan(&config.MinScore)
	_ = db.QueryRow(ctx, `SELECT COALESCE((value #>> '{}')::int, 15) FROM system_settings WHERE organization_id IS NULL AND key = 'deep_analysis.timeout_minutes'`).Scan(&config.TimeoutMinutes)
	if config.MinScore < 0 || config.MinScore > 30 {
		config.MinScore = 4
	}
	if config.TimeoutMinutes < 1 || config.TimeoutMinutes > 120 {
		config.TimeoutMinutes = 15
	}
	return config
}

func intPtr(value int) *int { return &value }

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
	return clampRetentionDays(days)
}

// MessageRetentionDaysForDomain returns the domain override when present,
// otherwise the organization/system value used by MessageRetentionDays.
func MessageRetentionDaysForDomain(ctx context.Context, db rowQuerier, orgID, domainID uuid.UUID) int {
	var value int
	err := db.QueryRow(ctx, `
		SELECT retention_days
		  FROM domains
		 WHERE id = $1
		   AND organization_id = $2
		   AND retention_days IS NOT NULL
	`, domainID, orgID).Scan(&value)
	if err == nil {
		return clampRetentionDays(value)
	}
	return MessageRetentionDays(ctx, db, orgID)
}

func clampRetentionDays(days int) int {
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
