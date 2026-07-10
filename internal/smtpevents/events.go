// Package smtpevents records Postfix-only SMTP transactions that never reach
// the Rspamd/API mail event path, such as NOQUEUE rejects, TLS failures, and
// downstream delivery deferrals.
package smtpevents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Event struct {
	ID             uuid.UUID   `json:"id"`
	OrganizationID *uuid.UUID  `json:"organization_id,omitempty"`
	DomainID       *uuid.UUID  `json:"domain_id,omitempty"`
	QueueID        *string     `json:"queue_id,omitempty"`
	EventType      string      `json:"event_type"`
	Phase          *string     `json:"phase,omitempty"`
	Direction      string      `json:"direction"`
	FromAddr       *string     `json:"from_addr,omitempty"`
	ToAddr         *string     `json:"to_addr,omitempty"`
	ClientIP       *netip.Addr `json:"client_ip,omitempty"`
	Helo           *string     `json:"helo,omitempty"`
	Relay          *string     `json:"relay,omitempty"`
	StatusCode     *string     `json:"status_code,omitempty"`
	DSN            *string     `json:"dsn,omitempty"`
	Reason         *string     `json:"reason,omitempty"`
	RawLog         *string     `json:"raw_log,omitempty"`
	OccurredAt     time.Time   `json:"occurred_at"`
}

type ingestReq struct {
	QueueID    string `json:"queue_id,omitempty"`
	EventType  string `json:"event_type"`
	Phase      string `json:"phase,omitempty"`
	Direction  string `json:"direction,omitempty"`
	FromAddr   string `json:"from_addr,omitempty"`
	ToAddr     string `json:"to_addr,omitempty"`
	ClientIP   string `json:"client_ip,omitempty"`
	Helo       string `json:"helo,omitempty"`
	Relay      string `json:"relay,omitempty"`
	StatusCode string `json:"status_code,omitempty"`
	DSN        string `json:"dsn,omitempty"`
	Reason     string `json:"reason,omitempty"`
	RawLog     string `json:"raw_log,omitempty"`
	OccurredAt string `json:"occurred_at,omitempty"`
}

type Handler struct {
	DB     *pgxpool.Pool
	Secret []byte
}

func MountPublic(r chi.Router, db *pgxpool.Pool, secret []byte) {
	h := &Handler{DB: db, Secret: secret}
	r.Post("/events", h.ingest)
}

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
}

func (h *Handler) ingest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if !verifySig(h.Secret, body, r.Header.Get("X-SMG-Signature")) {
		httpx.WriteError(w, http.StatusUnauthorized, "bad signature")
		return
	}
	var req ingestReq
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	req.EventType = normalizeEventType(req.EventType)
	if req.EventType == "" {
		httpx.WriteError(w, http.StatusBadRequest, "event_type required")
		return
	}
	if req.Direction == "" {
		req.Direction = "inbound"
	}
	occurredAt := time.Now().UTC()
	if req.OccurredAt != "" {
		if parsed, err := time.Parse(time.RFC3339, req.OccurredAt); err == nil {
			occurredAt = parsed
		}
	}

	orgID, domainID, _ := lookupOrgDomain(r.Context(), h.DB, req.ToAddr)
	var id uuid.UUID
	err = h.DB.QueryRow(r.Context(), `
		INSERT INTO smtp_events
		  (organization_id, domain_id, queue_id, event_type, phase, direction,
		   from_addr, to_addr, client_ip, helo, relay, status_code, dsn, reason,
		   raw_log, occurred_at)
		VALUES ($1, $2, NULLIF($3,''), $4, NULLIF($5,''), $6,
		        NULLIF($7,''), NULLIF($8,''), NULLIF($9,'')::inet, NULLIF($10,''),
		        NULLIF($11,''), NULLIF($12,''), NULLIF($13,''), NULLIF($14,''),
		        NULLIF($15,''), $16)
		RETURNING id
	`, orgID, domainID, req.QueueID, req.EventType, req.Phase, req.Direction,
		req.FromAddr, req.ToAddr, req.ClientIP, req.Helo, req.Relay,
		req.StatusCode, req.DSN, req.Reason, trimRaw(req.RawLog), occurredAt).Scan(&id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "insert: "+err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	if ident.Role == "org_user" {
		httpx.WriteError(w, http.StatusForbidden, "admin role required")
		return
	}
	page := httpx.ParsePage(r)
	q := r.URL.Query()
	var clauses []string
	var args []any
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		clauses = append(clauses, fmt.Sprintf("organization_id = ANY($%d)", len(args)))
	}
	if eventType := strings.TrimSpace(q.Get("event_type")); eventType != "" {
		args = append(args, normalizeEventType(eventType))
		clauses = append(clauses, fmt.Sprintf("event_type = $%d", len(args)))
	}
	if to := strings.TrimSpace(q.Get("to")); to != "" {
		args = append(args, "%"+strings.ToLower(to)+"%")
		clauses = append(clauses, fmt.Sprintf("lower(COALESCE(to_addr,'')) LIKE $%d", len(args)))
	}
	if from := strings.TrimSpace(q.Get("from")); from != "" {
		args = append(args, "%"+strings.ToLower(from)+"%")
		clauses = append(clauses, fmt.Sprintf("lower(COALESCE(from_addr,'')) LIKE $%d", len(args)))
	}
	if !parseQueryBool(q.Get("include_noise")) {
		clauses = append(clauses, smtpEventNoiseClause())
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM smtp_events`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "count")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+cols+` FROM smtp_events%s ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))
	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var evt Event
		if err := scan(rows, &evt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, evt)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Event]{Items: out, Total: total, Limit: page.Limit, Offset: page.Offset})
}

const cols = `id, organization_id, domain_id, queue_id, event_type, phase,
              direction, from_addr, to_addr, client_ip, helo, relay,
              status_code, dsn, reason, raw_log, occurred_at`

func scan(row pgx.Row, evt *Event) error {
	return row.Scan(&evt.ID, &evt.OrganizationID, &evt.DomainID, &evt.QueueID,
		&evt.EventType, &evt.Phase, &evt.Direction, &evt.FromAddr, &evt.ToAddr,
		&evt.ClientIP, &evt.Helo, &evt.Relay, &evt.StatusCode, &evt.DSN,
		&evt.Reason, &evt.RawLog, &evt.OccurredAt)
}

func verifySig(secret, body []byte, got string) bool {
	if len(secret) < 16 || got == "" {
		return false
	}
	got = strings.TrimSpace(strings.TrimPrefix(got, "sha256="))
	raw, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(raw, mac.Sum(nil))
}

func lookupOrgDomain(ctx context.Context, db *pgxpool.Pool, addr string) (*uuid.UUID, *uuid.UUID, error) {
	domain := domainPart(addr)
	if domain == "" {
		return nil, nil, nil
	}
	var orgID uuid.UUID
	var domainID uuid.UUID
	err := db.QueryRow(ctx, `
		SELECT organization_id, id FROM domains
		WHERE lower(name::text) = $1 AND is_active = true
		LIMIT 1
	`, domain).Scan(&orgID, &domainID)
	if err != nil {
		return nil, nil, err
	}
	return &orgID, &domainID, nil
}

func domainPart(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return strings.Trim(addr[i+1:], " <>")
	}
	return ""
}

func normalizeEventType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "reject", "rejected", "noqueue":
		return "reject"
	case "defer", "deferred":
		return "deferred"
	case "bounce", "bounced":
		return "bounced"
	case "fail", "failed":
		return "failed"
	case "tls", "tls_error", "tls-error":
		return "tls_error"
	case "disconnect":
		return "disconnect"
	case "info":
		return "info"
	default:
		return ""
	}
}

func smtpEventNoiseClause() string {
	patternDomain := `lower(regexp_replace(regexp_replace(regexp_replace(le.pattern, '^\*@', ''), '^@', ''), '\.$', ''))`
	eventText := `lower(
		COALESCE(smtp_events.from_addr, '') || ' ' ||
		COALESCE(smtp_events.relay, '') || ' ' ||
		COALESCE(smtp_events.reason, '') || ' ' ||
		COALESCE(smtp_events.raw_log, '')
	)`
	return `NOT (
		event_type IN ('deferred', 'bounced', 'failed')
		AND EXISTS (
			SELECT 1
			  FROM list_entries le
			 WHERE le.action = 'block'::listentry_action
			   AND le.scope IN ('system'::listentry_scope, 'org'::listentry_scope, 'domain'::listentry_scope)
			   AND le.user_id IS NULL
			   AND (le.organization_id IS NULL OR le.organization_id = smtp_events.organization_id)
			   AND (le.domain_id IS NULL OR le.domain_id IS NOT DISTINCT FROM smtp_events.domain_id)
			   AND le.pattern <> ''
			   AND ` + eventText + ` LIKE '%' || ` + patternDomain + ` || '%'
			   AND lower(COALESCE(smtp_events.to_addr, '')) NOT LIKE '%' || ` + patternDomain + ` || '%'
		)
	)`
}

func parseQueryBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func trimRaw(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 2000 {
		return value[:2000]
	}
	return value
}
