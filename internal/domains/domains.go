// Package domains implements /api/v1/domains.
package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Domain struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const cols = `id, organization_id, name, is_active, created_at, updated_at`

func scan(row pgx.Row, d *Domain) error {
	return row.Scan(&d.ID, &d.OrganizationID, &d.Name, &d.IsActive, &d.CreatedAt, &d.UpdatedAt)
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Get("/{id}", h.read)
	r.Get("/{id}/verification", h.verification)
	r.Patch("/{id}", h.update)
	r.Delete("/{id}", h.del)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope error")
		return
	}
	page := httpx.ParsePage(r)
	orgIDs := scope.VisibleOrgIDs
	if scope.IsSuperAdmin {
		orgIDs = nil
	}

	var total int
	countSQL := `SELECT count(*) FROM domains`
	listSQL := `SELECT ` + cols + ` FROM domains ORDER BY name LIMIT $1 OFFSET $2`
	if orgIDs != nil {
		countSQL = `SELECT count(*) FROM domains WHERE organization_id = ANY($1)`
		listSQL = `SELECT ` + cols + ` FROM domains WHERE organization_id = ANY($1) ORDER BY name LIMIT $2 OFFSET $3`
	}
	args := []any{}
	if orgIDs != nil {
		args = append(args, orgIDs)
	}
	if err := h.DB.QueryRow(r.Context(), countSQL, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db error")
		return
	}
	args = append(args, page.Limit, page.Offset)
	items, err := queryAll(r.Context(), h.DB, listSQL, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Domain]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

type writeReq struct {
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	Name           string     `json:"name"`
	IsActive       *bool      `json:"is_active,omitempty"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope error")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(strings.ToLower(req.Name))
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
	var d Domain
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "tx")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	err = scan(tx.QueryRow(r.Context(),
		`INSERT INTO domains (organization_id, name) VALUES ($1, $2) RETURNING `+cols,
		orgID, req.Name), &d)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(), `
		INSERT INTO policies (organization_id, domain_id, name,
		                      spam_threshold, quarantine_threshold, reject_threshold,
		                      dmarc_enforce, enable_greylist, quarantine_action, settings)
		VALUES ($1, $2, $3, 5.0, 7.0, 15.0, false, true, 'tag',
		        '{"preset":"balanced","auto_created":true}'::jsonb)
	`, orgID, d.ID, d.Name+" balanced spam tag"); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "policy create failed: "+err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, d)
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
	var d Domain
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM domains WHERE id = $1`, id), &d); err != nil {
		if httpx.IsNotFound(err) {
			httpx.WriteError(w, http.StatusNotFound, "not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "db error")
		return
	}
	if !scope.Allows(d.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

type VerificationCheck struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type VerificationResponse struct {
	Domain     Domain              `json:"domain"`
	ExpectedMX string              `json:"expected_mx"`
	DNS        map[string]any      `json:"dns"`
	Gateways   map[string]int      `json:"gateways"`
	Mail       map[string]any      `json:"mail"`
	Checks     []VerificationCheck `json:"checks"`
}

func (h *Handler) verification(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var d Domain
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM domains WHERE id = $1`, id), &d); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, d.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}

	expectedMX := lookupStringSetting(r.Context(), h.DB, "mail.hostname")
	totalGateways, activeGateways := 0, 0
	if err := h.DB.QueryRow(r.Context(),
		`SELECT count(*), count(*) FILTER (WHERE is_active)
		   FROM gateways
		  WHERE organization_id = $1 AND domain_id = $2`,
		d.OrganizationID, d.ID).Scan(&totalGateways, &activeGateways); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "gateway check failed")
		return
	}

	var recentCount int
	var newest sql.NullTime
	if err := h.DB.QueryRow(r.Context(),
		`SELECT count(*), max(received_at)
		   FROM mail_logs
		  WHERE organization_id = $1 AND domain_id = $2 AND received_at >= now() - interval '24 hours'`,
		d.OrganizationID, d.ID).Scan(&recentCount, &newest); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail check failed")
		return
	}
	dispositions, err := h.dispositionCounts(r.Context(), d.OrganizationID, d.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail summary failed")
		return
	}

	mxHosts, mxErr := lookupMX(r.Context(), d.Name)
	mxMatches := false
	if expectedMX != "" {
		for _, host := range mxHosts {
			if strings.EqualFold(trimDot(host), trimDot(expectedMX)) {
				mxMatches = true
				break
			}
		}
	}

	checks := []VerificationCheck{
		{
			Key:    "domain_active",
			Label:  "Domain accepts mail",
			Status: statusBool(d.IsActive),
			Detail: boolDetail(d.IsActive, "domain is active", "domain is disabled"),
		},
		{
			Key:    "mx_dns",
			Label:  "MX points at gateway",
			Status: mxStatus(expectedMX, mxHosts, mxMatches, mxErr),
			Detail: mxDetail(expectedMX, mxHosts, mxErr),
		},
		{
			Key:    "delivery_gateway",
			Label:  "Downstream gateway configured",
			Status: statusBool(activeGateways > 0),
			Detail: gatewayDetail(activeGateways, totalGateways),
		},
		{
			Key:    "recent_mail",
			Label:  "Recent mail observed",
			Status: statusBool(recentCount > 0),
			Detail: recentMailDetail(recentCount, newest),
		},
	}

	httpx.WriteJSON(w, http.StatusOK, VerificationResponse{
		Domain:     d,
		ExpectedMX: expectedMX,
		DNS: map[string]any{
			"mx":         mxHosts,
			"matches":    mxMatches,
			"error":      mxErr,
			"checked_at": time.Now().UTC(),
		},
		Gateways: map[string]int{"total": totalGateways, "active": activeGateways},
		Mail: map[string]any{
			"last_24h":     recentCount,
			"newest_at":    nullableTime(newest),
			"disposition":  dispositions,
			"checked_from": "mail_logs",
		},
		Checks: checks,
	})
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
	var d Domain
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM domains WHERE id = $1`, id), &d); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, d.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req writeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.DB.Exec(r.Context(), `
		UPDATE domains
		   SET name = COALESCE(NULLIF($1,''), name),
		       is_active = COALESCE($2, is_active),
		       updated_at = now()
		 WHERE id = $3
	`, strings.ToLower(req.Name), req.IsActive, id)
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
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var d Domain
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM domains WHERE id = $1`, id), &d); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, d.OrganizationID) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM domains WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Domain, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Domain{}
	for rows.Next() {
		var d Domain
		if err := scan(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (h *Handler) dispositionCounts(ctx context.Context, orgID, domainID uuid.UUID) (map[string]int, error) {
	rows, err := h.DB.Query(ctx,
		`SELECT disposition::text, count(*)
		   FROM mail_logs
		  WHERE organization_id = $1 AND domain_id = $2 AND received_at >= now() - interval '24 hours'
		  GROUP BY disposition`,
		orgID, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		out[key] = count
	}
	return out, rows.Err()
}

func lookupStringSetting(ctx context.Context, db *pgxpool.Pool, key string) string {
	raw, err := settings.Lookup(ctx, db, key)
	if err != nil || len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func lookupMX(ctx context.Context, domain string) ([]string, string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return []string{}, err.Error()
	}
	out := make([]string, 0, len(records))
	for _, mx := range records {
		out = append(out, trimDot(mx.Host))
	}
	return out, ""
}

func trimDot(s string) string {
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

func statusBool(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

func boolDetail(ok bool, pass, fail string) string {
	if ok {
		return pass
	}
	return fail
}

func mxStatus(expected string, hosts []string, match bool, err string) string {
	switch {
	case expected == "":
		return "warn"
	case err != "":
		return "unknown"
	case match:
		return "pass"
	case len(hosts) == 0:
		return "fail"
	default:
		return "warn"
	}
}

func mxDetail(expected string, hosts []string, err string) string {
	if expected == "" {
		return "mail.hostname is not configured"
	}
	if err != "" {
		return "DNS lookup failed: " + err
	}
	if len(hosts) == 0 {
		return "no MX records found; expected " + expected
	}
	return "expected " + expected + "; found " + strings.Join(hosts, ", ")
}

func gatewayDetail(active, total int) string {
	if active > 0 {
		return strings.TrimSpace(strings.Join([]string{intText(active), "active of", intText(total), "configured"}, " "))
	}
	if total > 0 {
		return "gateways exist but all are disabled"
	}
	return "no downstream gateway configured"
}

func recentMailDetail(count int, newest sql.NullTime) string {
	if count == 0 {
		return "no mail log rows for this domain in the last 24 hours"
	}
	if newest.Valid {
		return intText(count) + " messages in the last 24 hours; newest " + newest.Time.Format(time.RFC3339)
	}
	return intText(count) + " messages in the last 24 hours"
}

func nullableTime(t sql.NullTime) any {
	if !t.Valid {
		return nil
	}
	return t.Time
}

func intText(n int) string {
	return strconv.Itoa(n)
}
