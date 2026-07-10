// Package reports implements /api/v1/reports.
package reports

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type CountRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type DailyRow struct {
	Day   time.Time `json:"day"`
	Count int       `json:"count"`
}

type TimeTypeRow struct {
	Bucket time.Time `json:"bucket"`
	Type   string    `json:"type"`
	Count  int       `json:"count"`
}

type Summary struct {
	Window           string        `json:"window"`
	Since            time.Time     `json:"since"`
	Until            time.Time     `json:"until"`
	Total            int           `json:"total"`
	Inbound          int           `json:"inbound"`
	Outbound         int           `json:"outbound"`
	Disposition      []CountRow    `json:"disposition"`
	DeliveryOutcomes []CountRow    `json:"delivery_outcomes"`
	ThreatCategories []CountRow    `json:"threat_categories"`
	EmailTypes       []CountRow    `json:"email_types"`
	ScoreBands       []CountRow    `json:"score_bands"`
	PhishingReports  []CountRow    `json:"phishing_reports"`
	TopSymbols       []CountRow    `json:"top_symbols"`
	TopDomains       []CountRow    `json:"top_domains"`
	TopSenders       []CountRow    `json:"top_senders"`
	BlockedSenders   []CountRow    `json:"blocked_senders"`
	DailyVolume      []DailyRow    `json:"daily_volume"`
	MailTypeTimeline []TimeTypeRow `json:"mail_type_timeline"`
	Quarantined      int           `json:"quarantined"`
	Released         int           `json:"released"`
	PhishingTotal    int           `json:"phishing_total"`
	Rejected         int           `json:"rejected"`
	Delivered        int           `json:"delivered"`
	Tagged           int           `json:"tagged"`
	Failed           int           `json:"failed"`
	BlockedTotal     int           `json:"blocked_total"`
}

type AdminStats struct {
	Window string         `json:"window"`
	Since  time.Time      `json:"since"`
	MSPs   []MSPStatsRow  `json:"msps"`
	Orgs   []OrgStatsRow  `json:"orgs"`
	Users  []UserStatsRow `json:"users"`
}

type MSPStatsRow struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Slug            string    `json:"slug"`
	ChildOrgs       int       `json:"child_orgs"`
	ActiveUsers     int       `json:"active_users"`
	Domains         int       `json:"domains"`
	Processed       int       `json:"processed"`
	Quarantined     int       `json:"quarantined"`
	Rejected        int       `json:"rejected"`
	PhishingReports int       `json:"phishing_reports"`
}

type OrgStatsRow struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Slug            string     `json:"slug"`
	ParentID        *uuid.UUID `json:"parent_id,omitempty"`
	IsActive        bool       `json:"is_active"`
	ActiveUsers     int        `json:"active_users"`
	Domains         int        `json:"domains"`
	Processed       int        `json:"processed"`
	Quarantined     int        `json:"quarantined"`
	Rejected        int        `json:"rejected"`
	PhishingReports int        `json:"phishing_reports"`
}

type UserStatsRow struct {
	ID              uuid.UUID  `json:"id"`
	OrganizationID  uuid.UUID  `json:"organization_id"`
	Email           string     `json:"email"`
	DisplayName     *string    `json:"display_name,omitempty"`
	Role            string     `json:"role"`
	IsActive        bool       `json:"is_active"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	Processed       int        `json:"processed"`
	Quarantined     int        `json:"quarantined"`
	ReportedThreats int        `json:"reported_threats"`
}

type PhishingReport struct {
	ID               uuid.UUID       `json:"id"`
	OrganizationID   uuid.UUID       `json:"organization_id"`
	DomainID         *uuid.UUID      `json:"domain_id,omitempty"`
	Domain           string          `json:"domain"`
	MailLogID        *uuid.UUID      `json:"mail_log_id,omitempty"`
	MailboxMessageID *uuid.UUID      `json:"mailbox_message_id,omitempty"`
	ScanJobID        *uuid.UUID      `json:"scan_job_id,omitempty"`
	Source           string          `json:"source"`
	Status           string          `json:"status"`
	PhishingType     string          `json:"phishing_type"`
	Verdict          string          `json:"verdict"`
	FromAddr         string          `json:"from_addr"`
	ToAddr           string          `json:"to_addr"`
	Subject          string          `json:"subject"`
	Evidence         json.RawMessage `json:"evidence"`
	ReportedAt       time.Time       `json:"reported_at"`
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/summary", h.summary)
	r.Get("/phishing", h.phishing)
	r.Get("/admin-stats", h.adminStats)
}

func (h *Handler) adminStats(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	if ident.Role == "org_user" {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "7d"
	}
	dur, err := parseWindow(window)
	if err != nil {
		window = "7d"
		dur = 7 * 24 * time.Hour
	}
	since := time.Now().Add(-dur)
	args := []any{since}
	orgFilter := ""
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		orgFilter = " AND o.id = ANY($2)"
	}

	orgs, err := h.orgStats(r, orgFilter, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "organization stats failed")
		return
	}
	users, err := h.userStats(r, orgFilter, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "user stats failed")
		return
	}
	msps, err := h.mspStats(r, orgFilter, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "msp stats failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, AdminStats{
		Window: window,
		Since:  since,
		MSPs:   msps,
		Orgs:   orgs,
		Users:  users,
	})
}

func (h *Handler) phishing(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "30d"
	}
	dur, err := parseWindow(window)
	if err != nil {
		window = "30d"
		dur = 30 * 24 * time.Hour
	}
	since := time.Now().Add(-dur)
	where, args := scopedPhishingWhere(scope.VisibleOrgIDs, scope.IsSuperAdmin, since, ident)
	page := httpx.ParsePage(r)

	total, err := h.count(r, `
		SELECT count(*)
		  FROM phishing_reports pr
		  LEFT JOIN mail_logs ml ON ml.id = pr.mail_log_id
		  `+where, args...) //nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "phishing report count failed")
		return
	}
	args = append(args, page.Limit, page.Offset)
	rows, err := h.DB.Query(r.Context(), fmt.Sprintf(`
		SELECT pr.id,
		       pr.organization_id,
		       pr.domain_id,
		       COALESCE(d.name::text, ''),
		       pr.mail_log_id,
		       pr.mailbox_message_id,
		       pr.scan_job_id,
		       pr.source,
		       pr.status,
		       pr.phishing_type,
		       pr.verdict,
		       COALESCE(ml.from_addr, mm.from_addr, pr.evidence->>'from_addr', ''),
		       COALESCE(mm.to_addr, (ml.to_addrs)[1], pr.evidence->>'to_addr', ''),
		       COALESCE(ml.subject, mm.subject, pr.evidence->>'subject', ''),
		       pr.evidence,
		       pr.reported_at
		  FROM phishing_reports pr
		  LEFT JOIN mail_logs ml ON ml.id = pr.mail_log_id
		  LEFT JOIN mailbox_messages mm ON mm.id = pr.mailbox_message_id
		  LEFT JOIN domains d ON d.id = pr.domain_id
		  %s
		 ORDER BY pr.reported_at DESC
		 LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args)), args...) //nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "phishing reports failed")
		return
	}
	defer rows.Close()
	items := []PhishingReport{}
	for rows.Next() {
		var item PhishingReport
		if err := rows.Scan(
			&item.ID,
			&item.OrganizationID,
			&item.DomainID,
			&item.Domain,
			&item.MailLogID,
			&item.MailboxMessageID,
			&item.ScanJobID,
			&item.Source,
			&item.Status,
			&item.PhishingType,
			&item.Verdict,
			&item.FromAddr,
			&item.ToAddr,
			&item.Subject,
			&item.Evidence,
			&item.ReportedAt,
		); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "phishing report scan failed")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "phishing report rows failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[PhishingReport]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func (h *Handler) orgStats(r *http.Request, orgFilter string, args ...any) ([]OrgStatsRow, error) {
	rows, err := h.DB.Query(r.Context(), `
		SELECT o.id,
		       o.name,
		       o.slug,
		       o.parent_id,
		       o.is_active,
		       (SELECT count(*) FROM users u WHERE u.organization_id = o.id AND u.is_active)::int AS active_users,
		       (SELECT count(*) FROM domains d WHERE d.organization_id = o.id AND d.is_active)::int AS domains,
		       (SELECT count(*) FROM mail_logs ml WHERE ml.organization_id = o.id AND ml.received_at >= $1)::int AS processed,
		       (SELECT count(*) FROM mail_logs ml WHERE ml.organization_id = o.id AND ml.received_at >= $1 AND ml.disposition = 'quarantined')::int AS quarantined,
		       (SELECT count(*) FROM mail_logs ml WHERE ml.organization_id = o.id AND ml.received_at >= $1 AND ml.disposition = 'rejected')::int AS rejected,
		       (SELECT count(*) FROM phishing_reports pr WHERE pr.organization_id = o.id AND pr.reported_at >= $1)::int AS phishing_reports
		  FROM organizations o
		 WHERE true `+orgFilter+`
		 ORDER BY o.name`, args...) //nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgStatsRow{}
	for rows.Next() {
		var row OrgStatsRow
		if err := rows.Scan(
			&row.ID,
			&row.Name,
			&row.Slug,
			&row.ParentID,
			&row.IsActive,
			&row.ActiveUsers,
			&row.Domains,
			&row.Processed,
			&row.Quarantined,
			&row.Rejected,
			&row.PhishingReports,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) userStats(r *http.Request, orgFilter string, args ...any) ([]UserStatsRow, error) {
	rows, err := h.DB.Query(r.Context(), `
		SELECT u.id,
		       u.organization_id,
		       u.email,
		       u.display_name,
		       u.role::text,
		       u.is_active,
		       u.last_login_at,
		       (SELECT count(*)
		          FROM (
		               SELECT ml.id
		                 FROM mail_logs ml
		                WHERE ml.organization_id = u.organization_id
		                  AND ml.received_at >= $1
		                  AND EXISTS (SELECT 1 FROM unnest(ml.to_addrs) AS t WHERE lower(t) = lower(u.email))
		                UNION
		               SELECT mm.mail_log_id
		                 FROM mailbox_messages mm
		                WHERE mm.organization_id = u.organization_id
		                  AND mm.received_at >= $1
		                  AND lower(mm.to_addr) = lower(u.email)
		          ) user_mail)::int AS processed,
		       (SELECT count(*)
		          FROM (
		               SELECT ml.id
		                 FROM mail_logs ml
		                WHERE ml.organization_id = u.organization_id
		                  AND ml.received_at >= $1
		                  AND ml.disposition = 'quarantined'
		                  AND EXISTS (SELECT 1 FROM unnest(ml.to_addrs) AS t WHERE lower(t) = lower(u.email))
		                UNION
		               SELECT mm.mail_log_id
		                 FROM mailbox_messages mm
		                 JOIN mail_logs ml ON ml.id = mm.mail_log_id
		                WHERE mm.organization_id = u.organization_id
		                  AND mm.received_at >= $1
		                  AND lower(mm.to_addr) = lower(u.email)
		                  AND ml.disposition = 'quarantined'
		          ) held_mail)::int AS quarantined,
		       (SELECT count(*)
		          FROM mailbox_messages mm
		         WHERE mm.organization_id = u.organization_id
		           AND mm.received_at >= $1
		           AND lower(mm.to_addr) = lower(u.email)
		           AND mm.verdict IN ('spam', 'phishing', 'malware'))::int AS reported_threats
		  FROM users u
		  JOIN organizations o ON o.id = u.organization_id
		 WHERE true `+orgFilter+`
		 ORDER BY u.email`, args...) //nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserStatsRow{}
	for rows.Next() {
		var row UserStatsRow
		if err := rows.Scan(
			&row.ID,
			&row.OrganizationID,
			&row.Email,
			&row.DisplayName,
			&row.Role,
			&row.IsActive,
			&row.LastLoginAt,
			&row.Processed,
			&row.Quarantined,
			&row.ReportedThreats,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) mspStats(r *http.Request, orgFilter string, args ...any) ([]MSPStatsRow, error) {
	rows, err := h.DB.Query(r.Context(), `
		WITH RECURSIVE roots AS (
			SELECT o.id, o.name, o.slug
			  FROM organizations o
			 WHERE (
			       EXISTS (SELECT 1 FROM users u WHERE u.organization_id = o.id AND u.role = 'msp_admin')
			    OR EXISTS (SELECT 1 FROM organizations child WHERE child.parent_id = o.id)
			 ) `+orgFilter+`
		),
		tree(root_id, id) AS (
			SELECT id, id FROM roots
			UNION ALL
			SELECT t.root_id, o.id
			  FROM organizations o
			  JOIN tree t ON o.parent_id = t.id
		)
		SELECT r.id,
		       r.name,
		       r.slug,
		       (SELECT count(*) FROM organizations child WHERE child.parent_id = r.id)::int AS child_orgs,
		       (SELECT count(*) FROM users u JOIN tree t ON t.id = u.organization_id WHERE t.root_id = r.id AND u.is_active)::int AS active_users,
		       (SELECT count(*) FROM domains d JOIN tree t ON t.id = d.organization_id WHERE t.root_id = r.id AND d.is_active)::int AS domains,
		       (SELECT count(*) FROM mail_logs ml JOIN tree t ON t.id = ml.organization_id WHERE t.root_id = r.id AND ml.received_at >= $1)::int AS processed,
		       (SELECT count(*) FROM mail_logs ml JOIN tree t ON t.id = ml.organization_id WHERE t.root_id = r.id AND ml.received_at >= $1 AND ml.disposition = 'quarantined')::int AS quarantined,
		       (SELECT count(*) FROM mail_logs ml JOIN tree t ON t.id = ml.organization_id WHERE t.root_id = r.id AND ml.received_at >= $1 AND ml.disposition = 'rejected')::int AS rejected,
		       (SELECT count(*) FROM phishing_reports pr JOIN tree t ON t.id = pr.organization_id WHERE t.root_id = r.id AND pr.reported_at >= $1)::int AS phishing_reports
		  FROM roots r
		 ORDER BY r.name`, args...) //nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MSPStatsRow{}
	for rows.Next() {
		var row MSPStatsRow
		if err := rows.Scan(
			&row.ID,
			&row.Name,
			&row.Slug,
			&row.ChildOrgs,
			&row.ActiveUsers,
			&row.Domains,
			&row.Processed,
			&row.Quarantined,
			&row.Rejected,
			&row.PhishingReports,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "7d"
	}
	dur, err := parseWindow(window)
	if err != nil {
		window = "7d"
		dur = 7 * 24 * time.Hour
	}
	until := time.Now()
	since := until.Add(-dur)
	where, args := scopedWhere(scope.VisibleOrgIDs, scope.IsSuperAdmin, since, until, ident)

	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	total, err := h.count(r, "SELECT count(*) FROM mail_logs "+where, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "total failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	directions, err := h.countRows(r, "direction", "SELECT direction, count(*) FROM mail_logs "+where+" GROUP BY direction", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "direction summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	dispositions, err := h.countRows(r, "disposition", "SELECT disposition::text, count(*) FROM mail_logs "+where+" GROUP BY disposition ORDER BY count(*) DESC", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "disposition summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	deliveryOutcomes, err := h.countRows(r, "delivery_outcome", `
		SELECT outcome, count(*)
		  FROM (
			SELECT CASE
			  WHEN lower(COALESCE(ml.reason, '')) = 'sender matched blacklist' THEN 'blocked'
			  WHEN ml.disposition = 'rejected' THEN 'rejected'
			  WHEN ml.disposition = 'failed' THEN 'failed'
			  WHEN ml.disposition = 'deferred' THEN 'deferred'
			  WHEN ml.disposition = 'tagged' THEN 'tagged'
			  WHEN ml.disposition = 'quarantined' THEN 'quarantined'
			  ELSE 'delivered'
			END AS outcome
			FROM mail_logs ml
			`+aliasWhere(where, "ml")+`
		  ) x
		 GROUP BY outcome
		 ORDER BY min(CASE outcome
		   WHEN 'blocked' THEN 1
		   WHEN 'rejected' THEN 2
		   WHEN 'failed' THEN 3
		   WHEN 'deferred' THEN 4
		   WHEN 'quarantined' THEN 5
		   WHEN 'tagged' THEN 6
		   ELSE 7
		 END)`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delivery outcome summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	topDomains, err := h.countRows(r, "domain", "SELECT COALESCE(d.name::text, '(unknown)'), count(*) FROM mail_logs ml LEFT JOIN domains d ON d.id = ml.domain_id "+aliasWhere(where, "ml")+" GROUP BY 1 ORDER BY count(*) DESC LIMIT 10", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "domain summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	topSenders, err := h.countRows(r, "sender", "SELECT COALESCE(NULLIF(lower(from_addr), ''), '(unknown)'), count(*) FROM mail_logs "+where+" GROUP BY 1 ORDER BY count(*) DESC LIMIT 10", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sender summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	blockedTotal, err := h.count(r, "SELECT count(*) FROM mail_logs ml "+aliasWhere(where, "ml")+" AND lower(COALESCE(ml.reason, '')) = 'sender matched blacklist'", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "blocked sender summary failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	blockedSenders, err := h.countRows(r, "sender_domain", `
		SELECT COALESCE(NULLIF(lower(trim(both '. ' from substring(COALESCE(ml.from_addr, '') from '@([^@>[:space:]]+)'))), ''), '(unknown)'), count(*)
		  FROM mail_logs ml
		  `+aliasWhere(where, "ml")+`
		   AND lower(COALESCE(ml.reason, '')) = 'sender matched blacklist'
		 GROUP BY 1
		 ORDER BY count(*) DESC
		 LIMIT 10`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "blocked sender domains failed")
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	daily, err := h.dailyRows(r, "SELECT date_trunc('day', received_at) AS day, count(*) FROM mail_logs "+where+" GROUP BY day ORDER BY day", args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "daily summary failed")
		return
	}
	timelineBucket := "date_trunc('day', ml.received_at)"
	if window == "24h" {
		timelineBucket = "date_trunc('hour', ml.received_at)"
	}
	topSymbols, err := h.countRows(r, "symbol", `
		SELECT sym.key, count(*)
		  FROM mail_logs ml
		  CROSS JOIN LATERAL jsonb_object_keys(COALESCE(ml.symbols, '{}'::jsonb)) AS sym(key)
		`+aliasWhere(where, "ml")+`
		 GROUP BY sym.key
		 ORDER BY count(*) DESC
		 LIMIT 12`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "symbol summary failed")
		return
	}
	threatCategories, err := h.countRows(r, "category", `
		SELECT category, count(*)
		  FROM (
			SELECT CASE
			  WHEN lower(COALESCE(ml.reason, '')) = 'sender matched blacklist' THEN 'Sender blocklist'
			  WHEN lower(COALESCE(ml.reason, '')) = 'reputation blocklist hit' THEN 'Reputation blocklist'
			  WHEN EXISTS (
				SELECT 1 FROM jsonb_object_keys(COALESCE(ml.symbols, '{}'::jsonb)) s(key)
				WHERE upper(s.key) LIKE '%PHISH%' OR upper(s.key) LIKE '%DMARC%'
			  ) THEN 'Phishing / impersonation'
			  WHEN EXISTS (
				SELECT 1 FROM jsonb_object_keys(COALESCE(ml.symbols, '{}'::jsonb)) s(key)
				WHERE upper(s.key) LIKE '%VIRUS%' OR upper(s.key) LIKE '%CLAM%' OR upper(s.key) LIKE '%MALWARE%'
			  ) THEN 'Malware'
			  WHEN EXISTS (
				SELECT 1 FROM jsonb_object_keys(COALESCE(ml.symbols, '{}'::jsonb)) s(key)
				WHERE upper(s.key) LIKE '%RBL%' OR upper(s.key) LIKE '%ZEN%' OR upper(s.key) LIKE '%SPAMHAUS%' OR upper(s.key) LIKE '%SURBL%' OR upper(s.key) LIKE '%URIBL%'
			  ) THEN 'Reputation blocklist'
			  WHEN ml.disposition IN ('quarantined', 'tagged') THEN 'Spam content'
			  WHEN ml.disposition IN ('rejected', 'failed') THEN 'Rejected / failed'
			  ELSE 'Clean or low risk'
			END AS category
			FROM mail_logs ml
			`+aliasWhere(where, "ml")+`
		  ) x
		 GROUP BY category
		 ORDER BY count(*) DESC`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "threat category summary failed")
		return
	}
	scoreBands, err := h.countRows(r, "score_band", `
		SELECT score_band, count(*)
		  FROM (
			SELECT CASE
			  WHEN rspamd_score >= 15 THEN 'Reject level >= 15'
			  WHEN rspamd_score >= 7 THEN 'Quarantine level 7-14.99'
			  WHEN rspamd_score >= 5 THEN 'Tagged spam 5-6.99'
			  WHEN rspamd_score >= 0 THEN 'Low or neutral 0-4.99'
			  ELSE 'Trusted / negative score'
			END AS score_band
			FROM mail_logs ml
			`+aliasWhere(where, "ml")+`
		  ) x
		 GROUP BY score_band
		 ORDER BY min(CASE score_band
		   WHEN 'Reject level >= 15' THEN 1
		   WHEN 'Quarantine level 7-14.99' THEN 2
		   WHEN 'Tagged spam 5-6.99' THEN 3
		   WHEN 'Low or neutral 0-4.99' THEN 4
		   ELSE 5
		 END)`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "score band summary failed")
		return
	}
	pWhere, pArgs := scopedPhishingWhere(scope.VisibleOrgIDs, scope.IsSuperAdmin, since, ident)
	phishingReports, err := h.countRows(r, "phishing_type", `
		SELECT phishing_type, count(*)
		  FROM phishing_reports pr
		  LEFT JOIN mail_logs ml ON ml.id = pr.mail_log_id
		  `+pWhere+`
		 GROUP BY phishing_type
		 ORDER BY count(*) DESC`, pArgs...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "phishing report summary failed")
		return
	}
	emailTypes, err := h.countRows(r, "email_type", `
		SELECT email_type, count(*)
		  FROM (
			SELECT `+emailTypeCase("ml")+` AS email_type
			FROM mail_logs ml
			`+aliasWhere(where, "ml")+`
		  ) x
		 GROUP BY email_type
		 ORDER BY count(*) DESC`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "email type summary failed")
		return
	}
	mailTypeTimeline, err := h.timeTypeRows(r, `
		SELECT bucket, email_type, count(*)
		  FROM (
			SELECT `+timelineBucket+` AS bucket, `+emailTypeCase("ml")+` AS email_type
			  FROM mail_logs ml
			  `+aliasWhere(where, "ml")+`
		  ) x
		 GROUP BY bucket, email_type
		 ORDER BY bucket ASC, email_type ASC`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail type timeline failed")
		return
	}
	qWhere, qArgs := scopedQuarantineWhere(scope.VisibleOrgIDs, scope.IsSuperAdmin, since, ident)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	released, err := h.count(r, "SELECT count(*) FROM quarantine_entries "+qWhere, qArgs...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "released summary failed")
		return
	}

	byDisposition := map[string]int{}
	for _, row := range dispositions {
		byDisposition[row.Key] = row.Count
	}
	byDirection := map[string]int{}
	for _, row := range directions {
		byDirection[row.Key] = row.Count
	}
	phishingTotal := 0
	for _, row := range phishingReports {
		phishingTotal += row.Count
	}
	httpx.WriteJSON(w, http.StatusOK, Summary{
		Window:           window,
		Since:            since,
		Until:            until,
		Total:            total,
		Inbound:          byDirection["inbound"],
		Outbound:         byDirection["outbound"],
		Disposition:      dispositions,
		DeliveryOutcomes: deliveryOutcomes,
		ThreatCategories: threatCategories,
		EmailTypes:       emailTypes,
		ScoreBands:       scoreBands,
		PhishingReports:  phishingReports,
		TopSymbols:       topSymbols,
		TopDomains:       topDomains,
		TopSenders:       topSenders,
		BlockedSenders:   blockedSenders,
		DailyVolume:      daily,
		MailTypeTimeline: mailTypeTimeline,
		Quarantined:      byDisposition["quarantined"],
		Released:         released,
		PhishingTotal:    phishingTotal,
		Rejected:         byDisposition["rejected"],
		Delivered:        byDisposition["delivered"],
		Tagged:           byDisposition["tagged"],
		Failed:           byDisposition["failed"],
		BlockedTotal:     blockedTotal,
	})
}

func parseWindow(value string) (time.Duration, error) {
	switch value {
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported window")
	}
}

func scopedWhere(orgIDs []uuid.UUID, superAdmin bool, since, until time.Time, ident *auth.Identity) (string, []any) {
	args := []any{since, until}
	where := "WHERE received_at >= $1 AND received_at < $2"
	if superAdmin {
		if ident != nil && ident.Role == "org_user" {
			args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
			where += " AND " + recipientClause("", len(args))
		}
		return where, args
	}
	args = append(args, orgIDs)
	where += fmt.Sprintf(" AND organization_id = ANY($%d)", len(args))
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		where += " AND " + recipientClause("", len(args))
	}
	return where, args
}

func scopedQuarantineWhere(orgIDs []uuid.UUID, superAdmin bool, since time.Time, ident *auth.Identity) (string, []any) {
	args := []any{since}
	where := "WHERE released_at >= $1 AND state = 'released'"
	if !superAdmin {
		args = append(args, orgIDs)
		where += fmt.Sprintf(" AND organization_id = ANY($%d)", len(args))
	}
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		where += fmt.Sprintf(" AND lower(to_addr) = $%d", len(args))
	}
	return where, args
}

func scopedPhishingWhere(orgIDs []uuid.UUID, superAdmin bool, since time.Time, ident *auth.Identity) (string, []any) {
	args := []any{since}
	where := "WHERE pr.reported_at >= $1"
	if !superAdmin {
		args = append(args, orgIDs)
		where += fmt.Sprintf(" AND pr.organization_id = ANY($%d)", len(args))
	}
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		where += fmt.Sprintf(` AND (
			EXISTS (SELECT 1 FROM unnest(ml.to_addrs) AS t WHERE lower(t) = $%d)
			OR EXISTS (
				SELECT 1 FROM mailbox_messages mm
				WHERE mm.id = pr.mailbox_message_id AND lower(mm.to_addr) = $%d
			)
		)`, len(args), len(args))
	}
	return where, args
}

func aliasWhere(where, alias string) string {
	out := strings.ReplaceAll(where, "received_at", alias+".received_at")
	out = strings.ReplaceAll(out, "organization_id", alias+".organization_id")
	out = strings.ReplaceAll(out, "mail_logs.", alias+".")
	out = strings.ReplaceAll(out, "unnest(to_addrs)", "unnest("+alias+".to_addrs)")
	return out
}

func recipientClause(alias string, argIndex int) string {
	prefix := "mail_logs."
	unnestTarget := "to_addrs"
	if alias != "" {
		prefix = alias + "."
		unnestTarget = alias + ".to_addrs"
	}
	return fmt.Sprintf(`(
		EXISTS (SELECT 1 FROM unnest(%s) AS t WHERE lower(t) = $%d)
		OR EXISTS (
			SELECT 1 FROM mailbox_messages mm
			WHERE mm.mail_log_id = %sid AND lower(mm.to_addr) = $%d
		)
	)`, unnestTarget, argIndex, prefix, argIndex)
}

func emailTypeCase(alias string) string {
	return `CASE
	  WHEN EXISTS (
		SELECT 1 FROM mailbox_messages mm
		WHERE mm.mail_log_id = ` + alias + `.id AND mm.verdict = 'not_spam'
	  ) THEN 'User confirmed clean'
	  WHEN EXISTS (
		SELECT 1 FROM mailbox_messages mm
		WHERE mm.mail_log_id = ` + alias + `.id AND mm.verdict IN ('phishing', 'malware')
	  ) THEN 'User reported threat'
	  WHEN EXISTS (
		SELECT 1 FROM mailbox_messages mm
		WHERE mm.mail_log_id = ` + alias + `.id AND mm.verdict = 'spam'
	  ) THEN 'User reported spam'
	  WHEN EXISTS (
		SELECT 1 FROM scan_jobs sj
		WHERE sj.mail_log_id = ` + alias + `.id AND sj.verdict IN ('malicious', 'phishing', 'malware')
	  ) THEN 'Scanner confirmed threat'
	  WHEN lower(COALESCE(` + alias + `.reason, '')) LIKE '%phishing signal%' THEN 'Possible phishing'
	  WHEN lower(COALESCE(` + alias + `.reason, '')) LIKE '%phishing%' THEN 'Likely phishing'
	  WHEN lower(COALESCE(` + alias + `.reason, '')) LIKE '%malware%' OR lower(COALESCE(` + alias + `.reason, '')) LIKE '%virus%' THEN 'Likely malware'
	  WHEN ` + alias + `.disposition = 'quarantined' OR COALESCE(` + alias + `.rspamd_score, 0) >= 7 THEN 'Likely spam'
	  WHEN ` + alias + `.disposition = 'tagged' OR COALESCE(` + alias + `.rspamd_score, 0) >= 5 THEN 'Possible spam'
	  WHEN ` + alias + `.disposition = 'rejected' THEN 'Rejected'
	  WHEN ` + alias + `.disposition = 'failed' THEN 'Failed/deferred'
	  ELSE 'Clean or wanted mail'
	END`
}

func (h *Handler) count(r *http.Request, query string, args ...any) (int, error) {
	var count int
	err := h.DB.QueryRow(r.Context(), query, args...).Scan(&count)
	return count, err
}

func (h *Handler) countRows(r *http.Request, _ string, query string, args ...any) ([]CountRow, error) {
	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CountRow{}
	for rows.Next() {
		var row CountRow
		if err := rows.Scan(&row.Key, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) dailyRows(r *http.Request, query string, args ...any) ([]DailyRow, error) {
	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DailyRow{}
	for rows.Next() {
		var row DailyRow
		if err := rows.Scan(&row.Day, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *Handler) timeTypeRows(r *http.Request, query string, args ...any) ([]TimeTypeRow, error) {
	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TimeTypeRow{}
	for rows.Next() {
		var row TimeTypeRow
		if err := rows.Scan(&row.Bucket, &row.Type, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
