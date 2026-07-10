// Package maillogs implements /api/v1/mail-logs (read-only) plus /stats.
package maillogs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	stdmail "net/mail"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/audit"
	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/quarantine"
	"github.com/arphost/sentinelmail-gateway/internal/senderlists"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Entry struct {
	ID             uuid.UUID         `json:"id"`
	OrganizationID uuid.UUID         `json:"organization_id"`
	DomainID       *uuid.UUID        `json:"domain_id,omitempty"`
	QueueID        *string           `json:"queue_id,omitempty"`
	MessageID      *string           `json:"message_id,omitempty"`
	Direction      string            `json:"direction"`
	FromAddr       *string           `json:"from_addr,omitempty"`
	ToAddrs        []string          `json:"to_addrs"`
	ClientIP       *netip.Addr       `json:"client_ip,omitempty"`
	Helo           *string           `json:"helo,omitempty"`
	Subject        *string           `json:"subject,omitempty"`
	SizeBytes      *int              `json:"size_bytes,omitempty"`
	RspamdScore    *float64          `json:"rspamd_score,omitempty"`
	RspamdAction   *string           `json:"rspamd_action,omitempty"`
	Symbols        json.RawMessage   `json:"symbols,omitempty"`
	Disposition    string            `json:"disposition"`
	Reason         *string           `json:"reason,omitempty"`
	EmailType      string            `json:"email_type"`
	ScamWarning    string            `json:"scam_warning,omitempty"`
	ScamSignals    []string          `json:"scam_signals,omitempty"`
	ScamLinks      []classifier.Link `json:"scam_links,omitempty"`
	ReceivedAt     time.Time         `json:"received_at"`
}

const cols = `id, organization_id, domain_id, queue_id, message_id, direction,
              from_addr, to_addrs, client_ip, helo, subject, size_bytes,
              rspamd_score, rspamd_action, symbols, disposition::text, reason, received_at`

func scan(row pgx.Row, e *Entry) error {
	err := row.Scan(&e.ID, &e.OrganizationID, &e.DomainID, &e.QueueID, &e.MessageID, &e.Direction,
		&e.FromAddr, &e.ToAddrs, &e.ClientIP, &e.Helo, &e.Subject, &e.SizeBytes,
		&e.RspamdScore, &e.RspamdAction, &e.Symbols, &e.Disposition, &e.Reason, &e.ReceivedAt)
	applyAnalysis(e)
	return err
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Get("/stats", h.stats)
	r.Get("/{id}", h.read)
	r.Post("/{id}/source-ip-report", h.reportSourceIP)
	r.Post("/{id}/block-sender", h.blockSender)
	r.Post("/{id}/not-spam", h.notSpam)
	r.Post("/{id}/release", h.releaseHeld)
	r.Post("/{id}/delete-held", h.deleteHeld)
}

func applyAnalysis(e *Entry) {
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	analysis := classifier.AnalyzeCommonScam(subject, "")
	e.ScamWarning = analysis.Warning
	e.ScamSignals = analysis.Signals
	e.ScamLinks = analysis.Links
	reason := ""
	if e.Reason != nil {
		reason = *e.Reason
	}
	reason = strings.ToLower(reason)
	switch {
	case strings.Contains(reason, "phishing signal"):
		e.EmailType = "Possible phishing"
	case strings.Contains(reason, "phishing"):
		e.EmailType = "Likely phishing"
	case strings.Contains(reason, "malware") || strings.Contains(reason, "virus"):
		e.EmailType = "Likely malware"
	case e.Disposition == "quarantined" || (e.RspamdScore != nil && *e.RspamdScore >= 7):
		e.EmailType = "Likely spam"
	case e.Disposition == "tagged" || (e.RspamdScore != nil && *e.RspamdScore >= 5):
		e.EmailType = "Possible spam"
	case e.Disposition == "rejected":
		e.EmailType = "Rejected"
	case e.Disposition == "failed":
		e.EmailType = "Failed/deferred"
	default:
		e.EmailType = "Clean or wanted mail"
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
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
	// End-user filter: org_user role only sees messages they're a recipient
	// of (matches the quarantine list filter so the two views are consistent).
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		clauses = append(clauses, recipientClause("", len(args)))
	}
	if d := q.Get("disposition"); d != "" {
		args = append(args, d)
		clauses = append(clauses, fmt.Sprintf("disposition = $%d::mail_disposition", len(args)))
	}
	if outcome := strings.ToLower(strings.TrimSpace(q.Get("outcome"))); outcome != "" {
		switch outcome {
		case "blocked":
			clauses = append(clauses, "lower(COALESCE(reason, '')) = 'sender matched blacklist'")
		case "blocked_rejected_failed":
			clauses = append(clauses, "(lower(COALESCE(reason, '')) = 'sender matched blacklist' OR disposition IN ('rejected'::mail_disposition, 'failed'::mail_disposition))")
		case "quarantined":
			clauses = append(clauses, "disposition = 'quarantined'::mail_disposition AND lower(COALESCE(reason, '')) <> 'sender matched blacklist'")
		case "held_review":
			clauses = append(clauses, "disposition IN ('tagged'::mail_disposition, 'quarantined'::mail_disposition) AND lower(COALESCE(reason, '')) <> 'sender matched blacklist'")
		case "delivered", "tagged", "rejected", "deferred", "failed":
			args = append(args, outcome)
			clauses = append(clauses, fmt.Sprintf("disposition = $%d::mail_disposition", len(args)))
		}
	}
	if dir := q.Get("direction"); dir != "" {
		args = append(args, dir)
		clauses = append(clauses, fmt.Sprintf("direction = $%d", len(args)))
	}
	if since, ok := parseFilterTime(q.Get("since")); ok {
		args = append(args, since)
		clauses = append(clauses, fmt.Sprintf("received_at >= $%d", len(args)))
	}
	if until, ok := parseFilterTime(q.Get("until")); ok {
		args = append(args, until)
		clauses = append(clauses, fmt.Sprintf("received_at < $%d", len(args)))
	}
	if from := strings.TrimSpace(q.Get("from")); from != "" {
		args = append(args, strings.ToLower(from))
		clauses = append(clauses, fmt.Sprintf("lower(from_addr) = $%d", len(args)))
	}
	if senderDomain := strings.TrimSpace(q.Get("sender_domain")); senderDomain != "" {
		args = append(args, strings.ToLower(strings.Trim(senderDomain, ". ")))
		clauses = append(clauses, fmt.Sprintf("lower(trim(both '. ' from substring(COALESCE(from_addr, '') from '@([^@>[:space:]]+)'))) = $%d", len(args)))
	}
	if to := strings.TrimSpace(q.Get("to")); to != "" {
		args = append(args, strings.ToLower(to))
		clauses = append(clauses, recipientClause("", len(args)))
	}
	if reason := strings.TrimSpace(q.Get("reason")); reason != "" {
		args = append(args, strings.ToLower(reason))
		clauses = append(clauses, fmt.Sprintf("lower(COALESCE(reason, '')) = $%d", len(args)))
	}
	if search := strings.TrimSpace(q.Get("q")); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		clauses = append(clauses, fmt.Sprintf(`(
			lower(COALESCE(from_addr, '')) LIKE $%d
			OR EXISTS (SELECT 1 FROM unnest(to_addrs) AS t WHERE lower(t) LIKE $%d)
			OR lower(COALESCE(subject, '')) LIKE $%d
			OR lower(COALESCE(queue_id, '')) LIKE $%d
			OR lower(COALESCE(message_id, '')) LIKE $%d
			OR lower(COALESCE(reason, '')) LIKE $%d
			OR lower(COALESCE(symbols::text, '')) LIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args), len(args), len(args)))
	}
	if domain := strings.TrimSpace(q.Get("domain")); domain != "" {
		args = append(args, strings.ToLower(domain))
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM domains d WHERE d.id = domain_id AND lower(d.name::text) = $%d)", len(args)))
	}
	if symbol := strings.TrimSpace(q.Get("symbol")); symbol != "" {
		args = append(args, symbol)
		clauses = append(clauses, fmt.Sprintf("COALESCE(symbols, '{}'::jsonb) ? $%d", len(args)))
	}
	if scoreBand := strings.TrimSpace(q.Get("score_band")); scoreBand != "" {
		if clause := scoreBandClause(scoreBand); clause != "" {
			clauses = append(clauses, clause)
		}
	}
	if emailType := strings.TrimSpace(q.Get("email_type")); emailType != "" {
		args = append(args, emailType)
		clauses = append(clauses, fmt.Sprintf("(%s) = $%d", mailLogEmailTypeCase("mail_logs"), len(args)))
	}
	if threatCategory := strings.TrimSpace(q.Get("threat_category")); threatCategory != "" {
		args = append(args, threatCategory)
		clauses = append(clauses, fmt.Sprintf("(%s) = $%d", mailLogThreatCategoryCase("mail_logs"), len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` is built from clause strings that only contain $N placeholders
	// (never user data); user values flow through `args...`.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM mail_logs`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// Sprintf inputs are integer parameter indices + our own placeholder
	// strings. User values are passed via `args...` and parameterised by pgx.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(
		`SELECT `+cols+` FROM mail_logs%s ORDER BY received_at DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))
	items, err := queryAll(r.Context(), h.DB, sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Entry]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var e Entry
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM mail_logs WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.Allows(e.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	// org_user can only read messages they were a recipient of.
	if ident != nil && ident.Role == "org_user" {
		me := strings.ToLower(strings.TrimSpace(ident.Email))
		match := false
		for _, t := range e.ToAddrs {
			if strings.ToLower(strings.TrimSpace(t)) == me {
				match = true
				break
			}
		}
		if !match {
			err := h.DB.QueryRow(r.Context(), `
				SELECT EXISTS (
					SELECT 1 FROM mailbox_messages
					WHERE mail_log_id = $1 AND lower(to_addr) = $2
				)
			`, e.ID, me).Scan(&match)
			if err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "recipient check failed")
				return
			}
		}
		if !match {
			httpx.WriteError(w, http.StatusNotFound, "not found")
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

type actionReq struct {
	Match string `json:"match,omitempty"`
}

type actionResp struct {
	Message    string   `json:"message"`
	Pattern    string   `json:"pattern,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Released   int      `json:"released,omitempty"`
	Deleted    int      `json:"deleted,omitempty"`
	Failed     int      `json:"failed,omitempty"`
	Sent       bool     `json:"sent,omitempty"`
	SentTo     []string `json:"sent_to,omitempty"`
	Warning    string   `json:"warning,omitempty"`
	ReportIP   string   `json:"report_ip,omitempty"`
	ReportBody string   `json:"report_body,omitempty"`
	CanSend    bool     `json:"can_send,omitempty"`
}

func (h *Handler) reportSourceIP(w http.ResponseWriter, r *http.Request) {
	log, ident, ok := h.logForAction(w, r)
	if !ok {
		return
	}
	recipient := ""
	if ident.Role == "org_user" {
		recipient = ident.Email
	}
	entry := quarantineEntryFromLog(log, recipient)
	report, err := quarantine.SendSourceIPReportForEntry(r.Context(), h.DB, entry)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: log.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mail_logs.report_source_ip").ActorIP,
		Action:         "mail_logs.report_source_ip",
		TargetKind:     "mail_log",
		TargetID:       log.ID.String(),
		Detail:         map[string]any{"source_ip": report.IP, "sent_to": report.SentTo},
	})
	httpx.WriteJSON(w, http.StatusOK, actionResp{
		Message:  "Source IP report sent.",
		Sent:     true,
		SentTo:   report.SentTo,
		ReportIP: report.IP,
		Warning:  report.Warning,
		CanSend:  report.CanSend,
	})
}

func (h *Handler) blockSender(w http.ResponseWriter, r *http.Request) {
	log, ident, ok := h.logForAction(w, r)
	if !ok {
		return
	}
	var req actionReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	match := strings.ToLower(strings.TrimSpace(req.Match))
	if match == "" {
		match = "sender"
	}
	if match != "sender" && match != "domain" && match != "root_domain" {
		httpx.WriteError(w, http.StatusBadRequest, "match must be sender, domain, or root_domain")
		return
	}
	sender, err := normalizedSenderAddress(log.FromAddr)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	pattern := sender
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	if match == "domain" || match == "root_domain" {
		domain := domainPart(sender)
		if domain == "" || domain == "sentinelmail.local" {
			httpx.WriteError(w, http.StatusConflict, "sender domain is invalid")
			return
		}
		if match == "root_domain" {
			domain, err = senderlists.RootSenderDomain(domain)
			if err != nil {
				httpx.WriteError(w, http.StatusConflict, err.Error())
				return
			}
		}
		_, pattern, err = senderlists.UpsertDomainDecision(r.Context(), h.DB, &log.OrganizationID, log.DomainID, userID, entryScope, domain, "block", fmt.Sprintf("Blocked from mail log %s by %s", log.ID, ident.Email))
	} else if entryScope == "user" {
		err = senderlists.UpsertUserDecision(r.Context(), h.DB, log.OrganizationID, log.DomainID, ident.UserID, ident.Email, sender, "block", fmt.Sprintf("Blocked from mail log %s", log.ID))
	} else {
		err = h.upsertOrgSenderBlock(r.Context(), log.OrganizationID, sender, fmt.Sprintf("Blocked from mail log %s by %s", log.ID, ident.Email))
	}
	if err != nil {
		if match == "domain" {
			httpx.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "sender block failed")
		return
	}
	deleted, failed := h.deleteHeldRecipients(r.Context(), log, ident)
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: log.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mail_logs.block_sender").ActorIP,
		Action:         "mail_logs.block_sender",
		TargetKind:     "mail_log",
		TargetID:       log.ID.String(),
		Detail:         map[string]any{"match": match, "pattern": pattern, "scope": entryScope, "deleted": deleted, "failed": failed},
	})
	httpx.WriteJSON(w, http.StatusOK, actionResp{
		Message: "Sender blocked and held copies deleted.",
		Pattern: pattern,
		Scope:   entryScope,
		Deleted: deleted,
		Failed:  failed,
	})
}

func (h *Handler) notSpam(w http.ResponseWriter, r *http.Request) {
	log, ident, ok := h.logForAction(w, r)
	if !ok {
		return
	}
	sender, err := normalizedSenderAddress(log.FromAddr)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	domain := domainPart(sender)
	if domain == "" || domain == "sentinelmail.local" {
		httpx.WriteError(w, http.StatusConflict, "sender domain is invalid")
		return
	}
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	_, pattern, err := senderlists.UpsertDomainDecision(r.Context(), h.DB, &log.OrganizationID, log.DomainID, userID, entryScope, domain, "allow", fmt.Sprintf("Marked not spam from mail log %s by %s", log.ID, ident.Email))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "allowlist update failed")
		return
	}
	released, failed := h.releaseHeldRecipients(r.Context(), log, ident)
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: log.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mail_logs.not_spam").ActorIP,
		Action:         "mail_logs.not_spam",
		TargetKind:     "mail_log",
		TargetID:       log.ID.String(),
		Detail:         map[string]any{"pattern": pattern, "scope": entryScope, "released": released, "failed": failed},
	})
	httpx.WriteJSON(w, http.StatusOK, actionResp{
		Message:  "Message marked not spam, sender domain allowlisted, and held copies released.",
		Pattern:  pattern,
		Scope:    entryScope,
		Released: released,
		Failed:   failed,
	})
}

func (h *Handler) releaseHeld(w http.ResponseWriter, r *http.Request) {
	log, ident, ok := h.logForAction(w, r)
	if !ok {
		return
	}
	released, failed := h.releaseHeldRecipients(r.Context(), log, ident)
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: log.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mail_logs.release").ActorIP,
		Action:         "mail_logs.release",
		TargetKind:     "mail_log",
		TargetID:       log.ID.String(),
		Detail:         map[string]any{"released": released, "failed": failed},
	})
	httpx.WriteJSON(w, http.StatusOK, actionResp{Message: "Held copies released.", Released: released, Failed: failed})
}

func (h *Handler) deleteHeld(w http.ResponseWriter, r *http.Request) {
	log, ident, ok := h.logForAction(w, r)
	if !ok {
		return
	}
	deleted, failed := h.deleteHeldRecipients(r.Context(), log, ident)
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: log.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mail_logs.delete_held").ActorIP,
		Action:         "mail_logs.delete_held",
		TargetKind:     "mail_log",
		TargetID:       log.ID.String(),
		Detail:         map[string]any{"deleted": deleted, "failed": failed},
	})
	httpx.WriteJSON(w, http.StatusOK, actionResp{Message: "Held copies deleted.", Deleted: deleted, Failed: failed})
}

// stats backs the dashboard widgets: counts per disposition over a window.
func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	dur, err := time.ParseDuration(window)
	if err != nil || dur <= 0 || dur > 30*24*time.Hour {
		dur = 24 * time.Hour
	}
	since := time.Now().Add(-dur)

	var args []any
	where := "WHERE received_at >= $1"
	args = append(args, since)
	if !scope.IsSuperAdmin {
		args = append(args, scope.VisibleOrgIDs)
		where += fmt.Sprintf(" AND organization_id = ANY($%d)", len(args))
	}
	// org_user: stats reflect only their own messages so the Dashboard
	// matches the Mail logs view they're allowed to see.
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		where += " AND " + recipientClause("", len(args))
	}

	// `where` is composed of fixed literal SQL + our own $N placeholder
	// strings; user data flows only through `args...`.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	query := `SELECT disposition::text, count(*) FROM mail_logs ` + where + ` GROUP BY disposition`
	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db: "+err.Error())
		return
	}
	defer rows.Close()
	by := map[string]int{}
	total := 0
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err == nil {
			by[k] = c
			total += c
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"window":      window,
		"since":       since,
		"total":       total,
		"disposition": by,
	})
}

func parseFilterTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func recipientClause(alias string, argIndex int) string {
	prefix := "mail_logs."
	if alias != "" {
		prefix = alias + "."
	}
	return fmt.Sprintf(`(
		EXISTS (SELECT 1 FROM unnest(%sto_addrs) AS t WHERE lower(t) = $%d)
		OR EXISTS (
			SELECT 1 FROM mailbox_messages mm
			WHERE mm.mail_log_id = %sid AND lower(mm.to_addr) = $%d
		)
	)`, prefix, argIndex, prefix, argIndex)
}

func scoreBandClause(value string) string {
	switch value {
	case "Reject level >= 15":
		return "rspamd_score >= 15"
	case "Quarantine level 7-14.99":
		return "rspamd_score >= 7 AND rspamd_score < 15"
	case "Tagged spam 5-6.99":
		return "rspamd_score >= 5 AND rspamd_score < 7"
	case "Low or neutral 0-4.99":
		return "rspamd_score >= 0 AND rspamd_score < 5"
	case "Trusted / negative score":
		return "rspamd_score < 0"
	default:
		return ""
	}
}

func mailLogEmailTypeCase(alias string) string {
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

func mailLogThreatCategoryCase(alias string) string {
	return `CASE
	  WHEN lower(COALESCE(` + alias + `.reason, '')) = 'sender matched blacklist' THEN 'Sender blocklist'
	  WHEN lower(COALESCE(` + alias + `.reason, '')) = 'reputation blocklist hit' THEN 'Reputation blocklist'
	  WHEN EXISTS (
		SELECT 1 FROM jsonb_object_keys(COALESCE(` + alias + `.symbols, '{}'::jsonb)) s(key)
		WHERE upper(s.key) LIKE '%PHISH%' OR upper(s.key) LIKE '%DMARC%'
	  ) THEN 'Phishing / impersonation'
	  WHEN EXISTS (
		SELECT 1 FROM jsonb_object_keys(COALESCE(` + alias + `.symbols, '{}'::jsonb)) s(key)
		WHERE upper(s.key) LIKE '%VIRUS%' OR upper(s.key) LIKE '%CLAM%' OR upper(s.key) LIKE '%MALWARE%'
	  ) THEN 'Malware'
	  WHEN EXISTS (
		SELECT 1 FROM jsonb_object_keys(COALESCE(` + alias + `.symbols, '{}'::jsonb)) s(key)
		WHERE upper(s.key) LIKE '%RBL%' OR upper(s.key) LIKE '%ZEN%' OR upper(s.key) LIKE '%SPAMHAUS%' OR upper(s.key) LIKE '%SURBL%' OR upper(s.key) LIKE '%URIBL%'
	  ) THEN 'Reputation blocklist'
	  WHEN ` + alias + `.disposition IN ('quarantined', 'tagged') THEN 'Spam content'
	  WHEN ` + alias + `.disposition IN ('rejected', 'failed') THEN 'Rejected / failed'
	  ELSE 'Clean or low risk'
	END`
}

func (h *Handler) logForAction(w http.ResponseWriter, r *http.Request) (Entry, *auth.Identity, bool) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return Entry{}, nil, false
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return Entry{}, nil, false
	}
	var e Entry
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM mail_logs WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Entry{}, nil, false
	}
	if !scope.Allows(e.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Entry{}, nil, false
	}
	if ident != nil && ident.Role == "org_user" {
		allowed := logHasRecipient(e, ident.Email)
		if !allowed {
			if err := h.DB.QueryRow(r.Context(), `
				SELECT EXISTS (
					SELECT 1 FROM mailbox_messages
					WHERE mail_log_id = $1 AND lower(to_addr) = $2
				)
			`, e.ID, strings.ToLower(strings.TrimSpace(ident.Email))).Scan(&allowed); err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "recipient check failed")
				return Entry{}, nil, false
			}
		}
		if !allowed {
			httpx.WriteError(w, http.StatusNotFound, "not found")
			return Entry{}, nil, false
		}
	}
	return e, ident, true
}

func (h *Handler) releaseHeldRecipients(ctx context.Context, log Entry, ident *auth.Identity) (int, int) {
	recipients, err := h.actionRecipients(ctx, log, ident)
	if err != nil {
		return 0, 1
	}
	released := 0
	failed := 0
	for _, recipient := range recipients {
		ok, err := quarantine.ReleaseHeldForRecipient(ctx, h.DB, log.ID, recipient, ident.UserID)
		if err != nil {
			failed++
			continue
		}
		if ok {
			released++
		}
	}
	return released, failed
}

func (h *Handler) deleteHeldRecipients(ctx context.Context, log Entry, ident *auth.Identity) (int, int) {
	recipients, err := h.actionRecipients(ctx, log, ident)
	if err != nil {
		return 0, 1
	}
	deleted := 0
	failed := 0
	for _, recipient := range recipients {
		ok, err := quarantine.DeleteHeldForRecipient(ctx, h.DB, log.ID, recipient)
		if err != nil {
			failed++
			continue
		}
		if ok {
			deleted++
		}
	}
	return deleted, failed
}

func (h *Handler) actionRecipients(ctx context.Context, log Entry, ident *auth.Identity) ([]string, error) {
	if ident.Role == "org_user" {
		return []string{ident.Email}, nil
	}
	rows, err := h.DB.Query(ctx, `
		SELECT DISTINCT to_addr
		  FROM quarantine_entries
		 WHERE mail_log_id = $1
		   AND organization_id = $2
		   AND state = 'held'
		 ORDER BY to_addr
	`, log.ID, log.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	recipients := []string{}
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, rows.Err()
}

func quarantineEntryFromLog(log Entry, recipient string) *quarantine.Entry {
	if strings.TrimSpace(recipient) == "" && len(log.ToAddrs) > 0 {
		recipient = log.ToAddrs[0]
	}
	clientIP := ""
	if log.ClientIP != nil {
		clientIP = log.ClientIP.String()
	}
	threat := log.EmailType
	return &quarantine.Entry{
		ID:             log.ID,
		OrganizationID: log.OrganizationID,
		MailLogID:      &log.ID,
		DomainID:       log.DomainID,
		FromAddr:       log.FromAddr,
		ToAddr:         recipient,
		Subject:        log.Subject,
		ThreatClass:    &threat,
		ClientIP:       &clientIP,
		ReceivedAt:     log.ReceivedAt,
	}
}

func logHasRecipient(log Entry, email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, recipient := range log.ToAddrs {
		if strings.ToLower(strings.TrimSpace(recipient)) == email {
			return true
		}
	}
	return false
}

func normalizedSenderAddress(from *string) (string, error) {
	if from == nil || strings.TrimSpace(*from) == "" {
		return "", fmt.Errorf("message has no sender address")
	}
	value := strings.TrimSpace(*from)
	if parsed, err := stdmail.ParseAddress(value); err == nil && parsed.Address != "" {
		value = parsed.Address
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if _, err := stdmail.ParseAddress(value); err != nil || !strings.Contains(value, "@") {
		return "", fmt.Errorf("sender address is invalid")
	}
	return value, nil
}

func domainPart(value string) string {
	value = strings.TrimSpace(value)
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	if value == "" {
		return "sentinelmail.local"
	}
	return strings.ToLower(strings.Trim(value, " <>"))
}

func (h *Handler) upsertOrgSenderBlock(ctx context.Context, orgID uuid.UUID, sender, note string) error {
	sender = strings.ToLower(strings.TrimSpace(sender))
	if sender == "" {
		return fmt.Errorf("sender is required")
	}
	if _, err := h.DB.Exec(ctx, `
		DELETE FROM list_entries
		 WHERE organization_id = $1
		   AND domain_id IS NULL
		   AND user_id IS NULL
		   AND scope = 'org'::listentry_scope
		   AND lower(pattern) = lower($2)
	`, orgID, sender); err != nil {
		return err
	}
	_, err := h.DB.Exec(ctx, `
		INSERT INTO list_entries (organization_id, domain_id, user_id, scope, action, pattern, note)
		VALUES ($1, NULL, NULL, 'org'::listentry_scope, 'block'::listentry_action, $2, $3)
	`, orgID, sender, note)
	return err
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Entry, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := scan(rows, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
