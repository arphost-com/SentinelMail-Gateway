// Package quarantine implements /api/v1/quarantine.
package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	stdmail "net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/audit"
	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/phishingreports"
	"github.com/arphost/sentinelmail-gateway/internal/senderlists"
	"github.com/arphost/sentinelmail-gateway/internal/sentemails"
	"github.com/arphost/sentinelmail-gateway/internal/spoofing"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Entry struct {
	ID             uuid.UUID         `json:"id"`
	OrganizationID uuid.UUID         `json:"organization_id"`
	MailLogID      *uuid.UUID        `json:"mail_log_id,omitempty"`
	DomainID       *uuid.UUID        `json:"domain_id,omitempty"`
	FromAddr       *string           `json:"from_addr,omitempty"`
	ToAddr         string            `json:"to_addr"`
	Subject        *string           `json:"subject,omitempty"`
	RspamdScore    *float64          `json:"rspamd_score,omitempty"`
	ThreatClass    *string           `json:"threat_class,omitempty"`
	ClientIP       *string           `json:"client_ip,omitempty"`
	StorageKey     string            `json:"storage_key"`
	SizeBytes      *int              `json:"size_bytes,omitempty"`
	State          string            `json:"state"`
	HasBlob        bool              `json:"has_blob"`
	CanRelease     bool              `json:"can_release"`
	EmailType      string            `json:"email_type"`
	ScamWarning    string            `json:"scam_warning,omitempty"`
	ScamSignals    []string          `json:"scam_signals,omitempty"`
	ScamLinks      []classifier.Link `json:"scam_links,omitempty"`
	AuthStatus     string            `json:"auth_status,omitempty"`
	SpoofWarning   string            `json:"spoof_warning,omitempty"`
	SpoofSignals   []string          `json:"spoof_signals,omitempty"`
	Headers        []HeaderLine      `json:"headers,omitempty"`
	ContentText    string            `json:"content_text,omitempty"`
	RawExcerpt     string            `json:"raw_excerpt,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	ReceivedAt     time.Time         `json:"received_at"`
	ReleasedAt     *time.Time        `json:"released_at,omitempty"`
	ReleasedBy     *uuid.UUID        `json:"released_by,omitempty"`

	mailLogReason  *string
	mailLogSymbols json.RawMessage
}

type HeaderLine struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

const cols = `id, organization_id, mail_log_id, domain_id, from_addr, to_addr, subject,
              rspamd_score, threat_class, storage_key, size_bytes, state::text,
              EXISTS (SELECT 1 FROM quarantine_blobs qb WHERE qb.quarantine_entry_id = quarantine_entries.id),
              (SELECT client_ip::text FROM mail_logs ml WHERE ml.id = quarantine_entries.mail_log_id),
              expires_at, received_at, released_at, released_by,
              (SELECT reason FROM mail_logs ml WHERE ml.id = quarantine_entries.mail_log_id),
              COALESCE((SELECT symbols FROM mail_logs ml WHERE ml.id = quarantine_entries.mail_log_id), '{}'::jsonb)`

func scan(row pgx.Row, e *Entry) error {
	err := row.Scan(&e.ID, &e.OrganizationID, &e.MailLogID, &e.DomainID,
		&e.FromAddr, &e.ToAddr, &e.Subject, &e.RspamdScore, &e.ThreatClass,
		&e.StorageKey, &e.SizeBytes, &e.State, &e.HasBlob, &e.ClientIP, &e.ExpiresAt,
		&e.ReceivedAt, &e.ReleasedAt, &e.ReleasedBy, &e.mailLogReason, &e.mailLogSymbols)
	e.CanRelease = e.State == "held" && e.HasBlob
	applyAnalysis(e)
	return err
}

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/bulk", h.bulkAction)
	r.Post("/purge-expired", h.purgeExpired)
	r.Get("/{id}", h.read)
	r.Post("/{id}/release", h.release)
	r.Post("/{id}/not-spam", h.notSpam)
	r.Post("/{id}/verdict", h.verdict)
	r.Post("/{id}/block-sender", h.blockSender)
	r.Post("/{id}/allow-sender", h.allowSender)
	r.Get("/{id}/source-ip-report", h.prepareSourceIPReport)
	r.Post("/{id}/source-ip-report", h.sendSourceIPReport)
	r.Delete("/{id}", h.del)
}

func applyAnalysis(e *Entry) {
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	analysis := classifier.AnalyzeCommonScam(subject, "")
	e.EmailType = analysis.EmailType
	e.ScamWarning = analysis.Warning
	e.ScamSignals = analysis.Signals
	e.ScamLinks = analysis.Links
	reason := ""
	if e.mailLogReason != nil {
		reason = *e.mailLogReason
	}
	spoof := spoofing.Analyze(reason, e.mailLogSymbols)
	e.AuthStatus = spoof.Status
	e.SpoofWarning = spoof.Warning
	e.SpoofSignals = spoof.Signals
	if e.EmailType == "Clean or uncategorized" {
		if e.ThreatClass != nil && strings.TrimSpace(*e.ThreatClass) != "" {
			e.EmailType = *e.ThreatClass
			return
		}
		if e.RspamdScore != nil && *e.RspamdScore >= 7 {
			e.EmailType = "Likely spam"
			return
		}
		e.EmailType = "Quarantined message"
	}
}

func ReleaseHeldForRecipient(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID, toAddr string, releasedBy uuid.UUID) (bool, error) {
	h := &Handler{DB: db}
	var e Entry
	err := scan(db.QueryRow(ctx, `
		SELECT `+cols+`
		  FROM quarantine_entries
		 WHERE mail_log_id = $1
		   AND lower(to_addr) = lower($2)
		   AND state = 'held'
		 ORDER BY received_at DESC
		 LIMIT 1
	`, mailLogID, toAddr), &e)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if err := h.releaseMessage(ctx, &e); err != nil {
		return false, err
	}
	if _, err := db.Exec(ctx,
		`UPDATE quarantine_entries SET state = 'released', released_at = now(), released_by = $1 WHERE id = $2`,
		releasedBy, e.ID); err != nil {
		return false, err
	}
	return true, nil
}

func DeleteHeldForRecipient(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID, toAddr string) (bool, error) {
	tag, err := db.Exec(ctx, `
		UPDATE quarantine_entries
		   SET state = 'deleted'
		 WHERE mail_log_id = $1
		   AND lower(to_addr) = lower($2)
		   AND state = 'held'
	`, mailLogID, toAddr)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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
	// End-user self-service: org_user role only sees mail addressed to
	// themselves. Server-side enforcement of canEndUserAct already gates
	// release/delete, but the list filter has to match so the UI doesn't
	// expose other users' mail to the role.
	if ident != nil && ident.Role == "org_user" {
		args = append(args, strings.ToLower(strings.TrimSpace(ident.Email)))
		clauses = append(clauses, fmt.Sprintf("lower(to_addr) = $%d", len(args)))
	}
	if state := q.Get("state"); state != "" {
		args = append(args, state)
		clauses = append(clauses, fmt.Sprintf("state = $%d::quarantine_state", len(args)))
	}
	if to := q.Get("to"); to != "" {
		args = append(args, "%"+strings.ToLower(to)+"%")
		clauses = append(clauses, fmt.Sprintf("lower(to_addr) LIKE $%d", len(args)))
	}
	if search := firstNonEmpty(q.Get("search"), q.Get("q")); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		clauses = append(clauses, fmt.Sprintf(`(
			lower(COALESCE(from_addr, '')) LIKE $%d OR
			lower(to_addr) LIKE $%d OR
			lower(COALESCE(subject, '')) LIKE $%d OR
			EXISTS (
				SELECT 1
				  FROM quarantine_blobs qb
				 WHERE qb.quarantine_entry_id = quarantine_entries.id
				   AND lower(encode(qb.message_bytes, 'escape')) LIKE $%d
			)
		)`, len(args), len(args), len(args), len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// `where` is built from clause strings that only contain $N placeholders
	// (never user data); user values flow through `args...`.
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM quarantine_entries`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// Sprintf inputs are integer parameter indices + our own placeholder
	// strings. User values flow via `args...`.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(
		`SELECT `+cols+` FROM quarantine_entries%s ORDER BY received_at DESC LIMIT $%d OFFSET $%d`,
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
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM quarantine_entries WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.Allows(e.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if ident != nil && ident.Role == "org_user" && !canEndUserAct(ident, &e) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.loadStoredMessageDetail(r.Context(), &e); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "message detail failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

const maxDetailBytes = 128 << 10

func (h *Handler) loadStoredMessageDetail(ctx context.Context, e *Entry) error {
	if !e.HasBlob {
		return nil
	}
	var raw []byte
	if err := h.DB.QueryRow(ctx, `
		SELECT message_bytes
		  FROM quarantine_blobs
		 WHERE quarantine_entry_id = $1
	`, e.ID).Scan(&raw); err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > maxDetailBytes {
		e.RawExcerpt = string(raw[:maxDetailBytes])
	} else {
		e.RawExcerpt = string(raw)
	}
	msg, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		e.ContentText = e.RawExcerpt
		return nil
	}
	e.Headers = headerLines(msg.Header)
	body, err := io.ReadAll(io.LimitReader(msg.Body, maxDetailBytes))
	if err == nil {
		e.ContentText = string(body)
	}
	return nil
}

func headerLines(h stdmail.Header) []HeaderLine {
	preferred := []string{"From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Date", "Message-Id", "Return-Path", "Received", "Authentication-Results", "DKIM-Signature", "Content-Type"}
	seen := map[string]bool{}
	out := []HeaderLine{}
	for _, name := range preferred {
		values := h[name]
		if len(values) == 0 {
			continue
		}
		seen[strings.ToLower(name)] = true
		for _, value := range values {
			out = append(out, HeaderLine{Name: name, Value: value})
		}
	}
	for name, values := range h {
		if seen[strings.ToLower(name)] {
			continue
		}
		for _, value := range values {
			out = append(out, HeaderLine{Name: name, Value: value})
		}
	}
	return out
}

func (h *Handler) release(w http.ResponseWriter, r *http.Request) {
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
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM quarantine_entries WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, e.OrganizationID) {
		// Allow non-admin users to release messages addressed to themselves.
		if !canEndUserAct(ident, &e) {
			httpx.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	if e.State != "held" {
		httpx.WriteError(w, http.StatusConflict, "not in held state")
		return
	}
	if err := h.recordChallengeApproval(r.Context(), &e, ident); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sender approval failed")
		return
	}
	if err := h.releaseMessage(r.Context(), &e); err != nil {
		httpx.WriteError(w, http.StatusConflict, "release delivery failed: "+err.Error())
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE quarantine_entries SET state = 'released', released_at = now(), released_by = $1 WHERE id = $2`,
		ident.UserID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "release failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) notSpam(w http.ResponseWriter, r *http.Request) {
	e, ident, ok := h.readAllowedEntryWithIdentity(w, r)
	if !ok {
		return
	}
	sender, err := normalizedSenderAddress(e.FromAddr)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	senderDomain := domainPart(sender)
	if senderDomain == "" || senderDomain == "sentinelmail.local" {
		httpx.WriteError(w, http.StatusConflict, "sender domain is invalid")
		return
	}
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	released := false
	if e.State == "held" {
		if !e.HasBlob {
			httpx.WriteError(w, http.StatusConflict, "message cannot be released")
			return
		}
		if err := h.releaseMessage(r.Context(), e); err != nil {
			httpx.WriteError(w, http.StatusConflict, "release delivery failed: "+err.Error())
			return
		}
		if _, err := h.DB.Exec(r.Context(),
			`UPDATE quarantine_entries SET state = 'released', released_at = now(), released_by = $1 WHERE id = $2`,
			ident.UserID, e.ID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "release failed")
			return
		}
		e.State = "released"
		released = true
	}
	existing, pattern, err := senderlists.UpsertDomainDecision(
		r.Context(),
		h.DB,
		&e.OrganizationID,
		e.DomainID,
		userID,
		entryScope,
		senderDomain,
		"allow",
		fmt.Sprintf("Marked not spam from quarantine entry %s by %s", e.ID, ident.Email),
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "allowlist update failed")
		return
	}
	if err := h.recordQuarantineNotSpam(r.Context(), e, sender, ident); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "not-spam update failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: e.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "quarantine.not_spam").ActorIP,
		Action:         "quarantine.not_spam",
		TargetKind:     "quarantine_entry",
		TargetID:       e.ID.String(),
		Detail:         map[string]any{"pattern": pattern, "scope": entryScope, "from": sender, "to": e.ToAddr, "released": released},
	})
	message := "Message marked not spam and sender domain added to the allowlist."
	if released {
		message = "Message released, marked not spam, and sender domain added to the allowlist."
	}
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern:  pattern,
		Scope:    entryScope,
		Existing: existing,
		Message:  message,
	})
}

func (h *Handler) releaseMessage(ctx context.Context, e *Entry) error {
	var raw []byte
	if err := h.DB.QueryRow(ctx, `
		SELECT message_bytes
		  FROM quarantine_blobs
		 WHERE quarantine_entry_id = $1
	`, e.ID).Scan(&raw); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("original message is not stored for this quarantine entry")
		}
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("stored message is empty")
	}

	host, port, err := h.gatewayForRelease(ctx, e)
	if err != nil {
		return err
	}
	from := ""
	if e.FromAddr != nil {
		from = strings.TrimSpace(*e.FromAddr)
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	return sentemails.Send(ctx, h.DB, sentemails.Record{
		OrganizationID:    e.OrganizationID,
		DomainID:          e.DomainID,
		MailLogID:         e.MailLogID,
		QuarantineEntryID: &e.ID,
		Kind:              "quarantine_release",
		FromAddr:          from,
		ToAddrs:           []string{e.ToAddr},
		Subject:           subject,
		RelayHost:         host,
		RelayPort:         port,
		Raw:               raw,
	}, func() error {
		return smtp.SendMail(addr, nil, from, []string{e.ToAddr}, raw)
	})
}

func (h *Handler) gatewayForRelease(ctx context.Context, e *Entry) (string, int, error) {
	if e.DomainID == nil {
		return "", 0, fmt.Errorf("message has no domain for downstream gateway lookup")
	}
	var host string
	var port int
	err := h.DB.QueryRow(ctx, `
		SELECT host, port
		  FROM gateways
		 WHERE domain_id = $1
		   AND organization_id = $2
		   AND is_active = true
		 ORDER BY priority ASC, created_at ASC
		 LIMIT 1
	`, e.DomainID, e.OrganizationID).Scan(&host, &port)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", 0, fmt.Errorf("no active downstream gateway configured")
		}
		return "", 0, err
	}
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return "", 0, fmt.Errorf("downstream gateway is invalid")
	}
	return host, port, nil
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
	var e Entry
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM quarantine_entries WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if !scope.CanAdmin(ident.Role, e.OrganizationID) && !canEndUserAct(ident, &e) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.DB.Exec(r.Context(),
		`UPDATE quarantine_entries SET state = 'deleted' WHERE id = $1`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type bulkActionReq struct {
	IDs    []uuid.UUID `json:"ids"`
	Action string      `json:"action"`
}

type bulkActionResp struct {
	Action                 string   `json:"action"`
	Queued                 bool     `json:"queued"`
	Requested              int      `json:"requested"`
	Processed              int      `json:"processed"`
	Succeeded              int      `json:"succeeded"`
	Failed                 int      `json:"failed"`
	EmailSentTo            []string `json:"email_sent_to,omitempty"`
	Message                string   `json:"message"`
	NotifyTo               string   `json:"notify_to,omitempty"`
	NotificationPreference string   `json:"notification_preference,omitempty"`
	StartedAt              string   `json:"started_at,omitempty"`
	FinishedAt             string   `json:"finished_at,omitempty"`
}

type bulkActionResult struct {
	Processed   int
	Succeeded   int
	Failed      int
	EmailSentTo []string
}

const bulkBackgroundThreshold = 10

func (h *Handler) bulkAction(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req bulkActionReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if len(req.IDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no messages selected")
		return
	}
	if len(req.IDs) > 500 {
		httpx.WriteError(w, http.StatusBadRequest, "too many messages selected")
		return
	}
	if !validBulkAction(req.Action) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid bulk action")
		return
	}
	if shouldQueueBulkAction(req.Action, len(req.IDs)) {
		ids := append([]uuid.UUID(nil), req.IDs...)
		action := req.Action
		actor := *ident
		notification := h.bulkCompletionNotification(r.Context(), ident.UserID)
		go h.runBulkActionInBackground(ids, action, actor)
		httpx.WriteJSON(w, http.StatusAccepted, bulkActionResp{
			Action:                 action,
			Queued:                 true,
			Requested:              len(ids),
			Message:                bulkQueuedMessage(notification),
			NotifyTo:               bulkNotifyTo(notification, ident.Email),
			NotificationPreference: notification,
			StartedAt:              time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	result := h.runBulkAction(r.Context(), req.IDs, req.Action, scope, ident, r)
	httpx.WriteJSON(w, http.StatusOK, bulkActionResp{
		Action:      req.Action,
		Requested:   len(req.IDs),
		Processed:   result.Processed,
		Succeeded:   result.Succeeded,
		Failed:      result.Failed,
		EmailSentTo: result.EmailSentTo,
		Message:     bulkMessage(req.Action, result),
		FinishedAt:  time.Now().UTC().Format(time.RFC3339),
	})
}

func validBulkAction(action string) bool {
	switch action {
	case "release", "delete", "block_sender", "block_domain", "block_root_domain", "report_source_ip", "mark_spam", "mark_phishing", "mark_malware", "mark_other":
		return true
	default:
		return false
	}
}

func shouldQueueBulkAction(action string, count int) bool {
	if action == "report_source_ip" {
		return count >= 2
	}
	return count >= bulkBackgroundThreshold
}

func (h *Handler) runBulkActionInBackground(ids []uuid.UUID, action string, ident auth.Identity) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	notification := h.bulkCompletionNotification(ctx, ident.UserID)
	scope, err := tenant.ScopeForIdentity(ctx, h.DB, &ident)
	if err != nil {
		if bulkCompletionSendsEmail(notification) {
			_ = h.sendBulkCompletionEmail(context.Background(), ident, action, len(ids), bulkActionResult{Failed: len(ids)}, "scope failed: "+err.Error())
		}
		return
	}
	result := h.runBulkAction(ctx, ids, action, scope, &ident, nil)
	if bulkCompletionSendsEmail(notification) {
		_ = h.sendBulkCompletionEmail(context.Background(), ident, action, len(ids), result, "")
	}
}

func (h *Handler) runBulkAction(ctx context.Context, ids []uuid.UUID, action string, scope *tenant.Scope, ident *auth.Identity, r *http.Request) bulkActionResult {
	var result bulkActionResult
	for _, id := range ids {
		result.Processed++
		e, err := h.loadAllowedEntry(ctx, id, scope, ident)
		if err != nil {
			result.Failed++
			continue
		}
		emailSentTo, err := h.applyBulkAction(ctx, e, action, ident)
		if err != nil {
			result.Failed++
			continue
		}
		result.EmailSentTo = appendUniqueStrings(result.EmailSentTo, emailSentTo...)
		result.Succeeded++
	}
	auditDetail := map[string]any{"action": action, "requested": len(ids), "processed": result.Processed, "succeeded": result.Succeeded, "failed": result.Failed, "email_sent_to": result.EmailSentTo}
	evt := audit.Event{
		OrganizationID: ident.OrganizationID,
		ActorUserID:    ident.UserID,
		Action:         "quarantine.bulk_action",
		TargetKind:     "quarantine",
		Detail:         auditDetail,
	}
	if r != nil {
		evt.ActorIP = audit.FromRequest(r, "quarantine.bulk_action").ActorIP
	}
	audit.WriteAsync(h.DB, evt)
	return result
}

func (h *Handler) applyBulkAction(ctx context.Context, e *Entry, action string, ident *auth.Identity) ([]string, error) {
	switch action {
	case "release":
		if e.State != "held" {
			return nil, fmt.Errorf("not in held state")
		}
		if err := h.recordChallengeApproval(ctx, e, ident); err != nil {
			return nil, err
		}
		if err := h.releaseMessage(ctx, e); err != nil {
			return nil, err
		}
		_, err := h.DB.Exec(ctx, `UPDATE quarantine_entries SET state = 'released', released_at = now(), released_by = $1 WHERE id = $2`, ident.UserID, e.ID)
		if err != nil {
			return nil, err
		}
		return []string{e.ToAddr}, nil
	case "delete":
		_, err := h.DB.Exec(ctx, `UPDATE quarantine_entries SET state = 'deleted' WHERE id = $1`, e.ID)
		return nil, err
	case "block_sender":
		return nil, h.blockEntrySender(ctx, e, ident, "sender")
	case "block_domain":
		return nil, h.blockEntrySender(ctx, e, ident, "domain")
	case "block_root_domain":
		return nil, h.blockEntrySender(ctx, e, ident, "root_domain")
	case "mark_spam":
		return nil, h.recordQuarantineVerdict(ctx, e, ident, "spam")
	case "mark_phishing":
		return nil, h.recordQuarantineVerdict(ctx, e, ident, "phishing")
	case "mark_malware":
		return nil, h.recordQuarantineVerdict(ctx, e, ident, "malware")
	case "mark_other":
		return nil, h.recordQuarantineVerdict(ctx, e, ident, "other")
	case "report_source_ip":
		report, err := h.buildSourceIPReport(ctx, e)
		if err != nil {
			return nil, err
		}
		if !report.CanSend {
			return nil, fmt.Errorf("%s", report.Warning)
		}
		if err := h.sendAbuseReport(ctx, e, report); err != nil {
			return nil, err
		}
		return report.AbuseContacts, nil
	default:
		return nil, fmt.Errorf("invalid action")
	}
}

func (h *Handler) loadAllowedEntry(ctx context.Context, id uuid.UUID, scope *tenant.Scope, ident *auth.Identity) (*Entry, error) {
	var e Entry
	if err := scan(h.DB.QueryRow(ctx, `SELECT `+cols+` FROM quarantine_entries WHERE id = $1`, id), &e); err != nil {
		return nil, err
	}
	if !scope.Allows(e.OrganizationID) {
		return nil, fmt.Errorf("not found")
	}
	if ident != nil && ident.Role == "org_user" && !canEndUserAct(ident, &e) {
		return nil, fmt.Errorf("not found")
	}
	return &e, nil
}

func bulkMessage(action string, result bulkActionResult) string {
	return fmt.Sprintf("%s complete: %d succeeded, %d failed.", strings.ReplaceAll(action, "_", " "), result.Succeeded, result.Failed)
}

func (h *Handler) bulkCompletionNotification(ctx context.Context, userID uuid.UUID) string {
	var value string
	err := h.DB.QueryRow(ctx, `SELECT bulk_completion_notification FROM users WHERE id = $1`, userID).Scan(&value)
	if err != nil {
		return "email"
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "email" && value != "in_app" && value != "both" && value != "off" {
		return "email"
	}
	return value
}

func bulkCompletionSendsEmail(value string) bool {
	return value == "email" || value == "both"
}

func bulkNotifyTo(value, email string) string {
	if bulkCompletionSendsEmail(value) {
		return email
	}
	return ""
}

func bulkQueuedMessage(value string) string {
	switch value {
	case "email":
		return "Bulk action is running in the background. SentinelMail will email you when it finishes."
	case "both":
		return "Bulk action is running in the background. SentinelMail will show in-app status and email you when it finishes."
	case "in_app":
		return "Bulk action is running in the background. SentinelMail will keep completion status in the app."
	case "off":
		return "Bulk action is running in the background. Completion notifications are turned off."
	default:
		return "Bulk action is running in the background."
	}
}

func (h *Handler) sendBulkCompletionEmail(ctx context.Context, ident auth.Identity, action string, requested int, result bulkActionResult, extra string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	host, port, err := h.gatewayForNotification(ctx, ident.OrganizationID, ident.Email)
	if err != nil {
		return err
	}
	from := reportFrom(ctx, h.DB, ident.OrganizationID)
	subject := sanitizeHeader("SentinelMail bulk quarantine action finished")
	bodyLines := []string{
		"SentinelMail finished your bulk quarantine action.",
		"",
		"Action: " + strings.ReplaceAll(action, "_", " "),
		fmt.Sprintf("Requested: %d", requested),
		fmt.Sprintf("Processed: %d", result.Processed),
		fmt.Sprintf("Succeeded: %d", result.Succeeded),
		fmt.Sprintf("Failed: %d", result.Failed),
		"Finished at: " + time.Now().UTC().Format(time.RFC3339),
	}
	if len(result.EmailSentTo) > 0 {
		bodyLines = append(bodyLines, "", "Emails sent to:")
		for _, email := range result.EmailSentTo {
			bodyLines = append(bodyLines, "- "+email)
		}
	}
	if strings.TrimSpace(extra) != "" {
		bodyLines = append(bodyLines, "", "Note: "+sanitizeHeader(extra))
	}
	raw := strings.Join([]string{
		"From: " + from.String(),
		"To: " + (&stdmail.Address{Address: ident.Email}).String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		strings.Join(bodyLines, "\r\n"),
	}, "\r\n")
	return sentemails.Send(ctx, h.DB, sentemails.Record{
		OrganizationID: ident.OrganizationID,
		Kind:           "bulk_quarantine_completion",
		FromAddr:       from.Address,
		ToAddrs:        []string{ident.Email},
		Subject:        subject,
		RelayHost:      host,
		RelayPort:      port,
		Raw:            []byte(raw),
		Metadata:       map[string]any{"action": action, "requested": requested, "processed": result.Processed, "succeeded": result.Succeeded, "failed": result.Failed},
	}, func() error {
		return smtp.SendMail(net.JoinHostPort(host, fmt.Sprint(port)), nil, from.Address, []string{ident.Email}, []byte(raw))
	})
}

func (h *Handler) gatewayForNotification(ctx context.Context, orgID uuid.UUID, recipient string) (string, int, error) {
	domain := domainPart(recipient)
	var host string
	var port int
	err := h.DB.QueryRow(ctx, `
		SELECT g.host, g.port
		  FROM gateways g
		  JOIN domains d ON d.id = g.domain_id
		 WHERE d.organization_id = $1
		   AND lower(d.name::text) = lower($2)
		   AND d.is_active = true
		   AND g.is_active = true
		 ORDER BY g.priority ASC, g.created_at ASC
		 LIMIT 1
	`, orgID, domain).Scan(&host, &port)
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(host), port, nil
}

type purgeExpiredResp struct {
	PurgedEntries int64 `json:"purged_entries"`
	PurgedBlobs   int64 `json:"purged_blobs"`
}

func (h *Handler) purgeExpired(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	if ident == nil || (ident.Role != "super_admin" && ident.Role != "msp_admin" && ident.Role != "org_admin") {
		httpx.WriteError(w, http.StatusForbidden, "admin required")
		return
	}
	visible := scope.VisibleOrgIDs
	if len(visible) == 0 && !scope.IsSuperAdmin {
		visible = []uuid.UUID{scope.OrgID}
	}
	var resp purgeExpiredResp
	if err := h.DB.QueryRow(r.Context(), `
		WITH candidates AS (
			SELECT id
			  FROM quarantine_entries
			 WHERE expires_at IS NOT NULL
			   AND expires_at <= now()
			   AND ($1::boolean OR organization_id = ANY($2::uuid[]))
		),
		deleted_blobs AS (
			DELETE FROM quarantine_blobs
			 WHERE quarantine_entry_id IN (SELECT id FROM candidates)
			RETURNING 1
		),
		deleted_entries AS (
			DELETE FROM quarantine_entries
			 WHERE id IN (SELECT id FROM candidates)
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM deleted_entries)::bigint,
		       (SELECT count(*) FROM deleted_blobs)::bigint
	`, scope.IsSuperAdmin, visible).Scan(&resp.PurgedEntries, &resp.PurgedBlobs); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "purge failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: ident.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "quarantine.purge_expired").ActorIP,
		Action:         "quarantine.purge_expired",
		TargetKind:     "quarantine",
		Detail:         map[string]any{"purged_entries": resp.PurgedEntries, "purged_blobs": resp.PurgedBlobs},
	})
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type blockSenderReq struct {
	Match   string `json:"match"`
	Pattern string `json:"pattern"`
	Scope   string `json:"scope"`
	Verdict string `json:"verdict"`
}

type blockSenderResp struct {
	Pattern  string `json:"pattern"`
	Scope    string `json:"scope"`
	Existing bool   `json:"existing"`
	Message  string `json:"message"`
}

func (h *Handler) blockSender(w http.ResponseWriter, r *http.Request) {
	e, ident, ok := h.readAllowedEntryWithIdentity(w, r)
	if !ok {
		return
	}
	var req blockSenderReq
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
	verdict := normalizeQuarantineVerdict(req.Verdict)
	if verdict == "" {
		verdict = currentEntryVerdict(e)
	}
	if !validQuarantineVerdict(verdict) || verdict == "not_spam" {
		httpx.WriteError(w, http.StatusBadRequest, "verdict must be spam, phishing, malware, or other")
		return
	}
	sender, err := normalizedSenderAddress(e.FromAddr)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	pattern := sender
	if match == "domain" || match == "root_domain" {
		domain := domainPart(sender)
		if domain == "" || domain == "sentinelmail.local" {
			httpx.WriteError(w, http.StatusConflict, "sender domain is invalid")
			return
		}
		if strings.TrimSpace(req.Pattern) != "" {
			domain, _, err = senderlists.NormalizeSenderDomainPattern(req.Pattern)
			if err != nil {
				httpx.WriteError(w, http.StatusConflict, err.Error())
				return
			}
		} else if match == "root_domain" {
			domain, err = senderlists.RootSenderDomain(domain)
			if err != nil {
				httpx.WriteError(w, http.StatusConflict, err.Error())
				return
			}
		}
		pattern = "*@" + domain
	}
	entryScope, userID, err := h.resolveBlockScope(r, e, ident, strings.ToLower(strings.TrimSpace(req.Scope)))
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	existing := false
	if match == "domain" || match == "root_domain" {
		var orgID *uuid.UUID
		if entryScope != "system" {
			orgID = &e.OrganizationID
		}
		existing, pattern, err = senderlists.UpsertDomainDecision(r.Context(), h.DB, orgID, nil, userID, entryScope, strings.TrimPrefix(pattern, "*@"), "block", quarantineBlockNote(e, ident, verdict))
		if err != nil {
			httpx.WriteError(w, http.StatusConflict, err.Error())
			return
		}
	} else {
		existing, err = h.insertBlockEntry(r.Context(), e, entryScope, userID, pattern, ident, verdict)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "block sender failed")
			return
		}
	}
	if err := h.finishSenderBlock(r.Context(), e, sender, ident, verdict); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "spam report failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: e.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "quarantine.report_spam").ActorIP,
		Action:         "quarantine.report_spam",
		TargetKind:     "quarantine_entry",
		TargetID:       e.ID.String(),
		Detail: map[string]any{
			"match":   match,
			"pattern": pattern,
			"scope":   entryScope,
			"from":    sender,
			"to":      e.ToAddr,
			"verdict": verdict,
		},
	})
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern:  pattern,
		Scope:    entryScope,
		Existing: existing,
		Message:  "Sender blocked and message reported as " + verdict + ".",
	})
}

func (h *Handler) allowSender(w http.ResponseWriter, r *http.Request) {
	e, ident, ok := h.readAllowedEntryWithIdentity(w, r)
	if !ok {
		return
	}
	var req blockSenderReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	match := strings.ToLower(strings.TrimSpace(req.Match))
	if match == "" {
		match = "domain"
	}
	if match != "domain" && match != "root_domain" {
		httpx.WriteError(w, http.StatusBadRequest, "match must be domain or root_domain")
		return
	}
	sender, err := normalizedSenderAddress(e.FromAddr)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
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
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	existing, pattern, err := senderlists.UpsertDomainDecision(
		r.Context(),
		h.DB,
		&e.OrganizationID,
		e.DomainID,
		userID,
		entryScope,
		domain,
		"allow",
		fmt.Sprintf("Whitelisted from quarantine entry %s by %s", e.ID, ident.Email),
	)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if err := h.recordQuarantineNotSpam(r.Context(), e, sender, ident); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "not-spam update failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: e.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "quarantine.allow_sender").ActorIP,
		Action:         "quarantine.allow_sender",
		TargetKind:     "quarantine_entry",
		TargetID:       e.ID.String(),
		Detail:         map[string]any{"match": match, "pattern": pattern, "scope": entryScope, "from": sender, "to": e.ToAddr},
	})
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern:  pattern,
		Scope:    entryScope,
		Existing: existing,
		Message:  "Sender domain whitelisted and message marked not spam.",
	})
}

type verdictReq struct {
	Verdict string `json:"verdict"`
}

func (h *Handler) verdict(w http.ResponseWriter, r *http.Request) {
	e, ident, ok := h.readAllowedEntryWithIdentity(w, r)
	if !ok {
		return
	}
	var req verdictReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	verdict := normalizeQuarantineVerdict(req.Verdict)
	if !validQuarantineVerdict(verdict) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid verdict")
		return
	}
	if verdict == "not_spam" {
		httpx.WriteError(w, http.StatusBadRequest, "use the not-spam action to release and allow this sender")
		return
	}
	if err := h.recordQuarantineVerdict(r.Context(), e, ident, verdict); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "verdict update failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: e.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "quarantine.verdict").ActorIP,
		Action:         "quarantine.verdict",
		TargetKind:     "quarantine_entry",
		TargetID:       e.ID.String(),
		Detail:         map[string]any{"verdict": verdict, "to": e.ToAddr, "from": entryStringValue(e.FromAddr)},
	})
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern: entryStringValue(e.FromAddr),
		Scope:   "quarantine",
		Message: "Message marked as " + verdict + ".",
	})
}

func (h *Handler) resolveBlockScope(r *http.Request, e *Entry, ident *auth.Identity, requested string) (string, *uuid.UUID, error) {
	scope, _, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		return "", nil, fmt.Errorf("scope")
	}
	if requested == "" {
		if ident.Role == "org_user" {
			requested = "user"
		} else {
			requested = "org"
		}
	}
	switch requested {
	case "org":
		if !scope.CanAdmin(ident.Role, e.OrganizationID) {
			return "", nil, fmt.Errorf("forbidden")
		}
		return "org", nil, nil
	case "user":
		if ident.Role == "org_user" {
			if !canEndUserAct(ident, e) {
				return "", nil, fmt.Errorf("forbidden")
			}
			return "user", &ident.UserID, nil
		}
		if !scope.CanAdmin(ident.Role, e.OrganizationID) {
			return "", nil, fmt.Errorf("forbidden")
		}
		var userID uuid.UUID
		err := h.DB.QueryRow(r.Context(), `
			SELECT id
			  FROM users
			 WHERE organization_id = $1
			   AND lower(email::text) = lower($2)
			 LIMIT 1
		`, e.OrganizationID, strings.TrimSpace(e.ToAddr)).Scan(&userID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return "", nil, fmt.Errorf("recipient user was not found")
			}
			return "", nil, err
		}
		return "user", &userID, nil
	default:
		return "", nil, fmt.Errorf("scope must be org or user")
	}
}

func (h *Handler) insertBlockEntry(ctx context.Context, e *Entry, entryScope string, userID *uuid.UUID, pattern string, ident *auth.Identity, verdict string) (bool, error) {
	note := quarantineBlockNote(e, ident, verdict)
	var id uuid.UUID
	err := h.DB.QueryRow(ctx, `
		INSERT INTO list_entries (organization_id, domain_id, user_id, scope, action, pattern, note)
		SELECT $1, NULL, $2, $3::listentry_scope, 'block'::listentry_action, $4, $5
		 WHERE NOT EXISTS (
			SELECT 1
			  FROM list_entries
			 WHERE organization_id = $1
			   AND domain_id IS NULL
			   AND user_id IS NOT DISTINCT FROM $2
			   AND scope = $3::listentry_scope
			   AND action = 'block'::listentry_action
			   AND lower(pattern) = lower($4)
		 )
		RETURNING id
	`, e.OrganizationID, userID, entryScope, strings.ToLower(pattern), note).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (h *Handler) blockEntrySender(ctx context.Context, e *Entry, ident *auth.Identity, match string) error {
	sender, err := normalizedSenderAddress(e.FromAddr)
	if err != nil {
		return err
	}
	pattern := sender
	if match == "domain" || match == "root_domain" {
		domain := domainPart(sender)
		if domain == "" || domain == "sentinelmail.local" {
			return fmt.Errorf("sender domain is invalid")
		}
		if match == "root_domain" {
			domain, err = senderlists.RootSenderDomain(domain)
			if err != nil {
				return err
			}
		}
		pattern = "*@" + domain
	}
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	verdict := currentEntryVerdict(e)
	if match == "domain" || match == "root_domain" {
		if _, _, err := senderlists.UpsertDomainDecision(ctx, h.DB, &e.OrganizationID, nil, userID, entryScope, strings.TrimPrefix(pattern, "*@"), "block", quarantineBlockNote(e, ident, verdict)); err != nil {
			return err
		}
	} else {
		if _, err := h.insertBlockEntry(ctx, e, entryScope, userID, pattern, ident, verdict); err != nil {
			return err
		}
	}
	return h.finishSenderBlock(ctx, e, sender, ident, verdict)
}

func (h *Handler) finishSenderBlock(ctx context.Context, e *Entry, sender string, ident *auth.Identity, verdict string) error {
	if err := h.recordQuarantineClassification(ctx, e, sender, ident, verdict); err != nil {
		slog.Warn("quarantine.classification_update_failed",
			"quarantine_entry_id", e.ID.String(),
			"verdict", verdict,
			"err", err.Error())
	}
	return h.recordQuarantineVerdict(ctx, e, ident, verdict)
}

func (h *Handler) recordChallengeApproval(ctx context.Context, e *Entry, ident *auth.Identity) error {
	if ident == nil || ident.Role != "org_user" || !canEndUserAct(ident, e) || e.MailLogID == nil {
		return nil
	}
	var reason string
	if err := h.DB.QueryRow(ctx, `SELECT COALESCE(reason, '') FROM mail_logs WHERE id = $1`, *e.MailLogID).Scan(&reason); err != nil {
		return nil
	}
	if !challenge.IsPendingReason(reason) {
		return nil
	}
	from := ""
	if e.FromAddr != nil {
		from = *e.FromAddr
	}
	return senderlists.UpsertUserDecision(ctx, h.DB, e.OrganizationID, e.DomainID, ident.UserID, e.ToAddr, from, "allow", "Challenge-response approved from quarantine")
}

func (h *Handler) recordQuarantineClassification(ctx context.Context, e *Entry, sender string, ident *auth.Identity, verdict string) error {
	verdict = normalizeQuarantineVerdict(verdict)
	if verdict == "" || verdict == "not_spam" {
		verdict = "spam"
	}
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	fingerprints := []string{classifier.SubjectFingerprint(subject)}
	if fingerprints[0] != "" {
		fingerprints = append(fingerprints, "")
	}
	for _, fingerprint := range fingerprints {
		_, err := h.DB.Exec(ctx, `
			INSERT INTO user_mail_classifications
			  (organization_id, domain_id, user_email, from_addr, subject_fingerprint,
			   verdict, sample_count, last_mailbox_message_id, last_mail_log_id,
			   last_body_excerpt, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, 1, NULL, $7, '', $8, $8)
			ON CONFLICT (organization_id, (lower(user_email)), (lower(from_addr)), subject_fingerprint)
			DO UPDATE SET
			  domain_id = EXCLUDED.domain_id,
			  verdict = EXCLUDED.verdict,
			  sample_count = user_mail_classifications.sample_count + 1,
			  last_mail_log_id = EXCLUDED.last_mail_log_id,
			  updated_by = EXCLUDED.updated_by,
			  updated_at = now()
		`, e.OrganizationID, e.DomainID, strings.ToLower(strings.TrimSpace(e.ToAddr)), sender, fingerprint, verdict, e.MailLogID, ident.UserID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) recordQuarantineNotSpam(ctx context.Context, e *Entry, sender string, ident *auth.Identity) error {
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	if fingerprint := classifier.SubjectFingerprint(subject); fingerprint != "" {
		_, err := h.DB.Exec(ctx, `
			INSERT INTO user_mail_classifications
			  (organization_id, domain_id, user_email, from_addr, subject_fingerprint,
			   verdict, sample_count, last_mailbox_message_id, last_mail_log_id,
			   last_body_excerpt, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, 'not_spam', 1, NULL, $6, '', $7, $7)
			ON CONFLICT (organization_id, (lower(user_email)), (lower(from_addr)), subject_fingerprint)
			DO UPDATE SET
			  domain_id = EXCLUDED.domain_id,
			  verdict = EXCLUDED.verdict,
			  sample_count = user_mail_classifications.sample_count + 1,
			  last_mail_log_id = EXCLUDED.last_mail_log_id,
			  updated_by = EXCLUDED.updated_by,
			  updated_at = now()
		`, e.OrganizationID, e.DomainID, strings.ToLower(strings.TrimSpace(e.ToAddr)), sender, fingerprint, e.MailLogID, ident.UserID)
		if err != nil {
			return err
		}
	}
	return h.recordQuarantineVerdict(ctx, e, ident, "not_spam")
}

func (h *Handler) recordQuarantineVerdict(ctx context.Context, e *Entry, ident *auth.Identity, verdict string) error {
	verdict = normalizeQuarantineVerdict(verdict)
	if verdict == "" {
		return fmt.Errorf("invalid verdict")
	}
	if !validQuarantineVerdict(verdict) {
		return fmt.Errorf("invalid verdict")
	}
	threatClass := quarantineThreatClass(verdict)
	_, err := h.DB.Exec(ctx, `
		UPDATE quarantine_entries
		   SET threat_class = $1,
		       state = CASE
		         WHEN $3 <> 'not_spam' AND state = 'held' THEN 'deleted'::quarantine_state
		         ELSE state
		       END
		 WHERE id = $2
	`, threatClass, e.ID, verdict)
	if err != nil {
		return err
	}
	if err := phishingreports.RecordFromQuarantine(ctx, h.DB, e.ID, verdict, ident.UserID); err != nil {
		slog.Warn("quarantine.phishing_report_failed",
			"quarantine_entry_id", e.ID.String(),
			"verdict", verdict,
			"err", err.Error())
	}
	e.ThreatClass = &threatClass
	if verdict != "not_spam" && e.State == "held" {
		e.State = "deleted"
	}
	return nil
}

func validQuarantineVerdict(v string) bool {
	switch v {
	case "not_spam", "spam", "phishing", "malware", "other":
		return true
	default:
		return false
	}
}

func normalizeQuarantineVerdict(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func quarantineThreatClass(verdict string) string {
	switch normalizeQuarantineVerdict(verdict) {
	case "not_spam":
		return "NOT_SPAM"
	case "phishing":
		return "PHISHING"
	case "malware":
		return "MALWARE"
	case "other":
		return "OTHER"
	case "spam":
		fallthrough
	default:
		return "SPAM"
	}
}

func currentEntryVerdict(e *Entry) string {
	if e == nil || e.ThreatClass == nil {
		return "spam"
	}
	switch strings.ToUpper(strings.TrimSpace(*e.ThreatClass)) {
	case "NOT_SPAM":
		return "not_spam"
	case "MALWARE":
		return "malware"
	case "PHISHING":
		return "phishing"
	case "OTHER":
		return "other"
	case "SPAM":
		fallthrough
	default:
		return "spam"
	}
}

func quarantineBlockNote(e *Entry, ident *auth.Identity, verdict string) string {
	actor := ""
	if ident != nil {
		actor = ident.Email
	}
	verdict = normalizeQuarantineVerdict(verdict)
	if verdict == "" {
		verdict = "spam"
	}
	return fmt.Sprintf("Reported as %s from quarantine entry %s by %s", verdict, e.ID, actor)
}

func quarantineThreatLabel(e *Entry) string {
	if e == nil || e.ThreatClass == nil {
		return "phishing"
	}
	switch strings.ToUpper(strings.TrimSpace(*e.ThreatClass)) {
	case "MALWARE":
		return "malware"
	case "SPAM":
		return "spam"
	case "OTHER":
		return "suspicious"
	case "PHISHING":
		return "phishing"
	default:
		return strings.ToLower(strings.TrimSpace(*e.ThreatClass))
	}
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

func entryStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type SourceIPReport struct {
	IP             string        `json:"ip"`
	NetworkName    string        `json:"network_name,omitempty"`
	AbuseContacts  []string      `json:"abuse_contacts"`
	ReportSubject  string        `json:"report_subject"`
	ReportBody     string        `json:"report_body"`
	CanSend        bool          `json:"can_send"`
	Sent           bool          `json:"sent,omitempty"`
	SentTo         []string      `json:"sent_to,omitempty"`
	Warning        string        `json:"warning,omitempty"`
	OutboundServer string        `json:"outbound_server,omitempty"`
	SubmissionMode string        `json:"submission_mode"`
	Webform        *AbuseWebform `json:"webform,omitempty"`
}

type AbuseWebform struct {
	Provider             string `json:"provider"`
	URL                  string `json:"url"`
	AbuseType            string `json:"abuse_type"`
	AbuseSubtype         string `json:"abuse_subtype,omitempty"`
	ReportedIP           string `json:"reported_ip"`
	DateOfIncident       string `json:"date_of_incident"`
	AdditionalInfo       string `json:"additional_information"`
	AttachmentNote       string `json:"attachment_note,omitempty"`
	ContactName          string `json:"contact_name,omitempty"`
	ContactEmail         string `json:"contact_email,omitempty"`
	CompanyName          string `json:"company_name,omitempty"`
	PhoneNumber          string `json:"phone_number,omitempty"`
	PrivacyConfirmation  string `json:"privacy_confirmation,omitempty"`
	AccuracyConfirmation string `json:"accuracy_confirmation,omitempty"`
}

func PrepareSourceIPReportForEntry(ctx context.Context, db *pgxpool.Pool, e *Entry) (*SourceIPReport, error) {
	h := &Handler{DB: db}
	return h.buildSourceIPReport(ctx, e)
}

func SendSourceIPReportForEntry(ctx context.Context, db *pgxpool.Pool, e *Entry) (*SourceIPReport, error) {
	h := &Handler{DB: db}
	report, err := h.buildSourceIPReport(ctx, e)
	if err != nil {
		return nil, err
	}
	if !report.CanSend {
		return report, fmt.Errorf("%s", report.Warning)
	}
	if err := h.sendAbuseReport(ctx, e, report); err != nil {
		report.Warning = "send failed: " + err.Error()
		return report, err
	}
	report.Sent = true
	report.SentTo = append([]string(nil), report.AbuseContacts...)
	return report, nil
}

func (h *Handler) prepareSourceIPReport(w http.ResponseWriter, r *http.Request) {
	e, ok := h.readAllowedEntry(w, r)
	if !ok {
		return
	}
	report, err := h.buildSourceIPReport(r.Context(), e)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, report)
}

func (h *Handler) sendSourceIPReport(w http.ResponseWriter, r *http.Request) {
	e, ok := h.readAllowedEntry(w, r)
	if !ok {
		return
	}
	report, err := h.buildSourceIPReport(r.Context(), e)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if !report.CanSend {
		httpx.WriteJSON(w, http.StatusConflict, report)
		return
	}
	if err := h.sendAbuseReport(r.Context(), e, report); err != nil {
		report.Warning = "send failed: " + err.Error()
		httpx.WriteJSON(w, http.StatusBadGateway, report)
		return
	}
	report.Sent = true
	report.SentTo = append([]string(nil), report.AbuseContacts...)
	httpx.WriteJSON(w, http.StatusOK, report)
}

func (h *Handler) readAllowedEntry(w http.ResponseWriter, r *http.Request) (*Entry, bool) {
	e, _, ok := h.readAllowedEntryWithIdentity(w, r)
	return e, ok
}

func (h *Handler) readAllowedEntryWithIdentity(w http.ResponseWriter, r *http.Request) (*Entry, *auth.Identity, bool) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return nil, nil, false
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return nil, nil, false
	}
	var e Entry
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM quarantine_entries WHERE id = $1`, id), &e); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	if !scope.Allows(e.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	if ident != nil && ident.Role == "org_user" && !canEndUserAct(ident, &e) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	return &e, ident, true
}

func (h *Handler) buildSourceIPReport(ctx context.Context, e *Entry) (*SourceIPReport, error) {
	if e.ClientIP == nil || strings.TrimSpace(*e.ClientIP) == "" {
		return nil, fmt.Errorf("no source IP was recorded for this message")
	}
	ip, err := parseReportableSourceIP(strings.TrimSpace(*e.ClientIP))
	if err != nil {
		return nil, err
	}
	rdap, err := lookupRDAP(ctx, ip.String())
	if err != nil {
		report := &SourceIPReport{
			IP:             ip.String(),
			ReportSubject:  sanitizeHeader(reportSubjectForThreat(e, ip.String())),
			Warning:        "RDAP lookup is temporarily unavailable. Try again in a few minutes; the report cannot be sent until an abuse contact is found.",
			SubmissionMode: "email",
		}
		report.ReportBody = buildAbuseReportBody(e, report)
		return report, nil
	}
	report := &SourceIPReport{
		IP:             ip.String(),
		NetworkName:    rdap.Name,
		AbuseContacts:  rdap.AbuseContacts,
		ReportSubject:  sanitizeHeader(reportSubjectForThreat(e, ip.String())),
		SubmissionMode: "email",
	}
	report.ReportBody = buildAbuseReportBody(e, report)
	if isWorldstreamAbuseProvider(rdap) {
		report.SubmissionMode = "webform"
		report.Webform = h.worldstreamAbuseWebform(ctx, e, report)
		report.Warning = "Worldstream requires abuse complaints through its webform; email reports to their abuse mailbox are not processed."
		return report, nil
	}
	host := lookupSystemSetting(ctx, h.DB, "mail.outbound_relay_host", "")
	port := lookupSystemSetting(ctx, h.DB, "mail.outbound_relay_port", "25")
	if len(report.AbuseContacts) == 0 {
		report.Warning = "No abuse contact was found in RDAP."
		return report, nil
	}
	if strings.TrimSpace(host) == "" {
		report.Warning = "No outbound relay is configured."
		return report, nil
	}
	if !h.hasReportEvidence(ctx, e) {
		report.Warning = "No message evidence is available for this quarantine entry, so an abuse report cannot be sent."
		return report, nil
	}
	report.CanSend = true
	report.OutboundServer = net.JoinHostPort(host, port)
	return report, nil
}

func parseReportableSourceIP(value string) (netip.Addr, error) {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), "")
	if value == "" {
		return netip.Addr{}, fmt.Errorf("recorded source IP is invalid")
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		if prefix, prefixErr := netip.ParsePrefix(value); prefixErr == nil {
			ip = prefix.Addr()
			err = nil
		}
	}
	if err != nil {
		return netip.Addr{}, fmt.Errorf("recorded source IP is invalid")
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("recorded source IP is not publicly reportable")
	}
	return ip, nil
}

type rdapLookup struct {
	Name          string
	AbuseContacts []string
}

var rdapEndpointTemplates = []string{
	"https://rdap.db.ripe.net/ip/%s",
	"https://rdap.arin.net/registry/ip/%s",
	"https://rdap.apnic.net/ip/%s",
	"https://rdap.lacnic.net/rdap/ip/%s",
	"https://rdap.afrinic.net/rdap/ip/%s",
	"https://rdap.org/ip/%s",
}

func lookupRDAP(ctx context.Context, ip string) (*rdapLookup, error) {
	escapedIP := url.PathEscape(ip)
	var failures []string
	var fallback *rdapLookup
	for _, tmpl := range rdapEndpointTemplates {
		endpoint := fmt.Sprintf(tmpl, escapedIP)
		lookup, err := lookupRDAPEndpoint(ctx, endpoint)
		if err == nil && len(lookup.AbuseContacts) > 0 {
			return lookup, nil
		}
		if err == nil {
			if fallback == nil {
				fallback = lookup
			}
			failures = append(failures, endpoint+" returned no abuse contact")
			continue
		}
		failures = append(failures, err.Error())
	}
	if fallback != nil {
		return fallback, nil
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("rdap lookup temporarily unavailable")
	}
	return nil, fmt.Errorf("rdap lookup temporarily unavailable after trying trusted registries: %s", strings.Join(failures, "; "))
}

func lookupRDAPEndpoint(ctx context.Context, endpoint string) (*rdapLookup, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: validateRDAPRedirect,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	var doc rdapDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s response invalid", endpoint)
	}
	contacts := uniqueEmails(doc.collectAbuseEmails(nil))
	return &rdapLookup{Name: firstNonEmpty(doc.Name, doc.Handle), AbuseContacts: contacts}, nil
}

func validateRDAPRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("rdap lookup redirected too many times")
	}
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Hostname() == "" || req.URL.User != nil {
		return fmt.Errorf("rdap lookup redirected to an untrusted endpoint")
	}
	return nil
}

type rdapDoc struct {
	Handle   string       `json:"handle"`
	Name     string       `json:"name"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles     []string       `json:"roles"`
	VCard     []any          `json:"vcardArray"`
	Entities  []rdapEntity   `json:"entities"`
	PublicIDs []rdapPublicID `json:"publicIds"`
	Handle    string         `json:"handle"`
}

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

func (d rdapDoc) collectAbuseEmails(out []string) []string {
	for _, entity := range d.Entities {
		out = entity.collectAbuseEmails(out, false)
	}
	return out
}

func (e rdapEntity) collectAbuseEmails(out []string, inheritedAbuse bool) []string {
	isAbuse := inheritedAbuse || hasRole(e.Roles, "abuse")
	if isAbuse {
		out = append(out, vcardEmails(e.VCard)...)
	}
	for _, child := range e.Entities {
		out = child.collectAbuseEmails(out, isAbuse)
	}
	return out
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if strings.EqualFold(role, want) {
			return true
		}
	}
	return false
}

func vcardEmails(vcard []any) []string {
	if len(vcard) < 2 {
		return nil
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, prop := range props {
		items, ok := prop.([]any)
		if !ok || len(items) < 4 {
			continue
		}
		name, _ := items[0].(string)
		if !strings.EqualFold(name, "email") {
			continue
		}
		email, _ := items[3].(string)
		if parsed, err := stdmail.ParseAddress(email); err == nil {
			out = append(out, strings.ToLower(parsed.Address))
		}
	}
	return out
}

func uniqueEmails(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func appendUniqueStrings(out []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range out {
		seen[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func buildAbuseReportBody(e *Entry, report *SourceIPReport) string {
	from := ""
	if e.FromAddr != nil {
		from = *e.FromAddr
	}
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	threat := ""
	if e.ThreatClass != nil {
		threat = *e.ThreatClass
	}
	threatLabel := quarantineThreatLabel(e)
	lines := []string{
		"Hello,",
		"",
		"SentinelMail Gateway quarantined a " + threatLabel + " email from an IP address registered to your network.",
		"",
		"Source IP: " + report.IP,
		"Network: " + emptyDash(report.NetworkName),
		"SMTP sender: " + emptyDash(safeReportValue(from)),
		"Recipient: " + emptyDash(safeReportValue(e.ToAddr)),
		"Subject: " + emptyDash(safeReportValue(subject)),
		"Threat class: " + emptyDash(safeReportValue(threat)),
		"Received at: " + e.ReceivedAt.UTC().Format(time.RFC3339),
		"SentinelMail evidence ID: " + e.ID.String(),
		"",
		"A message/rfc822 evidence attachment is included so your abuse team can review the original message when stored, or SentinelMail's captured quarantine evidence when the original raw message is unavailable.",
		"Please investigate the source host and take appropriate action.",
		"",
		"SentinelMail Gateway",
	}
	return strings.Join(lines, "\r\n")
}

const worldstreamAbuseFormURL = "https://www.worldstream.com/en/abuse/abuse-form/"

func isWorldstreamAbuseProvider(lookup *rdapLookup) bool {
	if lookup == nil {
		return false
	}
	if strings.Contains(strings.ToLower(lookup.Name), "worldstream") {
		return true
	}
	for _, contact := range lookup.AbuseContacts {
		if strings.EqualFold(domainPart(contact), "worldstream.com") {
			return true
		}
	}
	return false
}

func (h *Handler) worldstreamAbuseWebform(ctx context.Context, e *Entry, report *SourceIPReport) *AbuseWebform {
	from := reportFrom(ctx, h.DB, e.OrganizationID)
	company := lookupOrgSetting(ctx, h.DB, e.OrganizationID, "brand.name", "")
	if strings.TrimSpace(company) == "" {
		company = lookupSystemSetting(ctx, h.DB, "ui.brand_name", "SentinelMail Gateway")
	}
	contactName := strings.TrimSpace(company)
	if contactName == "" {
		contactName = "SentinelMail Gateway"
	}
	return &AbuseWebform{
		Provider:             "Worldstream",
		URL:                  worldstreamAbuseFormURL,
		AbuseType:            "Spam",
		AbuseSubtype:         "Sending email spam",
		ReportedIP:           report.IP,
		DateOfIncident:       e.ReceivedAt.UTC().Format("2006-01-02"),
		AdditionalInfo:       buildWorldstreamAdditionalInfo(e, report),
		AttachmentNote:       "Attach the original-message.eml or sentinelmail-evidence.eml evidence from this quarantine entry when the form asks for a file.",
		ContactName:          contactName,
		ContactEmail:         from.Address,
		CompanyName:          strings.TrimSpace(company),
		PrivacyConfirmation:  "Review Worldstream's privacy policy in the browser, then tick this box if you agree.",
		AccuracyConfirmation: "Tick this box only after reviewing that the copied SentinelMail evidence is true and accurate.",
	}
}

func buildWorldstreamAdditionalInfo(e *Entry, report *SourceIPReport) string {
	lines := []string{
		"Abuse type: Spam",
		"Abuse subtype: Sending email spam",
		"",
		report.ReportBody,
		"",
		"Form evidence checklist:",
		"- IP address of reported content: " + report.IP,
		"- Date of incident: " + e.ReceivedAt.UTC().Format(time.RFC3339),
		"- Evidence attachment: original-message.eml if available; otherwise sentinelmail-evidence.eml.",
	}
	return strings.Join(lines, "\r\n")
}

func reportSubjectForThreat(e *Entry, ip string) string {
	label := quarantineThreatLabel(e)
	if label == "" {
		label = "phishing"
	}
	return strings.ToUpper(label[:1]) + label[1:] + " email from " + ip
}

func (h *Handler) sendAbuseReport(ctx context.Context, e *Entry, report *SourceIPReport) error {
	host := lookupSystemSetting(ctx, h.DB, "mail.outbound_relay_host", "")
	port := lookupSystemSetting(ctx, h.DB, "mail.outbound_relay_port", "25")
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("no outbound relay configured")
	}
	from := reportFrom(ctx, h.DB, e.OrganizationID)
	evidence, original, err := h.reportEvidenceBytes(ctx, e)
	if err != nil {
		return err
	}
	raw := buildAbuseReportMessage(from.String(), report.AbuseContacts, report.ReportSubject, report.ReportBody, e, report, evidence, original)
	relayPort, _ := strconv.Atoi(strings.TrimSpace(port))
	quarantineEntryID := h.sentEmailQuarantineEntryID(ctx, e)
	return sentemails.Send(ctx, h.DB, sentemails.Record{
		OrganizationID:    e.OrganizationID,
		DomainID:          e.DomainID,
		MailLogID:         e.MailLogID,
		QuarantineEntryID: quarantineEntryID,
		Kind:              "source_ip_abuse_report",
		FromAddr:          from.Address,
		ToAddrs:           report.AbuseContacts,
		Subject:           report.ReportSubject,
		RelayHost:         host,
		RelayPort:         relayPort,
		Raw:               raw,
		Metadata:          map[string]any{"source_ip": report.IP, "network_name": report.NetworkName, "includes_original_message": original, "includes_evidence_message": true},
	}, func() error {
		return sendRelayMail(host, port, from.Address, report.AbuseContacts, raw)
	})
}

func buildAbuseReportMessage(from string, to []string, subject, body string, e *Entry, report *SourceIPReport, evidence []byte, original bool) []byte {
	boundary := "smg-abuse-" + uuid.NewString()
	feedback := buildFeedbackReport(e, report)
	filename := "sentinelmail-evidence.eml"
	if original {
		filename = "original-message.eml"
	}
	var out bytes.Buffer
	out.WriteString(strings.Join([]string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + sanitizeHeader(subject),
		"MIME-Version: 1.0",
		`Content-Type: multipart/report; report-type=feedback-report; boundary="` + boundary + `"`,
		"",
		"This is a multipart abuse report generated by SentinelMail Gateway.",
		"",
		"--" + boundary,
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		body,
		"",
		"--" + boundary,
		"Content-Type: message/feedback-report",
		"Content-Transfer-Encoding: 7bit",
		"",
		feedback,
		"",
		"--" + boundary,
		"Content-Type: message/rfc822",
		`Content-Disposition: attachment; filename="` + filename + `"`,
		"",
	}, "\r\n"))
	out.Write(evidence)
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes()
}

func buildFeedbackReport(e *Entry, report *SourceIPReport) string {
	from := ""
	if e.FromAddr != nil {
		from = *e.FromAddr
	}
	lines := []string{
		"Feedback-Type: abuse",
		"User-Agent: SentinelMail Gateway",
		"Version: 1",
		"Source-IP: " + report.IP,
		"Original-Mail-From: " + safeReportValue(from),
		"Original-Rcpt-To: " + safeReportValue(e.ToAddr),
		"Arrival-Date: " + e.ReceivedAt.UTC().Format(time.RFC1123Z),
	}
	return strings.Join(lines, "\r\n")
}

func (h *Handler) hasReportEvidence(ctx context.Context, e *Entry) bool {
	_, _, err := h.reportEvidenceBytes(ctx, e)
	return err == nil
}

func (h *Handler) reportEvidenceBytes(ctx context.Context, e *Entry) ([]byte, bool, error) {
	if e == nil {
		return nil, false, fmt.Errorf("message evidence is not available")
	}
	var raw []byte
	if e.ID != uuid.Nil {
		if err := h.DB.QueryRow(ctx, `
			SELECT message_bytes
			  FROM quarantine_blobs
			 WHERE quarantine_entry_id = $1
			   AND organization_id = $2
		`, e.ID, e.OrganizationID).Scan(&raw); err == nil && len(raw) > 0 {
			return raw, true, nil
		} else if err != nil && err != pgx.ErrNoRows {
			return nil, false, err
		}
	}
	if e.MailLogID != nil {
		if err := h.DB.QueryRow(ctx, `
			SELECT message_bytes
			  FROM mail_log_blobs
			 WHERE mail_log_id = $1
			   AND organization_id = $2
		`, *e.MailLogID, e.OrganizationID).Scan(&raw); err == nil && len(raw) > 0 {
			return raw, true, nil
		} else if err != nil && err != pgx.ErrNoRows {
			return nil, false, err
		}
	}
	evidence := synthesizedEvidenceMessage(e)
	if len(evidence) == 0 {
		return nil, false, fmt.Errorf("message evidence is not available")
	}
	return evidence, false, nil
}

func synthesizedEvidenceMessage(e *Entry) []byte {
	if e == nil || e.ID == uuid.Nil {
		return nil
	}
	from := ""
	if e.FromAddr != nil {
		from = *e.FromAddr
	}
	subject := ""
	if e.Subject != nil {
		subject = *e.Subject
	}
	threat := ""
	if e.ThreatClass != nil {
		threat = *e.ThreatClass
	}
	clientIP := ""
	if e.ClientIP != nil {
		clientIP = *e.ClientIP
	}
	headers := []string{
		"From: " + sanitizeHeader(from),
		"To: " + sanitizeHeader(e.ToAddr),
		"Subject: " + sanitizeHeader(subject),
		"Date: " + e.ReceivedAt.UTC().Format(time.RFC1123Z),
		"X-SentinelMail-Evidence-ID: " + e.ID.String(),
		"X-SentinelMail-Source-IP: " + sanitizeHeader(clientIP),
		"X-SentinelMail-Threat-Class: " + sanitizeHeader(threat),
	}
	body := []string{
		"This is a SentinelMail-generated evidence message.",
		"",
		"The original raw message was not available in quarantine storage when this abuse report was sent.",
		"Stored quarantine metadata is included in the RFC822 headers above.",
	}
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.Join(body, "\r\n") + "\r\n")
}

func (h *Handler) sentEmailQuarantineEntryID(ctx context.Context, e *Entry) *uuid.UUID {
	if e == nil || e.ID == uuid.Nil {
		return nil
	}
	var exists bool
	if err := h.DB.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM quarantine_entries
			 WHERE id = $1
			   AND organization_id = $2
		)
	`, e.ID, e.OrganizationID).Scan(&exists); err != nil || !exists {
		return nil
	}
	return &e.ID
}

// LookupSystemSetting returns a system setting value using the same fallback
// behavior as quarantine notification and report sends.
func LookupSystemSetting(ctx context.Context, db *pgxpool.Pool, key, fallback string) string {
	return lookupSystemSetting(ctx, db, key, fallback)
}

// SendRelayMail sends a raw message through the configured relay semantics used
// by quarantine reports, including plain SMTP for internal relays.
func SendRelayMail(host, port, from string, to []string, raw []byte) error {
	return sendRelayMail(host, port, from, to, raw)
}

func sendRelayMail(host, port, from string, to []string, raw []byte) error {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	addr := net.JoinHostPort(host, port)
	if usePlainInternalRelay(host) {
		return sendPlainRelayMail(addr, from, to, raw)
	}
	return smtp.SendMail(addr, nil, from, to, raw)
}

func usePlainInternalRelay(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return !strings.Contains(host, ".")
}

func sendPlainRelayMail(addr, from string, to []string, raw []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	serverName := "localhost"
	if host, _, err := net.SplitHostPort(addr); err == nil && strings.TrimSpace(host) != "" {
		serverName = strings.Trim(host, "[]")
	}
	c, err := smtp.NewClient(conn, serverName)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Hello("sentinelmail.local"); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(raw); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func reportFrom(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID) *stdmail.Address {
	addr := lookupOrgSetting(ctx, db, orgID, "brand.support_email", "")
	if addr == "" {
		host := lookupSystemSetting(ctx, db, "mail.hostname", "sentinelmail.local")
		addr = "no-reply@" + domainPart(host)
	}
	parsed, err := stdmail.ParseAddress(addr)
	if err != nil || parsed.Address == "" {
		parsed = &stdmail.Address{Address: "no-reply@sentinelmail.local"}
	}
	name := lookupOrgSetting(ctx, db, orgID, "brand.name", "")
	if name == "" {
		name = lookupSystemSetting(ctx, db, "ui.brand_name", "SentinelMail Gateway")
	}
	parsed.Name = name
	return parsed
}

func lookupSystemSetting(ctx context.Context, db *pgxpool.Pool, key, fallback string) string {
	var value string
	err := db.QueryRow(ctx, `
		SELECT trim(both '"' from value::text)
		  FROM system_settings
		 WHERE organization_id IS NULL
		   AND key = $1
	`, key).Scan(&value)
	if err != nil || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func lookupOrgSetting(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, key, fallback string) string {
	var value string
	err := db.QueryRow(ctx, `
		SELECT trim(both '"' from value::text)
		  FROM system_settings
		 WHERE organization_id = $1
		   AND key = $2
	`, orgID, key).Scan(&value)
	if err != nil || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

var reportURLRE = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"']+`)

func safeReportValue(value string) string {
	value = sanitizeHeader(value)
	value = reportURLRE.ReplaceAllString(value, "[redacted URL]")
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func domainPart(value string) string {
	value = strings.TrimSpace(value)
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	if value == "" {
		return "sentinelmail.local"
	}
	return value
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

// canEndUserAct lets an org_user release/delete only messages addressed to
// their own email. The check is intentionally narrow — quarantine UI for
// end users is MVP 3, but the API enforces the boundary now.
func canEndUserAct(ident *auth.Identity, e *Entry) bool {
	if ident.Role != "org_user" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(e.ToAddr), strings.TrimSpace(ident.Email))
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
