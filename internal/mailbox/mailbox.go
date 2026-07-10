// Package mailbox exposes per-recipient message copies and user verdicts.
package mailbox

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
	"net/url"
	"strconv"
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
	"github.com/arphost/sentinelmail-gateway/internal/phishingreports"
	"github.com/arphost/sentinelmail-gateway/internal/quarantine"
	"github.com/arphost/sentinelmail-gateway/internal/senderlists"
	"github.com/arphost/sentinelmail-gateway/internal/sentemails"
	"github.com/arphost/sentinelmail-gateway/internal/spoofing"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Message struct {
	ID             uuid.UUID        `json:"id"`
	OrganizationID uuid.UUID        `json:"organization_id"`
	DomainID       *uuid.UUID       `json:"domain_id,omitempty"`
	MailLogID      uuid.UUID        `json:"mail_log_id"`
	FromAddr       *string          `json:"from_addr,omitempty"`
	ToAddr         string           `json:"to_addr"`
	Subject        *string          `json:"subject,omitempty"`
	BodyText       string           `json:"body_text"`
	Verdict        string           `json:"verdict"`
	EmailType      string           `json:"email_type"`
	ScamWarning    string           `json:"scam_warning,omitempty"`
	ScamSignals    []string         `json:"scam_signals,omitempty"`
	ScamLinks      []Link           `json:"scam_links,omitempty"`
	AuthStatus     string           `json:"auth_status,omitempty"`
	SpoofWarning   string           `json:"spoof_warning,omitempty"`
	SpoofSignals   []string         `json:"spoof_signals,omitempty"`
	Unsubscribe    *UnsubscribeInfo `json:"unsubscribe,omitempty"`
	VerdictBy      *uuid.UUID       `json:"verdict_by,omitempty"`
	VerdictAt      *time.Time       `json:"verdict_at,omitempty"`
	ReceivedAt     time.Time        `json:"received_at"`

	mailLogReason       *string
	mailLogSymbols      json.RawMessage
	listUnsubscribe     *string
	listUnsubscribePost *string
}

type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type UnsubscribeInfo struct {
	Available bool                `json:"available"`
	OneClick  bool                `json:"one_click,omitempty"`
	Options   []UnsubscribeOption `json:"options,omitempty"`
}

type UnsubscribeOption struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

const cols = `id, organization_id, domain_id, mail_log_id, from_addr, to_addr,
              subject, body_text, verdict, verdict_by, verdict_at, received_at,
              (SELECT reason FROM mail_logs ml WHERE ml.id = mailbox_messages.mail_log_id),
              COALESCE((SELECT symbols FROM mail_logs ml WHERE ml.id = mailbox_messages.mail_log_id), '{}'::jsonb),
              list_unsubscribe, list_unsubscribe_post`

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Post("/bulk", h.bulk)
	r.Get("/{id}", h.read)
	r.Post("/{id}/unsubscribe", h.unsubscribe)
	r.Post("/{id}/verdict", h.verdict)
	r.Post("/{id}/block-sender", h.blockSender)
	r.Post("/{id}/allow-sender", h.allowSender)
	r.Delete("/{id}", h.delete)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	page := httpx.ParsePage(r)
	recipient := strings.ToLower(strings.TrimSpace(ident.Email))
	where := "WHERE organization_id = ANY($1) AND lower(to_addr) = $2 AND " + notHeldQuarantineClause("mailbox_messages")
	args := []any{scope.VisibleOrgIDs, recipient}
	if scope.IsSuperAdmin {
		where = "WHERE lower(to_addr) = $1 AND " + notHeldQuarantineClause("mailbox_messages")
		args = []any{recipient}
	}
	if verdict := strings.TrimSpace(r.URL.Query().Get("verdict")); verdict != "" {
		args = append(args, verdict)
		where += fmt.Sprintf(" AND verdict = $%d", len(args))
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		where += fmt.Sprintf(` AND (
			lower(COALESCE(from_addr, '')) LIKE $%d
			OR lower(to_addr) LIKE $%d
			OR lower(COALESCE(subject, '')) LIKE $%d
			OR lower(COALESCE(body_text, '')) LIKE $%d
		)`, len(args), len(args), len(args), len(args))
	}
	var total int
	// `where` is assembled only from fixed SQL fragments and generated $N
	// placeholders; request values are always bound through `args`.
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), "SELECT count(*) FROM mailbox_messages "+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "count")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+cols+` FROM mailbox_messages %s ORDER BY received_at DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))
	items, err := queryAll(r.Context(), h.DB, sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Message]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
	if !ok {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(msg.ToAddr), strings.TrimSpace(ident.Email)) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, msg)
}

func (h *Handler) unsubscribe(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
	if !ok {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(msg.ToAddr), strings.TrimSpace(ident.Email)) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	info := parseUnsubscribeInfo(stringValue(msg.listUnsubscribe), stringValue(msg.listUnsubscribePost))
	if info == nil || len(info.Options) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no safe unsubscribe option is available")
		return
	}
	var req unsubscribeReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	option, found := findUnsubscribeOption(info.Options, req.Type, req.URL)
	if !found {
		httpx.WriteError(w, http.StatusBadRequest, "unsubscribe option was not found on this message")
		return
	}

	var resp unsubscribeResp
	var err error
	switch option.Type {
	case "mailto":
		resp, err = h.sendMailtoUnsubscribe(r.Context(), msg, option)
	case "url":
		if !info.OneClick {
			httpx.WriteError(w, http.StatusBadRequest, "message does not advertise one-click unsubscribe")
			return
		}
		resp, err = postOneClickUnsubscribe(r.Context(), option)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unsupported unsubscribe option")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: msg.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mailbox.unsubscribe").ActorIP,
		Action:         "mailbox.unsubscribe",
		TargetKind:     "mailbox_message",
		TargetID:       msg.ID.String(),
		Detail:         map[string]any{"type": option.Type, "url": option.URL, "sent_to": resp.SentTo, "status": resp.Status},
	})
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type verdictReq struct {
	Verdict string `json:"verdict"`
}

func (h *Handler) verdict(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
	if !ok {
		return
	}
	var req verdictReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Verdict = strings.ToLower(strings.TrimSpace(req.Verdict))
	if !validVerdict(req.Verdict) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid verdict")
		return
	}
	updated, err := h.setVerdict(r.Context(), r, msg, ident, req.Verdict)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg = updated
	httpx.WriteJSON(w, http.StatusOK, msg)
}

type bulkReq struct {
	IDs     []uuid.UUID `json:"ids"`
	Action  string      `json:"action"`
	Verdict string      `json:"verdict,omitempty"`
}

type blockSenderReq struct {
	Match   string `json:"match"`
	Pattern string `json:"pattern"`
}

type blockSenderResp struct {
	Pattern string `json:"pattern"`
	Scope   string `json:"scope"`
	Match   string `json:"match"`
	Message string `json:"message"`
}

type unsubscribeReq struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type unsubscribeResp struct {
	Message string   `json:"message"`
	Type    string   `json:"type"`
	Sent    bool     `json:"sent,omitempty"`
	SentTo  []string `json:"sent_to,omitempty"`
	Status  int      `json:"status,omitempty"`
	URL     string   `json:"url,omitempty"`
}

func (h *Handler) bulk(w http.ResponseWriter, r *http.Request) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return
	}
	var req bulkReq
	if err := httpx.DecodeJSON(r, w, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no messages selected")
		return
	}
	if len(req.IDs) > 200 {
		httpx.WriteError(w, http.StatusBadRequest, "too many messages selected")
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.Verdict = strings.ToLower(strings.TrimSpace(req.Verdict))

	items, err := h.messagesForUser(r.Context(), scope, ident, req.IDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "load selected messages failed")
		return
	}
	if len(items) != len(req.IDs) {
		httpx.WriteError(w, http.StatusForbidden, "one or more selected messages are not available")
		return
	}

	switch req.Action {
	case "delete":
		if _, err := h.DB.Exec(r.Context(), `DELETE FROM mailbox_messages WHERE id = ANY($1)`, req.IDs); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
			return
		}
		for _, msg := range items {
			audit.WriteAsync(h.DB, audit.Event{
				OrganizationID: msg.OrganizationID,
				ActorUserID:    ident.UserID,
				ActorIP:        audit.FromRequest(r, "mailbox.delete").ActorIP,
				Action:         "mailbox.delete",
				TargetKind:     "mailbox_message",
				TargetID:       msg.ID.String(),
				Detail:         map[string]any{"mail_log_id": msg.MailLogID.String()},
			})
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"updated": 0, "deleted": len(items)})
	case "verdict":
		if !validVerdict(req.Verdict) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid verdict")
			return
		}
		updated := 0
		failed := 0
		for _, msg := range items {
			if _, err := h.setVerdict(r.Context(), r, msg, ident, req.Verdict); err != nil {
				failed++
				slog.Warn("mailbox.bulk_verdict_failed",
					"mailbox_message_id", msg.ID.String(),
					"mail_log_id", msg.MailLogID.String(),
					"verdict", req.Verdict,
					"err", err.Error())
				continue
			}
			updated++
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"updated": updated, "deleted": 0, "failed": failed})
	case "block_sender", "block_domain", "block_root_domain", "allow_domain", "allow_root_domain":
		action := "block"
		match := strings.TrimPrefix(req.Action, "block_")
		if strings.HasPrefix(req.Action, "allow_") {
			action = "allow"
			match = strings.TrimPrefix(req.Action, "allow_")
		}
		updated := 0
		failed := 0
		for _, msg := range items {
			var err error
			if action == "allow" {
				_, _, err = h.allowMessageSender(r.Context(), r, msg, ident, match)
			} else {
				_, _, err = h.blockMessageSender(r.Context(), r, msg, ident, match, "")
			}
			if err != nil {
				failed++
				slog.Warn("mailbox.bulk_sender_decision_failed",
					"mailbox_message_id", msg.ID.String(),
					"mail_log_id", msg.MailLogID.String(),
					"action", action,
					"match", match,
					"err", err.Error())
				continue
			}
			updated++
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"updated": updated, "deleted": 0, "failed": failed})
	default:
		httpx.WriteError(w, http.StatusBadRequest, "invalid bulk action")
	}
}

func (h *Handler) blockSender(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
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
	scope, pattern, err := h.blockMessageSender(r.Context(), r, msg, ident, match, strings.TrimSpace(req.Pattern))
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern: pattern,
		Scope:   scope,
		Match:   match,
		Message: "Sender blocked and message marked as spam.",
	})
}

func (h *Handler) allowSender(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
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
	scope, pattern, err := h.allowMessageSender(r.Context(), r, msg, ident, match)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, blockSenderResp{
		Pattern: pattern,
		Scope:   scope,
		Match:   match,
		Message: "Sender whitelisted and message marked as not spam.",
	})
}

func (h *Handler) blockMessageSender(ctx context.Context, r *http.Request, msg Message, ident *auth.Identity, match, patternOverride string) (string, string, error) {
	sender, err := normalizedSenderAddress(msg.FromAddr)
	if err != nil {
		return "", "", err
	}
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	note := fmt.Sprintf("Blocked from inbox message %s by %s", msg.ID, ident.Email)
	pattern := strings.ToLower(sender)
	if match != "sender" && match != "domain" && match != "root_domain" {
		return "", "", fmt.Errorf("match must be sender, domain, or root_domain")
	}
	if match == "domain" || match == "root_domain" {
		domain := domainPart(sender)
		if domain == "" || domain == "sentinelmail.local" {
			return "", "", fmt.Errorf("sender domain is invalid")
		}
		if patternOverride != "" {
			domain, _, err = senderlists.NormalizeSenderDomainPattern(patternOverride)
			if err != nil {
				return "", "", err
			}
		} else if match == "root_domain" {
			domain, err = senderlists.RootSenderDomain(domain)
			if err != nil {
				return "", "", err
			}
		}
		_, pattern, err = senderlists.UpsertDomainDecision(ctx, h.DB, &msg.OrganizationID, msg.DomainID, userID, entryScope, domain, "block", note)
		if err != nil {
			return "", "", err
		}
	} else if entryScope == "user" {
		if err := senderlists.UpsertUserDecision(ctx, h.DB, msg.OrganizationID, msg.DomainID, ident.UserID, msg.ToAddr, sender, "block", note); err != nil {
			return "", "", fmt.Errorf("sender block failed")
		}
	} else {
		if err := h.upsertOrgSenderBlock(ctx, msg.OrganizationID, pattern, note); err != nil {
			return "", "", fmt.Errorf("sender block failed")
		}
	}
	if _, err := h.setVerdict(ctx, r, msg, ident, "spam"); err != nil {
		return "", "", err
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: msg.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mailbox.block_sender").ActorIP,
		Action:         "mailbox.block_sender",
		TargetKind:     "mailbox_message",
		TargetID:       msg.ID.String(),
		Detail:         map[string]any{"match": match, "pattern": pattern, "scope": entryScope, "from": sender, "to": msg.ToAddr},
	})
	return entryScope, pattern, nil
}

func (h *Handler) allowMessageSender(ctx context.Context, r *http.Request, msg Message, ident *auth.Identity, match string) (string, string, error) {
	sender, err := normalizedSenderAddress(msg.FromAddr)
	if err != nil {
		return "", "", err
	}
	if match != "domain" && match != "root_domain" {
		return "", "", fmt.Errorf("match must be domain or root_domain")
	}
	entryScope := "org"
	var userID *uuid.UUID
	if ident.Role == "org_user" {
		entryScope = "user"
		userID = &ident.UserID
	}
	domain := domainPart(sender)
	if domain == "" || domain == "sentinelmail.local" {
		return "", "", fmt.Errorf("sender domain is invalid")
	}
	if match == "root_domain" {
		domain, err = senderlists.RootSenderDomain(domain)
		if err != nil {
			return "", "", err
		}
	}
	note := fmt.Sprintf("Whitelisted from inbox message %s by %s", msg.ID, ident.Email)
	_, pattern, err := senderlists.UpsertDomainDecision(ctx, h.DB, &msg.OrganizationID, msg.DomainID, userID, entryScope, domain, "allow", note)
	if err != nil {
		return "", "", err
	}
	if _, err := h.setVerdict(ctx, r, msg, ident, "not_spam"); err != nil {
		return "", "", err
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: msg.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mailbox.allow_sender").ActorIP,
		Action:         "mailbox.allow_sender",
		TargetKind:     "mailbox_message",
		TargetID:       msg.ID.String(),
		Detail:         map[string]any{"match": match, "pattern": pattern, "scope": entryScope, "from": sender, "to": msg.ToAddr},
	})
	return entryScope, pattern, nil
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

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	msg, ident, ok := h.messageForUser(w, r)
	if !ok {
		return
	}
	if _, err := h.DB.Exec(r.Context(), `DELETE FROM mailbox_messages WHERE id = $1`, msg.ID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: msg.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mailbox.delete").ActorIP,
		Action:         "mailbox.delete",
		TargetKind:     "mailbox_message",
		TargetID:       msg.ID.String(),
		Detail:         map[string]any{"mail_log_id": msg.MailLogID.String()},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setVerdict(ctx context.Context, r *http.Request, msg Message, ident *auth.Identity, verdict string) (Message, error) {
	if err := scan(h.DB.QueryRow(ctx, `
		UPDATE mailbox_messages
		   SET verdict = $1, verdict_by = $2, verdict_at = now()
		 WHERE id = $3
		 RETURNING `+cols,
		verdict, ident.UserID, msg.ID), &msg); err != nil {
		return Message{}, fmt.Errorf("update failed")
	}
	if err := classifier.Learn(ctx, h.DB, classifier.Observation{
		OrganizationID:   msg.OrganizationID,
		DomainID:         msg.DomainID,
		UserEmail:        msg.ToAddr,
		FromAddr:         stringValue(msg.FromAddr),
		Subject:          stringValue(msg.Subject),
		Verdict:          verdict,
		MailboxMessageID: msg.ID,
		MailLogID:        msg.MailLogID,
		BodyText:         msg.BodyText,
		UserID:           ident.UserID,
	}); err != nil {
		slog.Warn("mailbox.classification_update_failed",
			"mailbox_message_id", msg.ID.String(),
			"mail_log_id", msg.MailLogID.String(),
			"verdict", verdict,
			"err", err.Error())
	}
	if err := phishingreports.RecordFromMailbox(ctx, h.DB, msg.ID, verdict, ident.UserID); err != nil {
		slog.Warn("mailbox.phishing_report_failed",
			"mailbox_message_id", msg.ID.String(),
			"mail_log_id", msg.MailLogID.String(),
			"verdict", verdict,
			"err", err.Error())
	}
	released := false
	denied := false
	releaseErr := ""
	if senderlists.MailLogHasChallengeReason(ctx, h.DB, msg.MailLogID) {
		switch verdict {
		case "not_spam":
			if err := senderlists.UpsertUserDecision(ctx, h.DB, msg.OrganizationID, msg.DomainID, ident.UserID, msg.ToAddr, stringValue(msg.FromAddr), "allow", "Challenge-response approved from mailbox"); err != nil {
				return Message{}, fmt.Errorf("sender approval failed")
			}
		case "spam", "phishing", "malware":
			if err := senderlists.UpsertUserDecision(ctx, h.DB, msg.OrganizationID, msg.DomainID, ident.UserID, msg.ToAddr, stringValue(msg.FromAddr), "block", "Challenge-response denied from mailbox"); err != nil {
				return Message{}, fmt.Errorf("sender denial failed")
			}
			if ok, err := quarantine.DeleteHeldForRecipient(ctx, h.DB, msg.MailLogID, msg.ToAddr); err != nil {
				releaseErr = err.Error()
			} else {
				denied = ok
			}
		}
	}
	if verdict == "not_spam" {
		if ok, err := quarantine.ReleaseHeldForRecipient(ctx, h.DB, msg.MailLogID, msg.ToAddr, ident.UserID); err != nil {
			releaseErr = err.Error()
		} else {
			released = ok
		}
	}
	audit.WriteAsync(h.DB, audit.Event{
		OrganizationID: msg.OrganizationID,
		ActorUserID:    ident.UserID,
		ActorIP:        audit.FromRequest(r, "mailbox.verdict").ActorIP,
		Action:         "mailbox.verdict",
		TargetKind:     "mailbox_message",
		TargetID:       msg.ID.String(),
		Detail:         map[string]any{"verdict": verdict, "mail_log_id": msg.MailLogID.String(), "released": released, "denied": denied, "release_error": releaseErr},
	})
	return msg, nil
}

func (h *Handler) messageForUser(w http.ResponseWriter, r *http.Request) (Message, *auth.Identity, bool) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return Message{}, nil, false
	}
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return Message{}, nil, false
	}
	var msg Message
	if err := scan(h.DB.QueryRow(r.Context(), `SELECT `+cols+` FROM mailbox_messages WHERE id = $1 AND `+notHeldQuarantineClause("mailbox_messages"), id), &msg); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Message{}, nil, false
	}
	if !scope.Allows(msg.OrganizationID) || !strings.EqualFold(strings.TrimSpace(msg.ToAddr), strings.TrimSpace(ident.Email)) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Message{}, nil, false
	}
	return msg, ident, true
}

func (h *Handler) messagesForUser(ctx context.Context, scope *tenant.Scope, ident *auth.Identity, ids []uuid.UUID) ([]Message, error) {
	rows, err := h.DB.Query(ctx, `SELECT `+cols+` FROM mailbox_messages WHERE id = ANY($1) AND `+notHeldQuarantineClause("mailbox_messages"), ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	recipient := strings.ToLower(strings.TrimSpace(ident.Email))
	for rows.Next() {
		var msg Message
		if err := scan(rows, &msg); err != nil {
			return nil, err
		}
		if !scope.Allows(msg.OrganizationID) || strings.ToLower(strings.TrimSpace(msg.ToAddr)) != recipient {
			continue
		}
		out = append(out, msg)
	}
	return out, rows.Err()
}

func notHeldQuarantineClause(alias string) string {
	return `NOT EXISTS (
		SELECT 1
		  FROM quarantine_entries qe
		 WHERE qe.mail_log_id = ` + alias + `.mail_log_id
		   AND lower(qe.to_addr) = lower(` + alias + `.to_addr)
		   AND qe.state = 'held'
	)`
}

func validVerdict(v string) bool {
	switch v {
	case "unreviewed", "not_spam", "spam", "phishing", "malware", "other":
		return true
	default:
		return false
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
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
	if !strings.Contains(value, "@") {
		return "", fmt.Errorf("sender address is invalid")
	}
	return value, nil
}

func domainPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	at := strings.LastIndex(value, "@")
	if at >= 0 {
		value = value[at+1:]
	}
	return strings.Trim(value, " <>")
}

func scan(row pgx.Row, msg *Message) error {
	err := row.Scan(&msg.ID, &msg.OrganizationID, &msg.DomainID, &msg.MailLogID,
		&msg.FromAddr, &msg.ToAddr, &msg.Subject, &msg.BodyText, &msg.Verdict,
		&msg.VerdictBy, &msg.VerdictAt, &msg.ReceivedAt, &msg.mailLogReason,
		&msg.mailLogSymbols, &msg.listUnsubscribe, &msg.listUnsubscribePost)
	applyAnalysis(msg)
	return err
}

func queryAll(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) ([]Message, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var msg Message
		if err := scan(rows, &msg); err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, rows.Err()
}

func applyAnalysis(msg *Message) {
	subject := stringValue(msg.Subject)
	analysis := classifier.AnalyzeCommonScam(subject, msg.BodyText)
	reason := stringValue(msg.mailLogReason)
	switch msg.Verdict {
	case "not_spam":
		msg.EmailType = "User confirmed clean"
	case "spam":
		msg.EmailType = "User reported spam"
	case "phishing":
		msg.EmailType = "User reported phishing"
	case "malware":
		msg.EmailType = "User reported malware"
	default:
		msg.EmailType = mailboxEmailType(reason)
	}
	msg.ScamWarning = analysis.Warning
	msg.ScamSignals = analysis.Signals
	msg.ScamLinks = make([]Link, 0, len(analysis.Links))
	for _, link := range analysis.Links {
		msg.ScamLinks = append(msg.ScamLinks, Link{Label: link.Label, URL: link.URL})
	}
	spoof := spoofing.Analyze(reason, msg.mailLogSymbols)
	msg.AuthStatus = spoof.Status
	msg.SpoofWarning = spoof.Warning
	msg.SpoofSignals = spoof.Signals
	msg.Unsubscribe = parseUnsubscribeInfo(stringValue(msg.listUnsubscribe), stringValue(msg.listUnsubscribePost))
}

func mailboxEmailType(reason string) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.Contains(reason, "phishing signal"):
		return "Possible phishing"
	case strings.Contains(reason, "phishing"):
		return "Likely phishing"
	case strings.Contains(reason, "malware") || strings.Contains(reason, "virus"):
		return "Likely malware"
	case strings.Contains(reason, "blacklist") || strings.Contains(reason, "blocklist"):
		return "Blocked sender"
	case strings.Contains(reason, "authentication"):
		return "Sender authentication issue"
	case strings.Contains(reason, "quarantine_threshold"):
		return "Likely spam"
	case strings.Contains(reason, "spam_threshold"):
		return "Possible spam"
	default:
		return "Clean or wanted mail"
	}
}

func parseUnsubscribeInfo(header, post string) *UnsubscribeInfo {
	options := make([]UnsubscribeOption, 0, 2)
	seen := map[string]bool{}
	for _, candidate := range listUnsubscribeCandidates(header) {
		option, ok := sanitizeUnsubscribeTarget(candidate)
		if !ok || seen[option.URL] {
			continue
		}
		seen[option.URL] = true
		options = append(options, option)
		if len(options) >= 3 {
			break
		}
	}
	if len(options) == 0 {
		return nil
	}
	return &UnsubscribeInfo{
		Available: true,
		OneClick:  strings.Contains(strings.ToLower(post), "list-unsubscribe=one-click"),
		Options:   options,
	}
}

func findUnsubscribeOption(options []UnsubscribeOption, reqType, reqURL string) (UnsubscribeOption, bool) {
	reqType = strings.ToLower(strings.TrimSpace(reqType))
	reqURL = strings.TrimSpace(reqURL)
	if reqType == "" || reqURL == "" {
		return UnsubscribeOption{}, false
	}
	for _, option := range options {
		if option.Type == reqType && option.URL == reqURL {
			return option, true
		}
	}
	return UnsubscribeOption{}, false
}

func (h *Handler) sendMailtoUnsubscribe(ctx context.Context, msg Message, option UnsubscribeOption) (unsubscribeResp, error) {
	to, subject, body, err := parseMailtoUnsubscribe(option.URL, msg.ToAddr)
	if err != nil {
		return unsubscribeResp{}, err
	}
	host := quarantine.LookupSystemSetting(ctx, h.DB, "mail.outbound_relay_host", "")
	port := quarantine.LookupSystemSetting(ctx, h.DB, "mail.outbound_relay_port", "25")
	if strings.TrimSpace(host) == "" {
		return unsubscribeResp{}, fmt.Errorf("no outbound relay configured")
	}
	from := (&stdmail.Address{Address: strings.ToLower(strings.TrimSpace(msg.ToAddr))}).String()
	raw := strings.Join([]string{
		"From: " + from,
		"To: " + formatAddressList(to),
		"Subject: " + sanitizeHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	relayPort, _ := strconv.Atoi(strings.TrimSpace(port))
	err = sentemails.Send(ctx, h.DB, sentemails.Record{
		OrganizationID: msg.OrganizationID,
		DomainID:       msg.DomainID,
		MailLogID:      &msg.MailLogID,
		Kind:           "mailing_list_unsubscribe",
		FromAddr:       msg.ToAddr,
		ToAddrs:        addressStrings(to),
		Subject:        subject,
		RelayHost:      host,
		RelayPort:      relayPort,
		Raw:            []byte(raw),
		Metadata:       map[string]any{"mailbox_message_id": msg.ID.String(), "unsubscribe_type": "mailto"},
	}, func() error {
		return quarantine.SendRelayMail(host, port, msg.ToAddr, addressStrings(to), []byte(raw))
	})
	if err != nil {
		return unsubscribeResp{}, err
	}
	return unsubscribeResp{
		Message: "Unsubscribe email sent.",
		Type:    "mailto",
		Sent:    true,
		SentTo:  addressStrings(to),
	}, nil
}

func parseMailtoUnsubscribe(raw, subscriber string) ([]*stdmail.Address, string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || strings.ToLower(parsed.Scheme) != "mailto" {
		return nil, "", "", fmt.Errorf("unsubscribe email target is invalid")
	}
	addressPart := parsed.Opaque
	if addressPart == "" {
		addressPart = parsed.Path
	}
	addressPart = strings.SplitN(addressPart, "?", 2)[0]
	addressPart, err = url.PathUnescape(addressPart)
	if err != nil {
		return nil, "", "", fmt.Errorf("unsubscribe email target is invalid")
	}
	to, err := stdmail.ParseAddressList(addressPart)
	if err != nil || len(to) == 0 || len(to) > 5 {
		return nil, "", "", fmt.Errorf("unsubscribe email target is invalid")
	}
	q := parsed.Query()
	subject := sanitizeHeader(q.Get("subject"))
	if subject == "" {
		subject = "unsubscribe"
	}
	body := cleanUnsubscribeBody(q.Get("body"))
	if body == "" {
		body = "Please unsubscribe " + strings.ToLower(strings.TrimSpace(subscriber)) + " from this mailing list."
	}
	return to, subject, body, nil
}

func cleanUnsubscribeBody(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 4096 {
		value = value[:4096]
	}
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func formatAddressList(addresses []*stdmail.Address) string {
	parts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		parts = append(parts, address.String())
	}
	return strings.Join(parts, ", ")
}

func addressStrings(addresses []*stdmail.Address) []string {
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, strings.ToLower(strings.TrimSpace(address.Address)))
	}
	return out
}

func postOneClickUnsubscribe(ctx context.Context, option UnsubscribeOption) (unsubscribeResp, error) {
	if option.Type != "url" {
		return unsubscribeResp{}, fmt.Errorf("unsubscribe URL is invalid")
	}
	target, err := url.Parse(option.URL)
	if err != nil || !safeUnsubscribeURL(target) {
		return unsubscribeResp{}, fmt.Errorf("unsubscribe URL is invalid")
	}
	body := bytes.NewBufferString("List-Unsubscribe=One-Click")
	// The target URL is selected only from the message's already-sanitized
	// List-Unsubscribe header options and is fetched with a transport that
	// rejects private, loopback, link-local, and otherwise non-global IPs.
	// nosemgrep: go.lang.security.audit.net.http.request-tainted-url.request-tainted-url
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), body)
	if err != nil {
		return unsubscribeResp{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "SentinelMail-Gateway/1.0")
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     unsubscribeHTTPTransport(),
		CheckRedirect: validateUnsubscribeRedirect,
	}
	resp, err := client.Do(req)
	if err != nil {
		return unsubscribeResp{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return unsubscribeResp{}, fmt.Errorf("unsubscribe endpoint returned HTTP %d", resp.StatusCode)
	}
	return unsubscribeResp{
		Message: "One-click unsubscribe request sent.",
		Type:    "url",
		Status:  resp.StatusCode,
		URL:     target.String(),
	}, nil
}

func unsubscribeHTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("unsubscribe host did not resolve")
			}
			for _, ip := range ips {
				if !safeOutboundIP(ip.IP) {
					return nil, fmt.Errorf("unsubscribe host resolved to a non-public address")
				}
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
}

func validateUnsubscribeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("too many unsubscribe redirects")
	}
	if !safeUnsubscribeURL(req.URL) {
		return fmt.Errorf("unsafe unsubscribe redirect")
	}
	return nil
}

func safeUnsubscribeURL(parsed *url.URL) bool {
	if parsed == nil || strings.ToLower(parsed.Scheme) != "https" || parsed.User != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	return safeExternalHost(host)
}

func safeOutboundIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

func listUnsubscribeCandidates(header string) []string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	out := []string{}
	remaining := header
	for {
		start := strings.Index(remaining, "<")
		if start < 0 {
			break
		}
		end := strings.Index(remaining[start+1:], ">")
		if end < 0 {
			break
		}
		value := strings.TrimSpace(remaining[start+1 : start+1+end])
		if value != "" {
			out = append(out, value)
		}
		remaining = remaining[start+1+end+1:]
	}
	if len(out) > 0 {
		return out
	}
	for _, part := range strings.Split(header, ",") {
		value := strings.TrimSpace(strings.Trim(part, "<>"))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func sanitizeUnsubscribeTarget(raw string) (UnsubscribeOption, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, "<>"))
	if raw == "" || len(raw) > 2048 || containsControl(raw) {
		return UnsubscribeOption{}, false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return UnsubscribeOption{}, false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.User != nil {
			return UnsubscribeOption{}, false
		}
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if !safeExternalHost(host) {
			return UnsubscribeOption{}, false
		}
		parsed.Fragment = ""
		return UnsubscribeOption{
			Type:  "url",
			Label: "Open unsubscribe page",
			URL:   parsed.String(),
		}, true
	case "mailto":
		if containsEncodedNewline(raw) {
			return UnsubscribeOption{}, false
		}
		if !validMailto(parsed) {
			return UnsubscribeOption{}, false
		}
		return UnsubscribeOption{
			Type:  "mailto",
			Label: "Email unsubscribe request",
			URL:   raw,
		}, true
	default:
		return UnsubscribeOption{}, false
	}
}

func validMailto(parsed *url.URL) bool {
	address := parsed.Opaque
	if address == "" {
		address = parsed.Path
	}
	address = strings.SplitN(address, "?", 2)[0]
	address, err := url.PathUnescape(address)
	if err != nil || strings.TrimSpace(address) == "" {
		return false
	}
	_, err = stdmail.ParseAddress(address)
	return err == nil
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func safeExternalHost(host string) bool {
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if strings.ContainsAny(host, " \t\r\n") || !strings.Contains(host, ".") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsGlobalUnicast() &&
			!addr.IsPrivate() &&
			!addr.IsLoopback() &&
			!addr.IsLinkLocalUnicast() &&
			!addr.IsLinkLocalMulticast() &&
			!addr.IsUnspecified()
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func containsEncodedNewline(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "%0a") || strings.Contains(value, "%0d")
}
