// Package mail handles the boundary between the SMTP/Rspamd plane and the
// Go control plane: ingest of post-scan mail events, policy application, and
// quarantine/log persistence.
package mail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/notifications"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
)

// Event is the payload Rspamd (via a small Lua snippet) POSTs after scanning.
// Shape kept tight on purpose — anything richer goes in symbols.
type Event struct {
	Direction  string         `json:"direction"` // inbound | outbound
	QueueID    string         `json:"queue_id,omitempty"`
	MessageID  string         `json:"message_id,omitempty"`
	From       string         `json:"from"`
	FromName   string         `json:"from_display_name,omitempty"`
	ReplyTo    string         `json:"reply_to,omitempty"`
	To         []string       `json:"to"`
	ClientIP   string         `json:"client_ip,omitempty"`
	Helo       string         `json:"helo,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	SizeBytes  int            `json:"size_bytes,omitempty"`
	Score      float64        `json:"score"`
	Action     string         `json:"action,omitempty"` // rspamd action: no action, add header, greylist, soft reject, reject
	Symbols    map[string]any `json:"symbols,omitempty"`
	StorageKey string         `json:"storage_key,omitempty"` // worker-supplied path for the .eml blob

	// MVP 2 — fields that drive auto-triggered scans. All optional.
	BodyText            string       `json:"body_text,omitempty"`
	RawMessageB64       string       `json:"raw_message_b64,omitempty"`
	ListUnsubscribe     string       `json:"list_unsubscribe,omitempty"`
	ListUnsubscribePost string       `json:"list_unsubscribe_post,omitempty"`
	URLs                []string     `json:"urls,omitempty"`
	Attachments         []Attachment `json:"attachments,omitempty"`
}

// Attachment is a single MIME part rspamd considers interesting (image, pdf,
// office doc, archive). For MVP 2 only `image/*` parts are used (QR scan).
type Attachment struct {
	ContentType string `json:"content_type"`
	Filename    string `json:"filename,omitempty"`
	DataB64     string `json:"data_b64"`
	SizeBytes   int    `json:"size_bytes,omitempty"`
}

// IngestHandler accepts POST /api/v1/mail/events from rspamd.
// Authentication: shared HMAC. Rspamd computes hex(hmac-sha256(secret, body))
// and sends it as X-SMG-Signature. NO session cookie (rspamd has none).
type IngestHandler struct {
	DB     *pgxpool.Pool
	Redis  *redis.Client // for MVP 2 scan auto-trigger; nil disables it
	Secret []byte        // shared with rspamd via SMG_INGEST_HMAC_KEY
}

func MountIngest(r chi.Router, db *pgxpool.Pool, rdb *redis.Client, secret []byte) {
	h := &IngestHandler{DB: db, Redis: rdb, Secret: secret}
	r.Post("/events", h.handle)
	r.Post("/sender-policy", h.senderPolicy)
}

func (h *IngestHandler) handle(w http.ResponseWriter, r *http.Request) {
	// 16 MiB — Lua sends body + URLs + up to 5×2 MiB image attachments.
	body, err := readSignedBody(w, r, h.Secret, 16<<20)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(ev.To) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "to required")
		return
	}
	if ev.Direction == "" {
		ev.Direction = "inbound"
	}

	// Map the first recipient's domain to an organization.
	domainID, orgID, err := lookupDomainOrg(r.Context(), h.DB, primaryDomain(ev.To[0]))
	if err != nil {
		httpx.WriteError(w, http.StatusAccepted, "unknown recipient domain (logged-only)")
		return
	}

	pol, err := policies.Resolve(r.Context(), h.DB, domainID, orgID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "policy resolve: "+err.Error())
		return
	}

	disposition, reason := decide(pol, &ev)
	disposition, reason = applyAuthEnforcement(disposition, reason, &ev)
	senderAction := ""
	disposition, reason, senderAction, err = h.applySenderListDecision(r.Context(), disposition, reason, pol, orgID, domainID, &ev)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sender policy lookup: "+err.Error())
		return
	}
	disposition, reason = applyRspamdSenderBlocklist(disposition, reason, &ev)
	disposition, reason = applyReputationBlocklist(disposition, reason, &ev)
	disposition, reason = applyCommonScamDetectionWithPolicy(disposition, reason, pol, &ev)
	disposition, reason = applyBrandImpersonationDetection(disposition, reason, senderAction, pol, &ev)
	disposition, reason = applyThreatSignalDispositionWithPolicy(disposition, reason, pol, &ev)
	disposition, reason = applySenderListAction(disposition, reason, senderAction, pol.SenderBlacklistEnabled())
	disposition, reason = applyChallengeResponseHold(disposition, reason, pol, senderAction, &ev)
	if orgID != nil {
		if learned, err := classifier.Lookup(r.Context(), h.DB, *orgID, ev.To[0], ev.From, ev.Subject); err == nil && learned != nil {
			disposition, reason = applyLearnedClassification(disposition, reason, learned)
		}
	}
	disposition, reason = applySenderListAction(disposition, reason, senderAction, pol.SenderBlacklistEnabled())
	disposition, reason = applyQuarantineFirst(disposition, reason, &ev)

	// Persist mail log.
	symbolsJSON := []byte("{}")
	if len(ev.Symbols) > 0 {
		symbolsJSON, _ = json.Marshal(ev.Symbols)
	}
	var mailLogID uuid.UUID
	err = h.DB.QueryRow(r.Context(), `
		INSERT INTO mail_logs (organization_id, domain_id, queue_id, message_id, direction,
		                       from_addr, to_addrs, client_ip, helo, subject, size_bytes,
		                       rspamd_score, rspamd_action, symbols, disposition, reason, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,'')::inet, $9, $10, $11,
		        $12, $13, $14::jsonb, $15::mail_disposition, $16, now())
		RETURNING id
	`, orgID, domainID, ev.QueueID, ev.MessageID, ev.Direction,
		ev.From, ev.To, ev.ClientIP, ev.Helo, ev.Subject, ev.SizeBytes,
		ev.Score, ev.Action, symbolsJSON, disposition, reason).Scan(&mailLogID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "log insert: "+err.Error())
		return
	}
	if err := h.insertMailboxCopies(r.Context(), orgID, domainID, mailLogID, disposition, &ev); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mailbox insert: "+err.Error())
		return
	}
	if err := h.insertMailLogBlob(r.Context(), orgID, mailLogID, &ev); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail log blob insert: "+err.Error())
		return
	}

	// Quarantine if needed.
	if disposition == "quarantined" {
		var quarantineID uuid.UUID
		threatClass := classifyThreat(&ev)
		if challenge.IsPendingReason(reason) {
			threatClass = "CHALLENGE_RESPONSE"
		}
		retentionDays := settings.QuarantineRetentionDays(r.Context(), h.DB, *orgID)
		err = h.DB.QueryRow(r.Context(), `
			INSERT INTO quarantine_entries
			  (organization_id, mail_log_id, domain_id, from_addr, to_addr, subject,
			   rspamd_score, threat_class, storage_key, size_bytes, expires_at, received_at)
			VALUES ($1, $2, $3, NULLIF($4,''), $5, NULLIF($6,''),
			        $7, $8, $9, NULLIF($10,0), now() + ($11::int * interval '1 day'), now())
			RETURNING id
		`, orgID, mailLogID, domainID, ev.From, ev.To[0], ev.Subject,
			ev.Score, threatClass, storageKey(&ev), ev.SizeBytes, retentionDays).Scan(&quarantineID)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "quarantine insert: "+err.Error())
			return
		}
		if err := h.insertQuarantineBlob(r.Context(), orgID, mailLogID, quarantineID, &ev); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "quarantine blob insert: "+err.Error())
			return
		}
		if threatClass == "PHISHING" {
			go func(id uuid.UUID) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = notifications.SendPhishingAlertForMailLog(ctx, h.DB, id)
			}(mailLogID)
		} else if threatClass == "CHALLENGE_RESPONSE" {
			go func(id uuid.UUID) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = notifications.SendChallengeResponseAlertForMailLog(ctx, h.DB, id)
			}(mailLogID)
		}
	}

	// MVP 2 — auto-spawn scans based on what rspamd extracted. Best-effort;
	// errors here are logged via the response field but never fail the
	// ingest call (mail flow must not depend on scan availability).
	spawned, scanErr := h.spawnScans(r.Context(), orgID, mailLogID, &ev)
	scanErrStr := ""
	if scanErr != nil {
		scanErrStr = scanErr.Error()
	}

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"mail_log_id":   mailLogID,
		"disposition":   disposition,
		"scans_spawned": spawned,
		"scan_error":    scanErrStr,
		"policy":        pol.Name,
	})
}

func readSignedBody(w http.ResponseWriter, r *http.Request, secret []byte, limit int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}
	h := &IngestHandler{Secret: secret}
	if !h.verifySig(body, r.Header.Get("X-SMG-Signature")) {
		return nil, errors.New("bad signature")
	}
	return body, nil
}

func (h *IngestHandler) insertMailboxCopies(ctx context.Context, orgID, domainID *uuid.UUID, mailLogID uuid.UUID, disposition string, ev *Event) error {
	if orgID == nil || domainID == nil {
		return nil
	}
	if !shouldCreateMailboxCopy(disposition) {
		return nil
	}
	body := ev.BodyText
	if len(body) > maxBodyForAI {
		body = body[:maxBodyForAI]
	}
	for _, to := range ev.To {
		to = strings.ToLower(strings.TrimSpace(to))
		if to == "" {
			continue
		}
		_, err := h.DB.Exec(ctx, `
			INSERT INTO mailbox_messages
			  (organization_id, domain_id, mail_log_id, from_addr, to_addr, subject, body_text,
			   list_unsubscribe, list_unsubscribe_post, received_at)
			VALUES ($1, $2, $3, NULLIF($4,''), $5, NULLIF($6,''), $7, NULLIF($8,''), NULLIF($9,''), now())
			ON CONFLICT (mail_log_id, to_addr) DO NOTHING
		`, orgID, domainID, mailLogID, ev.From, to, ev.Subject, body, ev.ListUnsubscribe, ev.ListUnsubscribePost)
		if err != nil {
			return err
		}
	}
	return nil
}

func shouldCreateMailboxCopy(disposition string) bool {
	return disposition == "delivered" || disposition == "tagged"
}

func (h *IngestHandler) insertQuarantineBlob(ctx context.Context, orgID *uuid.UUID, mailLogID, quarantineID uuid.UUID, ev *Event) error {
	if orgID == nil || ev.RawMessageB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(ev.RawMessageB64)
	if err != nil {
		return nil
	}
	if len(raw) == 0 || len(raw) > maxRawMessageBytes {
		return nil
	}
	_, err = h.DB.Exec(ctx, `
		INSERT INTO quarantine_blobs (quarantine_entry_id, organization_id, mail_log_id, message_bytes)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (quarantine_entry_id) DO NOTHING
	`, quarantineID, orgID, mailLogID, raw)
	return err
}

func (h *IngestHandler) insertMailLogBlob(ctx context.Context, orgID *uuid.UUID, mailLogID uuid.UUID, ev *Event) error {
	if orgID == nil || ev.RawMessageB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(ev.RawMessageB64)
	if err != nil {
		return nil
	}
	if len(raw) == 0 || len(raw) > maxRawMessageBytes {
		return nil
	}
	_, err = h.DB.Exec(ctx, `
		INSERT INTO mail_log_blobs (mail_log_id, organization_id, message_bytes)
		VALUES ($1, $2, $3)
		ON CONFLICT (mail_log_id) DO NOTHING
	`, mailLogID, orgID, raw)
	return err
}

// Redis queue names — kept in sync with internal/scan.queueFor().
const (
	scanQueueLight   = "smg:scan_jobs"
	scanQueueSandbox = "smg:scan_jobs_sandbox"
)

// Caps on auto-spawn so a pathological email can't enqueue 100 scans.
const (
	maxAttachmentSize  = 2 << 20 // 2 MiB per image
	maxAttachmentScans = 5
	maxURLScans        = 1       // sandbox is heavy; only the first URL
	maxBodyForAI       = 16_000  // chars
	maxRawMessageBytes = 8 << 20 // 8 MiB raw .eml, base64-encoded in JSON
)

// spawnScans enqueues async scans based on what rspamd surfaced. Returns the
// kinds spawned and the first error encountered. Mail flow MUST NOT depend on
// the scan layer — every error here is best-effort logged via the response.
func (h *IngestHandler) spawnScans(ctx context.Context, orgID *uuid.UUID, mailLogID uuid.UUID, ev *Event) ([]string, error) {
	if h.Redis == nil || orgID == nil {
		return nil, nil
	}
	spawned := []string{}
	var firstErr error

	// AI scoring for any inbound message that has something to read.
	if ev.Direction == "inbound" && (ev.Subject != "" || ev.BodyText != "") {
		body := ev.BodyText
		if len(body) > maxBodyForAI {
			body = body[:maxBodyForAI]
		}
		payload := map[string]any{
			"subject":           ev.Subject,
			"body_text":         body,
			"from_addr":         ev.From,
			"from_display_name": ev.FromName,
		}
		if err := h.enqueue(ctx, *orgID, &mailLogID, "ai", payload); err != nil && firstErr == nil {
			firstErr = err
		} else {
			spawned = append(spawned, "ai")
		}
	}

	// QR scan per image attachment (capped).
	imageCount := 0
	for _, att := range ev.Attachments {
		if imageCount >= maxAttachmentScans {
			break
		}
		if !strings.HasPrefix(strings.ToLower(att.ContentType), "image/") {
			continue
		}
		if att.SizeBytes > maxAttachmentSize {
			continue
		}
		payload := map[string]any{
			"image_b64": att.DataB64,
			"filename":  att.Filename,
		}
		if err := h.enqueue(ctx, *orgID, &mailLogID, "qr", payload); err != nil && firstErr == nil {
			firstErr = err
		} else {
			spawned = append(spawned, "qr")
		}
		imageCount++
	}

	// Sandbox the first URL (heavy; one per message keeps Chromium pool sane).
	for i, url := range ev.URLs {
		if i >= maxURLScans {
			break
		}
		if !isHTTPURL(url) {
			continue
		}
		if err := h.enqueue(ctx, *orgID, &mailLogID, "sandbox", map[string]any{"url": url}); err != nil && firstErr == nil {
			firstErr = err
		} else {
			spawned = append(spawned, "sandbox")
		}
	}

	// Outbound compromise check on outgoing mail.
	if ev.Direction == "outbound" {
		payload := map[string]any{
			"from_addr": ev.From,
			"to_addrs":  ev.To,
			"subject":   ev.Subject,
			"client_ip": ev.ClientIP,
		}
		if err := h.enqueue(ctx, *orgID, &mailLogID, "outbound", payload); err != nil && firstErr == nil {
			firstErr = err
		} else {
			spawned = append(spawned, "outbound")
		}
	}

	return spawned, firstErr
}

func (h *IngestHandler) enqueue(ctx context.Context, orgID uuid.UUID, mailLogID *uuid.UUID, kind string, payload map[string]any) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var scanID uuid.UUID
	err = h.DB.QueryRow(ctx, `
		INSERT INTO scan_jobs (organization_id, mail_log_id, kind, payload)
		VALUES ($1, $2, $3::scan_kind, $4::jsonb)
		RETURNING id
	`, orgID, mailLogID, kind, string(payloadJSON)).Scan(&scanID)
	if err != nil {
		return err
	}
	envelope, _ := json.Marshal(map[string]any{
		"scan_id":         scanID,
		"organization_id": orgID,
		"kind":            kind,
	})
	queue := scanQueueLight
	if kind == "sandbox" {
		queue = scanQueueSandbox
	}
	return h.Redis.RPush(ctx, queue, envelope).Err()
}

func isHTTPURL(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

// decide applies the resolved policy. Returns (mail_disposition, reason).
func decide(p *policies.Policy, ev *Event) (string, string) {
	if p == nil {
		return "delivered", ""
	}
	switch {
	case ev.Score >= p.RejectThreshold:
		return dispositionForPolicyAction(p.QuarantineAction), "score >= reject_threshold"
	case ev.Score >= p.QuarantineThreshold:
		return dispositionForPolicyAction(p.QuarantineAction), "score >= quarantine_threshold"
	case ev.Score >= p.SpamThreshold:
		return "tagged", "score >= spam_threshold"
	default:
		return "delivered", ""
	}
}

func dispositionForPolicyAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "deliver":
		return "delivered"
	case "tag":
		return "tagged"
	case "reject":
		return "rejected"
	default:
		return "quarantined"
	}
}

func hasSymbol(ev *Event, name string) bool {
	if ev == nil {
		return false
	}
	for key := range ev.Symbols {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func hasAnySymbol(ev *Event, names ...string) bool {
	for _, name := range names {
		if hasSymbol(ev, name) {
			return true
		}
	}
	return false
}

func applyLearnedClassification(disposition, reason string, learned *classifier.Match) (string, string) {
	switch learned.Verdict {
	case "not_spam":
		if isHardGateReason(reason) {
			return disposition, reason
		}
		if disposition == "quarantined" || disposition == "tagged" {
			return "delivered", "user classified similar mail as not spam"
		}
	case "spam":
		if disposition == "delivered" || disposition == "tagged" {
			return "quarantined", "user classified similar mail as spam"
		}
	case "phishing", "malware":
		if disposition == "delivered" || disposition == "tagged" || disposition == "quarantined" {
			return "quarantined", "user classified similar mail as " + learned.Verdict
		}
	}
	return disposition, reason
}

func isHardGateReason(reason string) bool {
	if strings.HasPrefix(reason, "sender authentication") ||
		strings.HasPrefix(reason, "sender failed DMARC") ||
		strings.HasPrefix(reason, "sender failed SPF/DKIM") ||
		strings.HasPrefix(reason, "malware signal hit") {
		return true
	}
	switch reason {
	case "sender authentication results missing",
		"sender matched blacklist",
		"reputation blocklist hit",
		challenge.ReasonPendingApproval:
		return true
	default:
		return false
	}
}

func (h *IngestHandler) applySenderListDecision(ctx context.Context, disposition, reason string, pol *policies.Policy, orgID *uuid.UUID, domainID *uuid.UUID, ev *Event) (string, string, string, error) {
	if pol == nil || orgID == nil || ev == nil || len(ev.To) == 0 {
		return disposition, reason, "", nil
	}
	action, _, err := h.lookupSenderList(ctx, *orgID, domainID, strings.ToLower(strings.TrimSpace(ev.To[0])), ev.From, ev.ReplyTo)
	if err != nil {
		return disposition, reason, "", err
	}
	nextDisposition, nextReason := applySenderListAction(disposition, reason, action, pol.SenderBlacklistEnabled())
	return nextDisposition, nextReason, action, nil
}

func applySenderListAction(disposition, reason, action string, blacklistEnabled bool) (string, string) {
	if action == "block" && blacklistEnabled {
		return "rejected", "sender matched blacklist"
	}
	if action == "allow" && !isAllowlistOverrideBlockedReason(reason) && (disposition == "tagged" || disposition == "quarantined") {
		return "delivered", "sender matched allowlist"
	}
	return disposition, reason
}

func isAllowlistOverrideBlockedReason(reason string) bool {
	if strings.HasPrefix(reason, "sender authentication") ||
		strings.HasPrefix(reason, "sender failed DMARC") ||
		strings.HasPrefix(reason, "sender failed SPF/DKIM") ||
		strings.HasPrefix(reason, "malware signal hit") {
		return true
	}
	switch reason {
	case "sender authentication results missing",
		"sender matched blacklist",
		challenge.ReasonPendingApproval:
		return true
	default:
		return false
	}
}

func applyRspamdSenderBlocklist(disposition, reason string, ev *Event) (string, string) {
	if hasSymbol(ev, "SMG_SENDER_BLACKLIST") {
		return "rejected", "sender matched blacklist"
	}
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	return disposition, reason
}

func applyReputationBlocklist(disposition, reason string, ev *Event) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	if hasReputationBlocklistHit(ev) {
		return "quarantined", "reputation blocklist hit"
	}
	return disposition, reason
}

func applyAuthEnforcement(disposition, reason string, ev *Event) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	if ev != nil && strings.EqualFold(ev.Direction, "outbound") {
		return disposition, reason
	}
	if !hasAuthSignal(ev) {
		return "quarantined", "sender authentication results missing"
	}
	if hasSymbol(ev, "DMARC_POLICY_REJECT") {
		return "quarantined", "sender failed DMARC reject policy"
	}
	if hasSymbol(ev, "DMARC_POLICY_QUARANTINE") {
		return "quarantined", "sender failed DMARC quarantine policy"
	}
	auth := authSignals(ev)
	if auth.DMARCPass || auth.SPFPass || auth.DKIMPass {
		return disposition, reason
	}
	if auth.SPFFail || auth.DKIMFail || auth.DMARCFail || hasSymbol(ev, "R_SPF_SOFTFAIL") {
		return "quarantined", "sender failed SPF/DKIM/DMARC authentication"
	}
	return "quarantined", "sender authentication results missing"
}

func applyCommonScamDetection(disposition, reason string, ev *Event) (string, string) {
	return applyCommonScamDetectionWithPolicy(disposition, reason, nil, ev)
}

func applyCommonScamDetectionWithPolicy(disposition, reason string, pol *policies.Policy, ev *Event) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	analysis := classifier.AnalyzeCommonScam(ev.Subject, ev.BodyText)
	if !commonScamDetectionAllows(pol, analysis.EmailType) {
		return disposition, reason
	}
	switch analysis.EmailType {
	case "Credential phishing":
		if isAuthenticatedProtectedBrandSender(ev) {
			return disposition, reason
		}
		return "quarantined", "detected " + strings.ToLower(analysis.EmailType)
	case "Payment support scam", "Tax document phishing", "Medical miracle scam", "Malware lure", "Health miracle spam", "Home services lead-gen spam":
		return "quarantined", "detected " + strings.ToLower(analysis.EmailType)
	default:
		return disposition, reason
	}
}

func applyBrandImpersonationDetection(disposition, reason, senderAction string, pol *policies.Policy, ev *Event) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	if pol != nil && !pol.BrandImpersonationEnabled() {
		return disposition, reason
	}
	if senderAction == "allow" {
		return disposition, reason
	}
	if ev != nil && strings.EqualFold(ev.Direction, "outbound") {
		return disposition, reason
	}
	analysis := analyzeBrandImpersonation(ev, brandAnalysisOptionsFromPolicy(pol))
	if analysis.Quarantine {
		return "quarantined", analysis.Reason()
	}
	return disposition, reason
}

func applyThreatSignalDisposition(disposition, reason string, ev *Event) (string, string) {
	return applyThreatSignalDispositionWithOptions(disposition, reason, ev, defaultBrandAnalysisOptions())
}

func applyThreatSignalDispositionWithPolicy(disposition, reason string, pol *policies.Policy, ev *Event) (string, string) {
	return applyThreatSignalDispositionWithOptionsAndPolicy(disposition, reason, ev, brandAnalysisOptionsFromPolicy(pol), pol)
}

func applyThreatSignalDispositionWithOptions(disposition, reason string, ev *Event, opts brandAnalysisOptions) (string, string) {
	return applyThreatSignalDispositionWithOptionsAndPolicy(disposition, reason, ev, opts, nil)
}

func applyThreatSignalDispositionWithOptionsAndPolicy(disposition, reason string, ev *Event, opts brandAnalysisOptions, pol *policies.Policy) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	switch threat := classifyThreatWithOptions(ev, opts, pol); threat {
	case "PHISHING":
		if disposition == "delivered" {
			return "tagged", "phishing signal hit"
		}
		return disposition, firstNonEmpty(reason, "phishing signal hit")
	case "VIRUS", "MALWARE":
		return "quarantined", "malware signal hit"
	default:
		return disposition, reason
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func applyChallengeResponseHold(disposition, reason string, pol *policies.Policy, senderAction string, ev *Event) (string, string) {
	if disposition == "rejected" || disposition == "quarantined" || pol == nil || !pol.ChallengeResponseEnabled() {
		return disposition, reason
	}
	if ev == nil || !strings.EqualFold(ev.Direction, "inbound") {
		return disposition, reason
	}
	if senderAction == "allow" {
		return disposition, reason
	}
	return "quarantined", challenge.ReasonPendingApproval
}

func authSignals(ev *Event) classifier.AuthSignals {
	return classifier.AuthSignals{
		SPFPass:   hasSymbolContaining(ev, "SPF", "ALLOW", "PASS"),
		DKIMPass:  hasSymbolContaining(ev, "DKIM", "ALLOW", "PASS"),
		DMARCPass: hasSymbolContaining(ev, "DMARC", "ALLOW", "PASS"),
		SPFFail:   hasAnySymbol(ev, "R_SPF_FAIL", "R_SPF_PERMFAIL"),
		DKIMFail:  hasSymbolContaining(ev, "DKIM", "FAIL", "REJECT"),
		DMARCFail: hasAnySymbol(ev, "DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE"),
	}
}

func applyQuarantineFirst(disposition, reason string, ev *Event) (string, string) {
	if disposition != "rejected" {
		return disposition, reason
	}
	if reason == "sender matched blacklist" {
		return disposition, reason
	}
	if ev == nil || strings.EqualFold(ev.Direction, "inbound") || ev.Direction == "" {
		return "quarantined", reason
	}
	return disposition, reason
}

func hasSymbolContaining(ev *Event, required string, alternatives ...string) bool {
	if ev == nil {
		return false
	}
	required = strings.ToUpper(required)
	for key := range ev.Symbols {
		upper := strings.ToUpper(key)
		if !strings.Contains(upper, required) {
			continue
		}
		for _, alt := range alternatives {
			if strings.Contains(upper, strings.ToUpper(alt)) {
				return true
			}
		}
	}
	return false
}

func hasAuthSignal(ev *Event) bool {
	if ev == nil {
		return false
	}
	for key := range ev.Symbols {
		upper := strings.ToUpper(key)
		if strings.Contains(upper, "SPF") || strings.Contains(upper, "DKIM") || strings.Contains(upper, "DMARC") {
			return true
		}
	}
	return false
}

func hasReputationBlocklistHit(ev *Event) bool {
	if ev == nil {
		return false
	}
	if hasReputationAllowlistHit(ev) {
		return false
	}
	for key, value := range ev.Symbols {
		s := strings.ToUpper(key)
		if isReputationBlockSymbol(s) && symbolScore(value) > 0 {
			return true
		}
	}
	return false
}

func hasReputationAllowlistHit(ev *Event) bool {
	if ev == nil {
		return false
	}
	for key := range ev.Symbols {
		if isReputationAllowSymbol(strings.ToUpper(key)) {
			return true
		}
	}
	return false
}

func isReputationAllowSymbol(symbol string) bool {
	switch {
	case strings.Contains(symbol, "WHITELIST"),
		strings.Contains(symbol, "MAILCOW_WHITE"),
		strings.Contains(symbol, "DNSWL"),
		strings.Contains(symbol, "RWL_"),
		strings.Contains(symbol, "ALLOWLIST"),
		strings.Contains(symbol, "MAILSPIKE_GOOD"),
		strings.Contains(symbol, "MAILSPIKE_NEUTRAL"),
		strings.Contains(symbol, "MAILSPIKE_POSSIBLE"):
		return true
	default:
		return false
	}
}

func isReputationBlockSymbol(symbol string) bool {
	if isReputationLookupFailureSymbol(symbol) {
		return false
	}
	switch {
	case strings.Contains(symbol, "SPAMHAUS"),
		strings.Contains(symbol, "SPAMCOP"),
		strings.Contains(symbol, "SURBL"),
		strings.Contains(symbol, "URIBL"),
		strings.Contains(symbol, "URLHAUS"),
		strings.Contains(symbol, "RSPAMD_EMAILBL"),
		strings.Contains(symbol, "DBL_"),
		strings.Contains(symbol, "SCBL"),
		strings.Contains(symbol, "MSBL"),
		strings.Contains(symbol, "BLACKLIST"),
		strings.Contains(symbol, "BLOCKLIST"),
		strings.Contains(symbol, "RBL_"),
		strings.Contains(symbol, "SEM_URIBL"),
		strings.Contains(symbol, "VIRUSFREE"),
		strings.Contains(symbol, "BOTNET"),
		strings.Contains(symbol, "OPENPHISH"):
		return true
	default:
		return false
	}
}

func isReputationLookupFailureSymbol(symbol string) bool {
	switch {
	case strings.HasSuffix(symbol, "_BLOCKED"),
		strings.Contains(symbol, "_DNSFAIL"),
		strings.Contains(symbol, "DNS_ERROR"),
		strings.Contains(symbol, "TIMEOUT"):
		return true
	default:
		return false
	}
}

func symbolScore(value any) float64 {
	obj, ok := value.(map[string]any)
	if !ok {
		return 0
	}
	switch score := obj["score"].(type) {
	case float64:
		return score
	case float32:
		return float64(score)
	case int:
		return float64(score)
	case json.Number:
		parsed, _ := score.Float64()
		return parsed
	default:
		return 0
	}
}

// classifyThreat picks a best-effort label from rspamd symbols.
func classifyThreat(ev *Event) string {
	return classifyThreatWithBrandOptions(ev, defaultBrandAnalysisOptions())
}

func classifyThreatWithBrandOptions(ev *Event, brandOpts brandAnalysisOptions) string {
	return classifyThreatWithOptions(ev, brandOpts, nil)
}

func classifyThreatWithOptions(ev *Event, brandOpts brandAnalysisOptions, pol *policies.Policy) string {
	if ev == nil {
		return ""
	}
	for sym, value := range ev.Symbols {
		s := strings.ToUpper(sym)
		switch {
		case strings.Contains(s, "PHISH") && symbolScore(value) > 0:
			if isAuthenticatedProtectedBrandSender(ev) && isGenericPhishingHeuristicSymbol(s) {
				continue
			}
			return "PHISHING"
		case (strings.Contains(s, "VIRUS") || strings.Contains(s, "CLAM")) && symbolScore(value) > 0:
			return "VIRUS"
		case isReputationBlockSymbol(s) && symbolScore(value) > 0:
			return "REPUTATION"
		}
	}
	analysis := classifier.AnalyzeCommonScam(ev.Subject, ev.BodyText)
	if commonScamDetectionAllows(pol, analysis.EmailType) {
		switch analysis.EmailType {
		case "Credential phishing":
			if !isAuthenticatedProtectedBrandSender(ev) {
				return "PHISHING"
			}
		case "Payment support scam", "Tax document phishing", "Medical miracle scam":
			return "PHISHING"
		case "Malware lure":
			return "MALWARE"
		case "Health miracle spam", "Home services lead-gen spam":
			return "SPAM"
		}
	}
	if analysis := analyzeBrandImpersonation(ev, brandOpts); analysis.Quarantine {
		return "PHISHING"
	}
	if ev.Score >= 10 {
		return "SPAM"
	}
	return ""
}

func commonScamDetectionAllows(pol *policies.Policy, emailType string) bool {
	if pol != nil && !pol.CommonScamDetectionEnabled() {
		return false
	}
	slug := commonScamCategorySlug(emailType)
	if slug == "" {
		return false
	}
	return pol == nil || pol.CommonScamCategoryEnabled(slug)
}

func commonScamCategorySlug(emailType string) string {
	switch emailType {
	case "Credential phishing":
		return "credential_phishing"
	case "Payment support scam":
		return "payment_support"
	case "Tax document phishing":
		return "tax_document"
	case "Malware lure":
		return "malware_lure"
	case "Medical miracle scam":
		return "health_miracle"
	case "Health miracle spam":
		return "health_miracle"
	case "Home services lead-gen spam":
		return "home_services"
	default:
		return ""
	}
}

type protectedBrandProfile struct {
	name          string
	terms         []string
	senderDomains []string
	cues          []string
}

var protectedBrandProfiles = []protectedBrandProfile{
	{
		name:          "microsoft",
		terms:         []string{"microsoft", "office 365", "microsoft 365", "onedrive", "sharepoint"},
		senderDomains: []string{"microsoft.com", "microsoftonline.com", "microsoftsupport.com", "office.com", "office365.com", "office365support.com", "outlook.com", "live.com", "mail.support.microsoft.com", "techsupport.microsoft.com"},
		cues:          []string{"account", "password", "security", "verify", "verification", "sign in", "login", "document", "shared", "subscription", "invoice", "billing", "storage"},
	},
	{
		name:          "google",
		terms:         []string{"google", "gmail", "google workspace", "google drive"},
		senderDomains: []string{"google.com", "accounts.google.com", "mail.google.com", "googlemail.com"},
		cues:          []string{"account", "password", "security", "verify", "verification", "sign in", "login", "drive", "document", "shared", "storage"},
	},
	{
		name:          "docusign",
		terms:         []string{"docusign", "docu sign"},
		senderDomains: []string{"docusign.net", "docusign.com"},
		cues:          []string{"document", "documents", "envelope", "signature", "sign", "signed", "complete", "review", "view", "agreement"},
	},
	{
		name:          "adobe",
		terms:         []string{"adobe", "acrobat", "adobe sign"},
		senderDomains: []string{"adobe.com", "email.adobe.com", "mail.adobe.com"},
		cues:          []string{"document", "documents", "signature", "sign", "signed", "agreement", "review", "shared", "invoice", "subscription", "account"},
	},
	{
		name:          "dropbox",
		terms:         []string{"dropbox", "dropbox paper"},
		senderDomains: []string{"dropbox.com", "dropboxmail.com", "docsend.com", "em-s.dropbox.com", "em.dropbox.com", "dropbox.zendesk.com", "dropboxpartners.com", "dropboxteam.com"},
		cues:          []string{"file", "files", "folder", "shared", "document", "documents", "view", "download", "sign in", "login", "storage"},
	},
	{
		name:          "paypal",
		terms:         []string{"paypal", "pay pal"},
		senderDomains: []string{"paypal.com", "mail.paypal.com"},
		cues:          []string{"account", "payment", "invoice", "transaction", "receipt", "refund", "charged", "charge", "billing", "verify", "verification", "limited", "dispute", "support"},
	},
	{
		name:          "intuit",
		terms:         []string{"intuit", "quickbooks", "quick books", "turbotax", "turbo tax"},
		senderDomains: []string{"intuit.com", "quickbooks.intuit.com", "notification.intuit.com", "selfemployed.intuit.com", "workforce.intuit.com", "tsheets.com", "macpayroll.com"},
		cues:          []string{"invoice", "payment", "payroll", "tax", "refund", "account", "billing", "statement", "verify", "verification", "document"},
	},
	{
		name:          "amazon",
		terms:         []string{"amazon", "amazon business", "amazon prime"},
		senderDomains: []string{"amazon.com", "amazonbusiness.com"},
		cues:          []string{"order", "shipment", "delivery", "payment", "invoice", "receipt", "refund", "account", "password", "billing", "prime", "subscription"},
	},
	{
		name:          "apple",
		terms:         []string{"apple", "apple id", "apple account", "icloud", "itunes", "app store"},
		senderDomains: []string{"apple.com", "email.apple.com", "icloud.com", "itunes.com"},
		cues:          []string{"account", "password", "security", "verify", "verification", "receipt", "purchase", "invoice", "icloud", "billing", "payment", "subscription"},
	},
	{
		name:          "netflix",
		terms:         []string{"netflix"},
		senderDomains: []string{"netflix.com"},
		cues:          []string{"account", "password", "billing", "payment", "subscription", "update", "verify", "verification", "sign in", "login", "membership"},
	},
}

type brandAnalysisOptions struct {
	Enabled                bool
	DisplayNameEnabled     bool
	SubjectEnabled         bool
	LinkMismatchEnabled    bool
	ThirdPartyReceiptsSafe bool
}

type brandAnalysis struct {
	Brand      string
	Score      int
	Signals    []string
	Quarantine bool
}

func (a brandAnalysis) Reason() string {
	if a.Brand == "" {
		return ""
	}
	if len(a.Signals) == 0 {
		return "brand impersonation: " + a.Brand
	}
	return "brand impersonation: " + a.Brand + "; " + strings.Join(a.Signals, "; ")
}

func defaultBrandAnalysisOptions() brandAnalysisOptions {
	return brandAnalysisOptions{
		Enabled:                true,
		DisplayNameEnabled:     true,
		SubjectEnabled:         true,
		LinkMismatchEnabled:    true,
		ThirdPartyReceiptsSafe: true,
	}
}

func brandAnalysisOptionsFromPolicy(pol *policies.Policy) brandAnalysisOptions {
	opts := defaultBrandAnalysisOptions()
	if pol == nil {
		return opts
	}
	opts.Enabled = pol.BrandImpersonationEnabled()
	opts.DisplayNameEnabled = pol.BrandImpersonationDisplayNameEnabled()
	opts.SubjectEnabled = pol.BrandImpersonationSubjectEnabled()
	opts.LinkMismatchEnabled = pol.BrandImpersonationLinkMismatchEnabled()
	opts.ThirdPartyReceiptsSafe = pol.BrandImpersonationThirdPartyReceiptsEnabled()
	return opts
}

func brandImpersonationHit(ev *Event) string {
	return analyzeBrandImpersonation(ev, defaultBrandAnalysisOptions()).Brand
}

func analyzeBrandImpersonation(ev *Event, opts brandAnalysisOptions) brandAnalysis {
	if !opts.Enabled || ev == nil {
		return brandAnalysis{}
	}
	fromDomain := emailDomain(ev.From)
	if fromDomain == "" {
		return brandAnalysis{}
	}
	var best brandAnalysis
	for _, profile := range protectedBrandProfiles {
		if domainMatchesAny(fromDomain, profile.senderDomains) {
			continue
		}
		current := scoreBrandClaim(ev, fromDomain, profile, opts)
		if current.Score > best.Score {
			best = current
		}
	}
	if best.Score >= 70 {
		best.Quarantine = true
	}
	return best
}

func scoreBrandClaim(ev *Event, fromDomain string, profile protectedBrandProfile, opts brandAnalysisOptions) brandAnalysis {
	fromName := suspiciousText(ev.FromName)
	subject := suspiciousText(ev.Subject)
	body := suspiciousText(ev.BodyText)
	combined := strings.TrimSpace(subject + " " + body)
	analysis := brandAnalysis{Brand: profile.name}

	if opts.DisplayNameEnabled && containsAny(fromName, profile.terms) {
		analysis.Score += 80
		analysis.Signals = append(analysis.Signals, "display name claims "+profile.name)
	}
	if opts.SubjectEnabled && containsAny(subject, profile.terms) && containsAny(combined, profile.cues) {
		analysis.Score += 45
		analysis.Signals = append(analysis.Signals, "subject or body claims "+profile.name+" with sensitive context")
	}
	if opts.LinkMismatchEnabled && containsAny(combined, profile.terms) {
		if host := firstMismatchedURLHost(ev, fromDomain, profile); host != "" {
			analysis.Score += 45
			analysis.Signals = append(analysis.Signals, "link points to unrelated domain "+host)
		}
	}
	if opts.ThirdPartyReceiptsSafe && isAuthenticatedThirdPartyReceipt(ev, fromDomain) {
		analysis.Score -= 80
		analysis.Signals = append(analysis.Signals, "authenticated third-party receipt context")
	}
	if analysis.Score < 0 {
		analysis.Score = 0
	}
	if analysis.Score == 0 {
		return brandAnalysis{}
	}
	return analysis
}

func firstMismatchedURLHost(ev *Event, fromDomain string, profile protectedBrandProfile) string {
	if ev == nil {
		return ""
	}
	for _, raw := range ev.URLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		host := strings.ToLower(strings.Trim(parsed.Hostname(), "."))
		if domainMatchesAny(host, profile.senderDomains) || domainMatchesAny(host, []string{fromDomain}) {
			continue
		}
		return host
	}
	return ""
}

func isAuthenticatedProtectedBrandSender(ev *Event) bool {
	if ev == nil || !authSignals(ev).DMARCPass {
		return false
	}
	fromDomain := emailDomain(ev.From)
	if fromDomain == "" {
		return false
	}
	for _, profile := range protectedBrandProfiles {
		if domainMatchesAny(fromDomain, profile.senderDomains) {
			return true
		}
	}
	return false
}

func isGenericPhishingHeuristicSymbol(symbol string) bool {
	switch strings.ToUpper(strings.TrimSpace(symbol)) {
	case "PHISHING", "PHISHING_CHECK":
		return true
	default:
		return false
	}
}

func isAuthenticatedThirdPartyReceipt(ev *Event, fromDomain string) bool {
	if !isAuthenticatedProtectedBrandSender(ev) {
		return false
	}
	if !domainMatchesAny(fromDomain, []string{"paypal.com", "mail.paypal.com"}) {
		return false
	}
	text := suspiciousText(ev.Subject + " " + ev.BodyText)
	if containsAny(text, []string{"verify", "verification", "password", "sign in", "login", "account suspended", "security alert"}) {
		return false
	}
	return containsAny(text, []string{
		"receipt",
		"transaction id",
		"you sent a payment",
		"payment sent",
		"paid to",
		"purchase details",
		"automatic payment",
		"preapproved payment",
	})
}

func emailDomain(addr string) string {
	addr = strings.Trim(strings.ToLower(strings.TrimSpace(addr)), "<>")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.Trim(addr[at+1:], ".")
}

func domainMatchesAny(domain string, allowed []string) bool {
	domain = strings.Trim(strings.ToLower(domain), ".")
	for _, candidate := range allowed {
		candidate = strings.Trim(strings.ToLower(candidate), ".")
		if domain == candidate || strings.HasSuffix(domain, "."+candidate) {
			return true
		}
	}
	return false
}

func suspiciousText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func storageKey(ev *Event) string {
	if strings.TrimSpace(ev.StorageKey) != "" {
		return ev.StorageKey
	}
	if ev.RawMessageB64 != "" {
		return "db"
	}
	return ""
}

func primaryDomain(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

func lookupDomainOrg(ctx context.Context, db *pgxpool.Pool, domain string) (*uuid.UUID, *uuid.UUID, error) {
	if domain == "" {
		return nil, nil, errors.New("empty domain")
	}
	var did, oid uuid.UUID
	err := db.QueryRow(ctx,
		`SELECT id, organization_id FROM domains WHERE lower(name) = $1 AND is_active = true`,
		domain).Scan(&did, &oid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errors.New("domain not configured")
		}
		return nil, nil, err
	}
	return &did, &oid, nil
}

func (h *IngestHandler) verifySig(body []byte, sigHex string) bool {
	if len(h.Secret) == 0 || sigHex == "" {
		return false
	}
	want := hmac.New(sha256.New, h.Secret)
	want.Write(body)
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return hmac.Equal(want.Sum(nil), got)
}
