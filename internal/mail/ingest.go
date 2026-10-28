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
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/arphost/sentinelmail-gateway/internal/brandintel"
	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/notifications"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
	"github.com/arphost/sentinelmail-gateway/internal/threatfeed"
)

// Event is the payload Rspamd (via a small Lua snippet) POSTs after scanning.
// Shape kept tight on purpose — anything richer goes in symbols.
type Event struct {
	Direction      string         `json:"direction"` // inbound | outbound
	QueueID        string         `json:"queue_id,omitempty"`
	MessageID      string         `json:"message_id,omitempty"`
	From           string         `json:"from"`
	FromName       string         `json:"from_display_name,omitempty"`
	ReplyTo        string         `json:"reply_to,omitempty"`
	To             []string       `json:"to"`
	ClientIP       string         `json:"client_ip,omitempty"`
	ClientHostname string         `json:"client_hostname,omitempty"`
	Helo           string         `json:"helo,omitempty"`
	Subject        string         `json:"subject,omitempty"`
	SizeBytes      int            `json:"size_bytes,omitempty"`
	Score          float64        `json:"score"`
	Action         string         `json:"action,omitempty"` // rspamd action: no action, add header, greylist, soft reject, reject
	Symbols        map[string]any `json:"symbols,omitempty"`
	StorageKey     string         `json:"storage_key,omitempty"` // worker-supplied path for the .eml blob

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
	Brands *brandintel.Catalog
	Feeds  *threatfeed.Registry
}

func MountIngest(r chi.Router, db *pgxpool.Pool, rdb *redis.Client, secret []byte, brands *brandintel.Catalog, feeds *threatfeed.Registry) {
	h := &IngestHandler{DB: db, Redis: rdb, Secret: secret, Brands: brands, Feeds: feeds}
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
	challengeEnabled := h.challengeResponseEnabled(r.Context(), pol, orgID, ev.To[0])
	brandProfiles := protectedBrandProfiles
	if h.Brands != nil {
		if profiles, loadErr := h.Brands.ProtectedProfiles(r.Context()); loadErr == nil && len(profiles) > 0 {
			brandProfiles = make([]protectedBrandProfile, 0, len(profiles))
			for _, profile := range profiles {
				brandProfiles = append(brandProfiles, protectedBrandProfile{
					name:          profile.Name,
					terms:         profile.Aliases,
					senderDomains: profile.OfficialDomains,
					cues:          profile.Cues,
				})
			}
		}
	}

	disposition, reason := decide(pol, &ev)
	disposition, reason = applyDeliveryStatusNotificationDisposition(disposition, reason, &ev)
	disposition, reason = applyAuthEnforcement(disposition, reason, &ev)
	senderAction := ""
	disposition, reason, senderAction, err = h.applySenderListDecision(r.Context(), disposition, reason, pol, challengeEnabled, orgID, domainID, &ev)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sender policy lookup: "+err.Error())
		return
	}
	disposition, reason = applyRspamdSenderBlocklist(disposition, reason, &ev)
	disposition, reason = applyReputationBlocklist(disposition, reason, &ev)
	disposition, reason = h.applyCachedThreatIntelligence(r.Context(), disposition, reason, &ev)
	disposition, reason = applyCommonScamDetectionWithPolicy(disposition, reason, pol, &ev)
	disposition, reason = applyBrandImpersonationDetectionWithProfiles(disposition, reason, senderAction, pol, &ev, brandProfiles)
	disposition, reason = applyThreatSignalDispositionWithPolicy(disposition, reason, pol, &ev)
	disposition, reason = applySenderListAction(disposition, reason, senderAction, pol.SenderBlacklistEnabled() || challengeEnabled)
	disposition, reason = applyChallengeResponseHoldEnabled(disposition, reason, pol, senderAction, challengeEnabled, &ev)
	if orgID != nil {
		if learned, err := classifier.Lookup(r.Context(), h.DB, *orgID, ev.To[0], ev.From, ev.Subject); err == nil && learned != nil {
			disposition, reason = applyLearnedClassification(disposition, reason, learned)
		}
	}
	disposition, reason = applySenderListAction(disposition, reason, senderAction, pol.SenderBlacklistEnabled() || challengeEnabled)
	disposition, reason = applyQuarantineFirst(disposition, reason, &ev)
	senderResultAction := effectiveSenderListAction(senderAction, pol.SenderBlacklistEnabled() || challengeEnabled)
	deepAnalysisState := "not_required"
	var deepAnalysisDeadline *time.Time
	if shouldHoldForDeepAnalysis(r.Context(), h.DB, disposition, &ev) {
		disposition = "quarantined"
		reason = "pending deep analysis"
		deepAnalysisState = "pending"
		deadline := time.Now().Add(time.Duration(settings.LookupDeepAnalysisConfig(r.Context(), h.DB).TimeoutMinutes) * time.Minute)
		deepAnalysisDeadline = &deadline
	}

	threatClass := ""
	if disposition == "quarantined" {
		if deepAnalysisState == "pending" {
			threatClass = "PENDING_ANALYSIS"
		} else {
			threatClass = classifyThreatWithProfiles(&ev, brandAnalysisOptionsFromPolicy(pol), pol, brandProfiles)
		}
		if challenge.IsPendingReason(reason) {
			threatClass = "CHALLENGE_RESPONSE"
		}
	}
	highConfidence := highConfidenceCampaign(disposition, reason, threatClass)
	campaign, err := recordCampaign(r.Context(), h.DB, orgID, domainID, disposition, threatClass, &ev)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "campaign update: "+err.Error())
		return
	}
	campaignAction := "aggregate"
	suppressDuplicate := highConfidence && campaign.MessageCount > 1 && campaign.HasRepresentative
	if highConfidence && campaign.MessageCount >= int64(pol.CampaignThreshold()) {
		campaignAction = pol.CampaignAction()
		switch campaignAction {
		case "reject":
			disposition = "rejected"
			reason = "high-confidence campaign threshold reached; rejected by tenant policy"
			suppressDuplicate = true
		case "discard":
			reason = "high-confidence campaign threshold reached; accepted and discarded by tenant policy"
			suppressDuplicate = campaign.MessageCount > 1
		}
	}

	// Persist mail log.
	recordSenderListSymbol(&ev, senderResultAction)
	symbolsJSON := []byte("{}")
	if len(ev.Symbols) > 0 {
		symbolsJSON, _ = json.Marshal(ev.Symbols)
	}
	var mailLogID uuid.UUID
	err = h.DB.QueryRow(r.Context(), `
		INSERT INTO mail_logs (organization_id, domain_id, campaign_id, campaign_copy_number,
		                       queue_id, message_id, direction,
		                       from_addr, to_addrs, client_ip, client_hostname, helo, subject, size_bytes,
		                       rspamd_score, rspamd_action, symbols, disposition, reason,
		                       deep_analysis_state, deep_analysis_deadline, received_at)
		VALUES ($1, $2, NULLIF($3, '00000000-0000-0000-0000-000000000000'::uuid), NULLIF($4,0),
		        $5, $6, $7, $8, $9, NULLIF($10,'')::inet, NULLIF($11,''), $12, $13, $14,
		        $15, $16, $17::jsonb, $18::mail_disposition, $19, $20, $21, now())
		RETURNING id
	`, orgID, domainID, campaign.ID, campaign.MessageCount, ev.QueueID, ev.MessageID, ev.Direction,
		ev.From, ev.To, ev.ClientIP, ev.ClientHostname, ev.Helo, ev.Subject, ev.SizeBytes,
		ev.Score, ev.Action, symbolsJSON, disposition, reason, deepAnalysisState, deepAnalysisDeadline).Scan(&mailLogID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "log insert: "+err.Error())
		return
	}
	if campaign.ID != uuid.Nil {
		_, _ = h.DB.Exec(r.Context(), `
			UPDATE mail_campaigns
			   SET representative_mail_log_id = COALESCE(representative_mail_log_id, $2),
			       latest_disposition = $3,
			       updated_at = now()
			 WHERE id = $1
		`, campaign.ID, mailLogID, disposition)
	}
	if err := h.insertMailboxCopies(r.Context(), orgID, domainID, mailLogID, disposition, &ev); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mailbox insert: "+err.Error())
		return
	}
	if !suppressDuplicate {
		err = h.insertMailLogBlob(r.Context(), orgID, mailLogID, &ev)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail log blob insert: "+err.Error())
		return
	}

	// Quarantine if needed.
	if disposition == "quarantined" && !suppressDuplicate {
		var quarantineID uuid.UUID
		var quarantineCampaignID *uuid.UUID
		if highConfidence && campaign.ID != uuid.Nil {
			quarantineCampaignID = &campaign.ID
		}
		retentionDays := settings.MessageRetentionDaysForDomain(r.Context(), h.DB, *orgID, *domainID)
		err = h.DB.QueryRow(r.Context(), `
			INSERT INTO quarantine_entries
			  (organization_id, mail_log_id, domain_id, from_addr, to_addr, subject,
			   rspamd_score, threat_class, storage_key, size_bytes, expires_at, received_at, campaign_id)
			VALUES ($1, $2, $3, NULLIF($4,''), $5, NULLIF($6,''),
			        $7, $8, $9, NULLIF($10,0), now() + ($11::int * interval '1 day'), now(), $12)
			ON CONFLICT DO NOTHING
			RETURNING id
		`, orgID, mailLogID, domainID, ev.From, ev.To[0], ev.Subject,
			ev.Score, threatClass, storageKey(&ev), ev.SizeBytes, retentionDays, quarantineCampaignID).Scan(&quarantineID)
		if errors.Is(err, pgx.ErrNoRows) {
			suppressDuplicate = true
		} else if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "quarantine insert: "+err.Error())
			return
		}
		if !suppressDuplicate {
			if campaign.ID != uuid.Nil {
				_, _ = h.DB.Exec(r.Context(), `
					UPDATE mail_campaigns
					   SET representative_quarantine_id = COALESCE(representative_quarantine_id, $2),
					       updated_at = now()
					 WHERE id = $1
				`, campaign.ID, quarantineID)
			}
			if err := h.insertQuarantineBlob(r.Context(), orgID, mailLogID, quarantineID, &ev); err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "quarantine blob insert: "+err.Error())
				return
			}
		}
		if !suppressDuplicate && threatClass == "CHALLENGE_RESPONSE" {
			go func(id uuid.UUID) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := notifications.SendChallengeResponseAlertForMailLog(ctx, h.DB, id); err != nil {
					slog.Default().Warn("challenge_alert.send_failed",
						slog.String("mail_log_id", id.String()), slog.String("error", err.Error()))
				}
			}(mailLogID)
		} else if !suppressDuplicate && threatClass != "PENDING_ANALYSIS" {
			// Every quarantined class alerts immediate-cadence recipients, not
			// just PHISHING. Deep-analysis holds stay silent because most are
			// released again within minutes.
			if threatClass == "PHISHING" && campaign.ID != uuid.Nil {
				_, _ = h.DB.Exec(r.Context(), `
					UPDATE mail_campaigns
					   SET last_alert_at = now(), updated_at = now()
					 WHERE id = $1
				`, campaign.ID)
			}
			go func(id uuid.UUID) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := notifications.SendPhishingAlertForMailLog(ctx, h.DB, id); err != nil {
					slog.Default().Warn("quarantine_alert.send_failed",
						slog.String("mail_log_id", id.String()), slog.String("error", err.Error()))
				}
			}(mailLogID)
		}
	}
	if suppressDuplicate && campaign.ID != uuid.Nil {
		_, _ = h.DB.Exec(r.Context(), `
			UPDATE mail_campaigns
			   SET suppressed_count = suppressed_count + 1, updated_at = now()
			 WHERE id = $1
		`, campaign.ID)
	}

	// MVP 2 — auto-spawn scans based on what rspamd extracted. Best-effort;
	// errors here are logged via the response field but never fail the
	// ingest call (mail flow must not depend on scan availability).
	var spawned []string
	var scanErr error
	if !suppressDuplicate {
		spawned, scanErr = h.spawnScans(r.Context(), orgID, mailLogID, disposition, &ev)
	}
	scanErrStr := ""
	if scanErr != nil {
		scanErrStr = scanErr.Error()
	}

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"mail_log_id":         mailLogID,
		"disposition":         disposition,
		"scans_spawned":       spawned,
		"scan_error":          scanErrStr,
		"policy":              pol.Name,
		"campaign_id":         campaign.ID,
		"campaign_count":      campaign.MessageCount,
		"campaign_action":     campaignAction,
		"campaign_suppressed": suppressDuplicate,
		"sender_action":       senderResultAction,
	})
	h.warmThreatIntelligence(&ev)
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
	retentionDays := settings.MessageRetentionDaysForDomain(ctx, h.DB, *orgID, *domainID)
	for _, to := range ev.To {
		to = strings.ToLower(strings.TrimSpace(to))
		if to == "" {
			continue
		}
		_, err := h.DB.Exec(ctx, `
			INSERT INTO mailbox_messages
			  (organization_id, domain_id, mail_log_id, from_addr, to_addr, subject, body_text,
			   list_unsubscribe, list_unsubscribe_post, expires_at, received_at)
			VALUES ($1, $2, $3, NULLIF($4,''), $5, NULLIF($6,''), $7, NULLIF($8,''), NULLIF($9,''), now() + ($10::int * interval '1 day'), now())
			ON CONFLICT (mail_log_id, to_addr) DO NOTHING
		`, orgID, domainID, mailLogID, ev.From, to, ev.Subject, body, ev.ListUnsubscribe, ev.ListUnsubscribePost, retentionDays)
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
	maxURLScans        = 3       // sandbox is heavy; rank and cap CTA destinations
	maxBodyForAI       = 16_000  // chars
	maxRawMessageBytes = 8 << 20 // 8 MiB raw .eml, base64-encoded in JSON
)

// spawnScans enqueues async scans based on what rspamd surfaced. Returns the
// kinds spawned and the first error encountered. Mail flow MUST NOT depend on
// the scan layer — every error here is best-effort logged via the response.
func (h *IngestHandler) spawnScans(ctx context.Context, orgID *uuid.UUID, mailLogID uuid.UUID, disposition string, ev *Event) ([]string, error) {
	if h.Redis == nil || orgID == nil {
		return nil, nil
	}
	spawned := []string{}
	var firstErr error

	// AI scoring is explicitly cost-controlled by the database-backed mode.
	// Missing provider configuration creates no job instead of flooding the
	// queue with unavailable results.
	if ev.Direction == "inbound" && (ev.Subject != "" || ev.BodyText != "") && settings.ShouldQueueAI(ctx, h.DB, disposition) {
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

	// Rank a small set of actionable links instead of trusting Rspamd's
	// arbitrary URL order. Images, pixels, assets, and unsubscribe controls
	// are poor browser-sandbox targets and can hide the actual CTA.
	for _, targetURL := range prioritizedSandboxURLs(ev) {
		if err := h.enqueue(ctx, *orgID, &mailLogID, "sandbox", map[string]any{"url": targetURL}); err != nil && firstErr == nil {
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

func shouldHoldForDeepAnalysis(ctx context.Context, db *pgxpool.Pool, disposition string, ev *Event) bool {
	if ev == nil || !strings.EqualFold(ev.Direction, "inbound") || disposition != "tagged" {
		return false
	}
	config := settings.LookupDeepAnalysisConfig(ctx, db)
	ai := settings.LookupAIConfig(ctx, db)
	return deepAnalysisEligible(disposition, ev, config, ai)
}

func deepAnalysisEligible(disposition string, ev *Event, config settings.DeepAnalysisConfig, ai settings.AIConfig) bool {
	return ev != nil && len(ev.To) == 1 && strings.EqualFold(ev.Direction, "inbound") && disposition == "tagged" &&
		config.Enabled && ev.Score >= config.MinScore && ai.Available &&
		(ai.Mode == "suspicious" || ai.Mode == "all")
}

type threatCandidate struct {
	kind  threatfeed.Kind
	value string
}

func (h *IngestHandler) applyCachedThreatIntelligence(ctx context.Context, disposition, reason string, ev *Event) (string, string) {
	if h.Feeds == nil || ev == nil || disposition == "rejected" || disposition == "quarantined" {
		return disposition, reason
	}
	var enabled bool
	if err := h.DB.QueryRow(ctx, `SELECT COALESCE((value #>> '{}')::boolean, false) FROM system_settings WHERE organization_id IS NULL AND key = 'threat_intel.cached_enforcement'`).Scan(&enabled); err != nil || !enabled {
		return disposition, reason
	}
	for _, candidate := range threatCandidates(ev) {
		result, ok := h.Feeds.LookupCached(ctx, candidate.kind, candidate.value)
		if !ok || !result.Hit {
			continue
		}
		if ev.Symbols == nil {
			ev.Symbols = map[string]any{}
		}
		ev.Symbols[threatFeedSymbol(result.Source)] = map[string]any{"score": 10, "group": "sentinelmail_threat_intel"}
		return "quarantined", "cached threat intelligence hit: " + result.Source
	}
	return disposition, reason
}

func (h *IngestHandler) warmThreatIntelligence(ev *Event) {
	if h.Feeds == nil || ev == nil {
		return
	}
	candidates := threatCandidates(ev)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, candidate := range candidates {
			if ctx.Err() != nil {
				return
			}
			h.Feeds.Warm(ctx, candidate.kind, candidate.value)
		}
	}()
}

func threatCandidates(ev *Event) []threatCandidate {
	if ev == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]threatCandidate, 0, 8)
	add := func(kind threatfeed.Kind, value string) {
		value = strings.TrimSpace(value)
		key := string(kind) + "\x00" + strings.ToLower(value)
		if value == "" || seen[key] || len(out) >= 8 {
			return
		}
		seen[key] = true
		out = append(out, threatCandidate{kind: kind, value: value})
	}
	add(threatfeed.KindIP, ev.ClientIP)
	add(threatfeed.KindDomain, emailDomain(ev.From))
	for _, raw := range ev.URLs {
		if len(out) >= 8 {
			break
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			continue
		}
		add(threatfeed.KindDomain, u.Hostname())
		add(threatfeed.KindURL, u.String())
	}
	return out
}

func threatFeedSymbol(source string) string {
	var b strings.Builder
	b.WriteString("SMG_TF_")
	for _, r := range strings.ToUpper(source) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.TrimRight(b.String(), "_")
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
		return "rejected", "score >= reject_threshold"
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

func applyDeliveryStatusNotificationDisposition(disposition, reason string, ev *Event) (string, string) {
	if !isDeliveryStatusNotification(ev) {
		return disposition, reason
	}
	if reason == "" || strings.HasPrefix(reason, "score >=") {
		return "delivered", "delivery status notification"
	}
	return disposition, reason
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
		strings.HasPrefix(reason, "score >= quarantine_threshold") ||
		strings.HasPrefix(reason, "score >= reject_threshold") ||
		strings.HasPrefix(reason, "cached threat intelligence hit:") ||
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

func (h *IngestHandler) applySenderListDecision(ctx context.Context, disposition, reason string, pol *policies.Policy, challengeEnabled bool, orgID *uuid.UUID, domainID *uuid.UUID, ev *Event) (string, string, string, error) {
	if pol == nil || orgID == nil || ev == nil || len(ev.To) == 0 {
		return disposition, reason, "", nil
	}
	action, _, err := h.lookupSenderListWithIP(ctx, *orgID, domainID, strings.ToLower(strings.TrimSpace(ev.To[0])), ev.ClientIP, ev.From, ev.ReplyTo)
	if err != nil {
		return disposition, reason, "", err
	}
	nextDisposition, nextReason := applySenderListAction(disposition, reason, action, pol.SenderBlacklistEnabled() || challengeEnabled)
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

func effectiveSenderListAction(action string, blacklistEnabled bool) string {
	if action == "allow" || (action == "block" && blacklistEnabled) {
		return action
	}
	return ""
}

func recordSenderListSymbol(ev *Event, action string) {
	if ev == nil || (action != "allow" && action != "block") {
		return
	}
	if ev.Symbols == nil {
		ev.Symbols = make(map[string]any)
	}
	name := "SMG_SENDER_ALLOWLIST"
	score := -20.0
	if action == "block" {
		name = "SMG_SENDER_BLACKLIST"
		score = 20.0
	}
	ev.Symbols[name] = map[string]any{
		"score":   score,
		"group":   "sentinelmail",
		"options": []string{},
	}
}

func isAllowlistOverrideBlockedReason(reason string) bool {
	if strings.HasPrefix(reason, "sender authentication") ||
		strings.HasPrefix(reason, "score >= quarantine_threshold") ||
		strings.HasPrefix(reason, "score >= reject_threshold") ||
		strings.HasPrefix(reason, "cached threat intelligence hit:") ||
		strings.HasPrefix(reason, "sender failed DMARC") ||
		strings.HasPrefix(reason, "sender failed SPF/DKIM") ||
		strings.HasPrefix(reason, "malware signal hit") ||
		strings.HasPrefix(reason, "user classified similar mail as spam") ||
		strings.HasPrefix(reason, "user classified similar mail as phishing") ||
		strings.HasPrefix(reason, "user classified similar mail as malware") {
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
	if isDeliveryStatusNotification(ev) {
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
	case "Wallet access phishing", "Payment support scam", "Tax document phishing", "Medical miracle scam", "Malware lure", "Health miracle spam", "Health lead-generation spam", "Home services lead-gen spam":
		return "quarantined", "detected " + strings.ToLower(analysis.EmailType)
	default:
		return disposition, reason
	}
}

func applyBrandImpersonationDetection(disposition, reason, senderAction string, pol *policies.Policy, ev *Event) (string, string) {
	return applyBrandImpersonationDetectionWithProfiles(disposition, reason, senderAction, pol, ev, protectedBrandProfiles)
}

func applyBrandImpersonationDetectionWithProfiles(disposition, reason, senderAction string, pol *policies.Policy, ev *Event, profiles []protectedBrandProfile) (string, string) {
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
	analysis := analyzeBrandImpersonationWithProfiles(ev, brandAnalysisOptionsFromPolicy(pol), profiles)
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
	return applyChallengeResponseHoldEnabled(disposition, reason, pol, senderAction, pol != nil && pol.ChallengeResponseEnabled(), ev)
}

func applyChallengeResponseHoldEnabled(disposition, reason string, pol *policies.Policy, senderAction string, enabled bool, ev *Event) (string, string) {
	if disposition == "rejected" || pol == nil || !enabled {
		return disposition, reason
	}
	if ev == nil || !strings.EqualFold(ev.Direction, "inbound") {
		return disposition, reason
	}
	if isDeliveryStatusNotification(ev) {
		return disposition, reason
	}
	if disposition == "quarantined" && !challengeCanRequestApproval(reason, pol, ev) {
		return disposition, reason
	}
	if senderAction == "allow" && (!pol.ChallengeResponseRequireVerifiedSource() || challengeSourceVerified(ev)) {
		return disposition, reason
	}
	return "quarantined", challenge.ReasonPendingApproval
}

func challengeCanRequestApproval(reason string, pol *policies.Policy, ev *Event) bool {
	// Authentication failure is useful evidence and remains visible in the
	// stored symbols, but it is not an existing sender/domain/IP block. In
	// strict challenge mode the user must therefore be notified that the
	// unknown sender is waiting for approval. Never convert malware, phishing,
	// or other threat classifications into an approval request.
	authQuarantine := reason == "sender authentication results missing" ||
		strings.HasPrefix(reason, "sender failed DMARC") ||
		strings.HasPrefix(reason, "sender failed SPF/DKIM") ||
		strings.HasPrefix(reason, "sender authentication")
	if !authQuarantine || ev == nil {
		return false
	}
	if threat := classifyThreat(ev); threat == "PHISHING" || threat == "VIRUS" || threat == "MALWARE" {
		return false
	}
	analysis := classifier.AnalyzeCommonScam(ev.Subject, ev.BodyText)
	return analysis.EmailType == "" || !commonScamDetectionAllows(pol, analysis.EmailType)
}

func (h *IngestHandler) challengeResponseEnabled(ctx context.Context, pol *policies.Policy, orgID *uuid.UUID, recipient string) bool {
	if pol == nil {
		return false
	}
	enabled := pol.ChallengeResponseEnabled()
	if h == nil || h.DB == nil || orgID == nil {
		return enabled
	}
	var mode string
	var active bool
	err := h.DB.QueryRow(ctx, `
		SELECT challenge_response_mode, is_active
		  FROM users
		 WHERE organization_id = $1
		   AND lower(email::text) = lower($2)
		 LIMIT 1
	`, *orgID, strings.TrimSpace(recipient)).Scan(&mode, &active)
	if err != nil {
		return enabled
	}
	return challengeResponseModeEnabled(enabled, mode, active)
}

func challengeResponseModeEnabled(policyEnabled bool, mode string, active bool) bool {
	// Deactivated mailboxes cannot silently bypass an organization-wide
	// allowlist-first policy. They remain held and visible to active admins,
	// but receive no approval digest and cannot approve a release.
	if !active {
		return policyEnabled
	}
	switch mode {
	case "enabled":
		return true
	case "disabled":
		return false
	default:
		return policyEnabled
	}
}

func challengeSourceVerified(ev *Event) bool {
	if ev == nil {
		return false
	}
	auth := authSignals(ev)
	if !auth.DMARCPass || (!auth.SPFPass && !auth.DKIMPass) {
		return false
	}
	hostname := strings.ToLower(strings.Trim(strings.TrimSpace(ev.ClientHostname), "."))
	if hostname == "" || hostname == "unknown" || hostname == "localhost" || strings.HasPrefix(hostname, "[") {
		return false
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return false
	}
	return strings.Contains(hostname, ".")
}

func isDeliveryStatusNotification(ev *Event) bool {
	if ev == nil || strings.EqualFold(ev.Direction, "outbound") {
		return false
	}
	from := strings.ToLower(strings.TrimSpace(ev.From))
	hasNullEnvelope := from == "" || from == "<>"
	fromLooksSystem := strings.HasPrefix(from, "mailer-daemon@") || strings.HasPrefix(from, "postmaster@")
	subjectLooksDSN := looksLikeDSNSubject(ev.Subject)
	symbolLooksDSN := hasDeliveryStatusNotificationSymbol(ev)
	rawLooksDSN := rawMessageLooksDSN(ev.RawMessageB64)
	if symbolLooksDSN && (hasNullEnvelope || fromLooksSystem || subjectLooksDSN) {
		return true
	}
	if rawLooksDSN && (hasNullEnvelope || fromLooksSystem || subjectLooksDSN) {
		return true
	}
	return hasNullEnvelope && subjectLooksDSN
}

func hasDeliveryStatusNotificationSymbol(ev *Event) bool {
	for key, value := range ev.Symbols {
		if !strings.EqualFold(key, "BOUNCE") {
			continue
		}
		if symbolHasOption(value, "DSN") {
			return true
		}
		return true
	}
	return false
}

func symbolHasOption(value any, want string) bool {
	want = strings.ToUpper(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return false
	}
	options, ok := obj["options"]
	if !ok {
		return false
	}
	switch vals := options.(type) {
	case []any:
		for _, value := range vals {
			if strings.EqualFold(strings.TrimSpace(toString(value)), want) {
				return true
			}
		}
	case []string:
		for _, value := range vals {
			if strings.EqualFold(strings.TrimSpace(value), want) {
				return true
			}
		}
	}
	return false
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func looksLikeDSNSubject(subject string) bool {
	subject = strings.ToLower(strings.TrimSpace(subject))
	switch {
	case strings.Contains(subject, "delivery status notification"),
		strings.Contains(subject, "undelivered mail returned"),
		strings.Contains(subject, "undeliverable:"),
		strings.Contains(subject, "mail delivery failed"),
		strings.Contains(subject, "returned mail"),
		strings.Contains(subject, "failure notice"):
		return true
	default:
		return false
	}
}

func rawMessageLooksDSN(rawB64 string) bool {
	rawB64 = strings.TrimSpace(rawB64)
	if rawB64 == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil || len(raw) == 0 {
		return false
	}
	if len(raw) > 64*1024 {
		raw = raw[:64*1024]
	}
	s := strings.ToLower(string(raw))
	switch {
	case strings.Contains(s, "report-type=delivery-status"),
		strings.Contains(s, "message/delivery-status"),
		strings.Contains(s, "auto-submitted: auto-generated"),
		strings.Contains(s, "auto-submitted: auto-replied"):
		return true
	default:
		return false
	}
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
		if isReputationBlockSymbol(s) && symbolScore(value) > 0 &&
			!isAuthenticatedFirstPartyURLReputationHit(s, value, ev) {
			return true
		}
	}
	return false
}

// RSPAMD_URIBL is a broad URL-reputation heuristic rather than a feed-specific
// malware verdict. Do not turn it into a hard quarantine when DMARC passed and
// every listed URL domain is the authenticated sender's own domain or parent.
// Feed-specific URLhaus/OpenPhish hits and unrelated URL domains still block.
func isAuthenticatedFirstPartyURLReputationHit(symbol string, value any, ev *Event) bool {
	if !strings.EqualFold(symbol, "RSPAMD_URIBL") || ev == nil || !authSignals(ev).DMARCPass {
		return false
	}
	senderDomain := emailDomain(ev.From)
	if senderDomain == "" {
		return false
	}
	options := symbolOptions(value)
	if len(options) == 0 {
		return false
	}
	matched := false
	for _, option := range options {
		domain, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(option)), ":")
		domain = strings.Trim(domain, ".")
		if domain == "" {
			continue
		}
		matched = true
		if !domainsRelated(senderDomain, domain) {
			return false
		}
	}
	return matched
}

func domainsRelated(a, b string) bool {
	a = strings.Trim(strings.ToLower(a), ".")
	b = strings.Trim(strings.ToLower(b), ".")
	return a != "" && b != "" &&
		(a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a))
}

func symbolOptions(value any) []string {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	switch values := obj["options"].(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if option, ok := value.(string); ok {
				out = append(out, option)
			}
		}
		return out
	default:
		return nil
	}
}

func hasReputationAllowlistHit(ev *Event) bool {
	if ev == nil {
		return false
	}
	for key := range ev.Symbols {
		s := strings.ToUpper(key)
		if isReputationLookupFailureSymbol(s) {
			continue
		}
		if isReputationAllowSymbol(s) {
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
	return classifyThreatWithProfiles(ev, brandOpts, pol, protectedBrandProfiles)
}

func classifyThreatWithProfiles(ev *Event, brandOpts brandAnalysisOptions, pol *policies.Policy, profiles []protectedBrandProfile) string {
	if ev == nil {
		return ""
	}
	for sym, value := range ev.Symbols {
		s := strings.ToUpper(sym)
		switch {
		case strings.Contains(s, "PHISH") && symbolScore(value) > 0:
			if isAuthenticatedProtectedBrandSenderWithProfiles(ev, profiles) && isGenericPhishingHeuristicSymbol(s) {
				continue
			}
			return "PHISHING"
		case (strings.Contains(s, "VIRUS") || strings.Contains(s, "CLAM")) && symbolScore(value) > 0:
			return "VIRUS"
		case isReputationBlockSymbol(s) && symbolScore(value) > 0 &&
			!isAuthenticatedFirstPartyURLReputationHit(s, value, ev):
			return "REPUTATION"
		}
	}
	analysis := classifier.AnalyzeCommonScam(ev.Subject, ev.BodyText)
	if commonScamDetectionAllows(pol, analysis.EmailType) {
		switch analysis.EmailType {
		case "Credential phishing":
			if !isAuthenticatedProtectedBrandSenderWithProfiles(ev, profiles) {
				return "PHISHING"
			}
		case "Wallet access phishing", "Payment support scam", "Tax document phishing", "Medical miracle scam":
			return "PHISHING"
		case "Malware lure":
			return "MALWARE"
		case "Health miracle spam", "Health lead-generation spam", "Home services lead-gen spam":
			return "SPAM"
		}
	}
	if analysis := analyzeBrandImpersonationWithProfiles(ev, brandOpts, profiles); analysis.Quarantine {
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
	case "Wallet access phishing":
		return "credential_phishing"
	case "Payment support scam":
		return "payment_support"
	case "Tax document phishing":
		return "tax_document"
	case "Malware lure":
		return "malware_lure"
	case "Medical miracle scam":
		return "health_miracle"
	case "Health miracle spam", "Health lead-generation spam":
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
	return analyzeBrandImpersonationWithProfiles(ev, opts, protectedBrandProfiles)
}

func analyzeBrandImpersonationWithProfiles(ev *Event, opts brandAnalysisOptions, profiles []protectedBrandProfile) brandAnalysis {
	if !opts.Enabled || ev == nil {
		return brandAnalysis{}
	}
	fromDomain := emailDomain(ev.From)
	if fromDomain == "" {
		return brandAnalysis{}
	}
	var best brandAnalysis
	for _, profile := range profiles {
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
	displayNameClaim := containsAny(fromName, profile.terms)
	subjectClaim := containsAny(subject, profile.terms)
	bodyClaim := containsAny(body, profile.terms)
	pressureClaim := (subjectClaim || bodyClaim) &&
		containsAny(combined, accountLossPressurePhrases) &&
		containsAny(combined, updateDetailsCTAPhrases)
	authenticatedNewsletter := authSignals(ev).DMARCPass &&
		strings.TrimSpace(ev.ListUnsubscribe) != "" &&
		!displayNameClaim && !pressureClaim

	if opts.DisplayNameEnabled && displayNameClaim {
		analysis.Score += 80
		analysis.Signals = append(analysis.Signals, "display name claims "+profile.name)
	}
	if opts.SubjectEnabled && subjectClaim && containsAny(combined, profile.cues) {
		analysis.Score += 45
		analysis.Signals = append(analysis.Signals, "message claims "+profile.name+" with sensitive context")
	}
	// Some impersonation templates put the brand claim entirely in the body.
	// Require a signature workflow, an action request, and an off-domain URL;
	// a passing DKIM signature for an unrelated sending service is insufficient.
	if opts.LinkMismatchEnabled && bodyClaim && !displayNameClaim && !subjectClaim &&
		containsAny(body, []string{"review & sign", "review and sign", "sign the document", "electronic approval"}) &&
		containsAny(body, []string{"signature pending", "electronic signature", "signature platform", "envelope"}) {
		if host := firstMismatchedDirectURLHost(ev, fromDomain, profile); host != "" {
			analysis.Score += 80
			analysis.Signals = append(analysis.Signals, "body claims "+profile.name+" signature workflow with link to unrelated domain "+host)
		}
	}
	if pressureClaim {
		analysis.Score += 80
		analysis.Signals = append(analysis.Signals, "account or payment pressure asks the recipient to update details")
	}
	// A brand mentioned only in ordinary body copy is not an impersonation
	// claim. Newsletters, portfolio summaries, receipts, and integrations often
	// mention other brands and link to unrelated social or app-store domains.
	// Only use link mismatch after an explicit display-name/subject claim or a
	// high-risk body claim containing both pressure and an account-update CTA.
	if opts.LinkMismatchEnabled && (displayNameClaim || subjectClaim || pressureClaim) && !authenticatedNewsletter {
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

func firstMismatchedDirectURLHost(ev *Event, fromDomain string, profile protectedBrandProfile) string {
	if ev == nil {
		return ""
	}
	// Redirect and click-tracking URLs belong to the sender's mail platform,
	// not necessarily to the signature destination claimed in the message.
	direct := *ev
	direct.URLs = nil
	for _, raw := range ev.URLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || strings.HasPrefix(strings.ToLower(parsed.Hostname()), "click.") {
			continue
		}
		direct.URLs = append(direct.URLs, raw)
	}
	return firstMismatchedURLHost(&direct, fromDomain, profile)
}

func firstMismatchedURLHost(ev *Event, fromDomain string, profile protectedBrandProfile) string {
	if ev == nil {
		return ""
	}
	for _, raw := range prioritizedSandboxURLs(ev) {
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

var accountLossPressurePhrases = []string{
	"payment failed", "can't process your payment", "cannot process your payment",
	"payment declined", "billing issue", "account suspended", "account locked",
	"account restricted", "account will be closed", "lose access", "loss of access",
	"subscription will end", "subscription expired", "final reminder", "action required",
	"pending verification", "permanent loss",
}

var updateDetailsCTAPhrases = []string{
	"update details", "update your details", "update payment", "update billing",
	"verify account", "verify your account", "confirm account", "confirm your information",
	"restore access", "reactivate", "sign in", "log in", "login", "click below",
}

type sandboxURLCandidate struct {
	raw   string
	score int
	order int
}

func prioritizedSandboxURLs(ev *Event) []string {
	if ev == nil {
		return nil
	}
	candidates := make([]sandboxURLCandidate, 0, len(ev.URLs))
	seen := map[string]struct{}{}
	for order, raw := range ev.URLs {
		raw = strings.TrimSpace(raw)
		if !isHTTPURL(raw) {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		normalized := strings.ToLower(parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath())
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		candidates = append(candidates, sandboxURLCandidate{
			raw: raw, score: sandboxURLPriority(parsed, ev), order: order,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].order < candidates[j].order
		}
		return candidates[i].score > candidates[j].score
	})
	actionable := candidates[:0]
	for _, candidate := range candidates {
		if candidate.score > 0 {
			actionable = append(actionable, candidate)
		}
	}
	candidates = actionable
	if len(candidates) > maxURLScans {
		candidates = candidates[:maxURLScans]
	}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.raw)
	}
	return out
}

func sandboxURLPriority(parsed *url.URL, ev *Event) int {
	value := strings.ToLower(parsed.Hostname() + " " + parsed.EscapedPath() + " " + parsed.RawQuery)
	score := 10
	if containsAny(value, []string{
		"login", "log-in", "signin", "sign-in", "account", "verify", "verification",
		"secure", "security", "auth", "password", "billing", "payment", "update",
		"confirm", "reactivate", "restore", "reset", "checkout",
	}) {
		score += 100
	}
	if containsAny(value, []string{"click", "redirect", "link", "/ls/", "/r/"}) {
		score += 35
	}
	path := strings.ToLower(parsed.EscapedPath())
	if containsAny(path, []string{
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".js",
		".woff", ".woff2", ".ttf", ".mp4", ".pdf",
	}) {
		score -= 200
	}
	if containsAny(value, []string{"pixel", "tracking", "track/open", "open.gif", "beacon", "spacer"}) {
		score -= 150
	}
	if containsAny(value, []string{"unsubscribe", "optout", "opt-out", "preferences"}) ||
		strings.Contains(strings.ToLower(ev.ListUnsubscribe), parsed.Hostname()) {
		score -= 250
	}
	return score
}

func isAuthenticatedProtectedBrandSender(ev *Event) bool {
	return isAuthenticatedProtectedBrandSenderWithProfiles(ev, protectedBrandProfiles)
}

func isAuthenticatedProtectedBrandSenderWithProfiles(ev *Event, profiles []protectedBrandProfile) bool {
	if ev == nil || !authSignals(ev).DMARCPass {
		return false
	}
	fromDomain := emailDomain(ev.From)
	if fromDomain == "" {
		return false
	}
	for _, profile := range profiles {
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
