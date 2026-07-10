// Package billing implements MVP 3 billing webhook capture.
package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/auth"
	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
)

var providerRe = regexp.MustCompile(`^[a-z0-9_-]{2,32}$`)

type Event struct {
	ID             uuid.UUID       `json:"id"`
	Provider       string          `json:"provider"`
	EventType      *string         `json:"event_type,omitempty"`
	ExternalID     *string         `json:"external_id,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	SignatureValid bool            `json:"signature_valid"`
	ReceivedAt     time.Time       `json:"received_at"`
}

type Handler struct {
	DB     *pgxpool.Pool
	Secret []byte
}

func MountPublic(r chi.Router, db *pgxpool.Pool, secret []byte) {
	h := &Handler{DB: db, Secret: secret}
	r.Post("/webhooks/{provider}", h.webhook)
}

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/events", h.list)
}

func (h *Handler) webhook(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if !providerRe.MatchString(provider) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid provider")
		return
	}
	if len(h.Secret) < 16 {
		httpx.WriteError(w, http.StatusServiceUnavailable, "webhook signing is not configured")
		return
	}
	if !billingWebhooksEnabled(r.Context(), h.DB) {
		httpx.WriteError(w, http.StatusForbidden, "billing webhooks disabled")
		return
	}

	var payload map[string]any
	body, err := readAndDecode(r, w, &payload)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !verifySig(h.Secret, body, r.Header.Get("X-SMG-Signature")) {
		httpx.WriteError(w, http.StatusUnauthorized, "bad signature")
		return
	}

	eventType := stringPtr(payload, "event_type", "event", "type")
	externalID := stringPtr(payload, "id", "event_id", "invoice_id", "service_id")
	var id uuid.UUID
	err = h.DB.QueryRow(r.Context(), `
		INSERT INTO billing_webhook_events (provider, event_type, external_id, payload, signature_valid)
		VALUES ($1, $2, $3, $4::jsonb, true)
		RETURNING id
	`, provider, eventType, externalID, string(body)).Scan(&id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "store failed")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": "accepted"})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ident, ok := auth.IdentityFrom(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "auth")
		return
	}
	if ident.Role != "super_admin" {
		httpx.WriteError(w, http.StatusForbidden, "super_admin required")
		return
	}
	page := httpx.ParsePage(r)
	rows, err := h.DB.Query(r.Context(), `
		SELECT id, provider, event_type, external_id, payload, signature_valid, received_at
		  FROM billing_webhook_events
		 ORDER BY received_at DESC
		 LIMIT $1 OFFSET $2
	`, page.Limit, page.Offset)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "db")
		return
	}
	defer rows.Close()
	items := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Provider, &e.EventType, &e.ExternalID, &e.Payload, &e.SignatureValid, &e.ReceivedAt); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "scan")
			return
		}
		items = append(items, e)
	}
	var total int
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM billing_webhook_events`).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "count")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Event]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func billingWebhooksEnabled(ctx context.Context, db *pgxpool.Pool) bool {
	raw, err := settings.Lookup(ctx, db, "billing.webhooks_enabled")
	if err != nil || len(raw) == 0 {
		return false
	}
	var enabled bool
	return json.Unmarshal(raw, &enabled) == nil && enabled
}

func readAndDecode(r *http.Request, w http.ResponseWriter, dst any) ([]byte, error) {
	bodyReader := http.MaxBytesReader(w, r.Body, httpx.MaxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return nil, err
	}
	return body, nil
}

func verifySig(secret, body []byte, sigHex string) bool {
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func stringPtr(payload map[string]any, keys ...string) *string {
	for _, key := range keys {
		if value, ok := payload[key].(string); ok {
			value = strings.TrimSpace(value)
			if value != "" {
				return &value
			}
		}
	}
	return nil
}

func scan(row pgx.Row, e *Event) error {
	return row.Scan(&e.ID, &e.Provider, &e.EventType, &e.ExternalID, &e.Payload, &e.SignatureValid, &e.ReceivedAt)
}
