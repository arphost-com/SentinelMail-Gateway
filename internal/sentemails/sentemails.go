// Package sentemails records application-originated email sends and exposes
// admin-scoped reporting views.
package sentemails

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	stdmail "net/mail"
	"net/netip"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/httpapi/httpx"
	"github.com/arphost/sentinelmail-gateway/internal/tenant"
)

type Email struct {
	ID                uuid.UUID       `json:"id"`
	OrganizationID    uuid.UUID       `json:"organization_id"`
	DomainID          *uuid.UUID      `json:"domain_id,omitempty"`
	MailLogID         *uuid.UUID      `json:"mail_log_id,omitempty"`
	QuarantineEntryID *uuid.UUID      `json:"quarantine_entry_id,omitempty"`
	Kind              string          `json:"kind"`
	FromAddr          string          `json:"from_addr"`
	ToAddrs           []string        `json:"to_addrs"`
	Subject           *string         `json:"subject,omitempty"`
	RelayHost         *string         `json:"relay_host,omitempty"`
	RelayPort         *int            `json:"relay_port,omitempty"`
	Status            string          `json:"status"`
	Error             *string         `json:"error,omitempty"`
	RawSize           int             `json:"raw_size"`
	RawExcerpt        string          `json:"raw_excerpt,omitempty"`
	RawTruncated      bool            `json:"raw_truncated,omitempty"`
	Metadata          json.RawMessage `json:"metadata,omitempty"`
	SentAt            *time.Time      `json:"sent_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type Record struct {
	OrganizationID    uuid.UUID
	DomainID          *uuid.UUID
	MailLogID         *uuid.UUID
	QuarantineEntryID *uuid.UUID
	Kind              string
	FromAddr          string
	ToAddrs           []string
	Subject           string
	RelayHost         string
	RelayPort         int
	Raw               []byte
	Metadata          map[string]any
}

const (
	maxRawExcerptBytes = 256 << 10
	maxStoredRawBytes  = 16 << 20
)

const cols = `id, organization_id, domain_id, mail_log_id, quarantine_entry_id,
              kind, from_addr, to_addrs, subject, relay_host, relay_port,
              status::text, error, octet_length(raw_message), metadata,
              sent_at, created_at, updated_at`

type Handler struct{ DB *pgxpool.Pool }

func Mount(r chi.Router, db *pgxpool.Pool) {
	h := &Handler{DB: db}
	r.Get("/", h.list)
	r.Get("/{id}", h.read)
	r.Get("/{id}/raw", h.raw)
	r.Post("/{id}/resend", h.resend)
}

// Send wraps an SMTP send with best-effort durable logging. Logging failures do
// not mask the send result, because callers need the real SMTP outcome.
func Send(ctx context.Context, db *pgxpool.Pool, rec Record, send func() error) error {
	id, logErr := InsertPending(ctx, db, rec)
	err := send()
	if logErr == nil {
		status := "sent"
		errText := ""
		if err != nil {
			status = "failed"
			errText = err.Error()
		}
		_ = Finish(ctx, db, id, status, errText)
	}
	return err
}

func InsertPending(ctx context.Context, db *pgxpool.Pool, rec Record) (uuid.UUID, error) {
	if rec.OrganizationID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("organization_id is required")
	}
	rec.Kind = strings.TrimSpace(rec.Kind)
	if rec.Kind == "" {
		return uuid.Nil, fmt.Errorf("kind is required")
	}
	rec.FromAddr = normalizeAddress(rec.FromAddr)
	rec.ToAddrs = normalizeAddresses(rec.ToAddrs)
	if len(rec.ToAddrs) == 0 {
		return uuid.Nil, fmt.Errorf("at least one recipient is required")
	}
	if len(rec.Raw) == 0 {
		return uuid.Nil, fmt.Errorf("raw message is required")
	}
	if len(rec.Raw) > maxStoredRawBytes {
		return uuid.Nil, fmt.Errorf("raw message is too large")
	}
	metadata := []byte("{}")
	if len(rec.Metadata) > 0 {
		if raw, err := json.Marshal(rec.Metadata); err == nil {
			metadata = raw
		}
	}
	var id uuid.UUID
	err := db.QueryRow(ctx, `
		INSERT INTO sent_emails
		  (organization_id, domain_id, mail_log_id, quarantine_entry_id,
		   kind, from_addr, to_addrs, subject, relay_host, relay_port, raw_message, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,''), NULLIF($9,''), NULLIF($10,0), $11, $12::jsonb)
		RETURNING id
	`, rec.OrganizationID, rec.DomainID, rec.MailLogID, rec.QuarantineEntryID,
		rec.Kind, rec.FromAddr, rec.ToAddrs, sanitizeHeader(rec.Subject),
		strings.TrimSpace(rec.RelayHost), rec.RelayPort, rec.Raw, metadata).Scan(&id)
	return id, err
}

func Finish(ctx context.Context, db *pgxpool.Pool, id uuid.UUID, status, errText string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "sent" && status != "failed" {
		status = "failed"
	}
	_, err := db.Exec(ctx, `
		UPDATE sent_emails
		   SET status = $2::sent_email_status,
		       error = NULLIF($3, ''),
		       sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END,
		       updated_at = now()
		 WHERE id = $1
	`, id, status, trimError(errText))
	return err
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
	if kind := strings.TrimSpace(q.Get("kind")); kind != "" {
		args = append(args, kind)
		clauses = append(clauses, fmt.Sprintf("kind = $%d", len(args)))
	}
	if status := strings.TrimSpace(q.Get("status")); status != "" {
		args = append(args, status)
		clauses = append(clauses, fmt.Sprintf("status = $%d::sent_email_status", len(args)))
	}
	if to := strings.TrimSpace(q.Get("to")); to != "" {
		args = append(args, "%"+strings.ToLower(to)+"%")
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(to_addrs) AS t WHERE lower(t) LIKE $%d)", len(args)))
	}
	if from := strings.TrimSpace(q.Get("from")); from != "" {
		args = append(args, "%"+strings.ToLower(from)+"%")
		clauses = append(clauses, fmt.Sprintf("lower(from_addr) LIKE $%d", len(args)))
	}
	if search := strings.TrimSpace(q.Get("q")); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		clauses = append(clauses, fmt.Sprintf(`(
			lower(from_addr) LIKE $%d
			OR EXISTS (SELECT 1 FROM unnest(to_addrs) AS t WHERE lower(t) LIKE $%d)
			OR lower(COALESCE(subject, '')) LIKE $%d
			OR lower(kind) LIKE $%d
			OR lower(COALESCE(error, '')) LIKE $%d
		)`, len(args), len(args), len(args), len(args), len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	var total int
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	if err := h.DB.QueryRow(r.Context(), `SELECT count(*) FROM sent_emails`+where, args...).Scan(&total); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "count")
		return
	}
	args = append(args, page.Limit, page.Offset)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sql := fmt.Sprintf(`SELECT `+cols+` FROM sent_emails%s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args))
	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []Email{}
	for rows.Next() {
		var item Email
		if err := scan(rows, &item); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, item)
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.List[Email]{Items: out, Total: total, Limit: page.Limit, Offset: page.Offset})
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	item, ok := h.readAllowed(w, r, id, true)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, item)
}

func (h *Handler) raw(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	item, ok := h.readAllowed(w, r, id, false)
	if !ok {
		return
	}
	var raw []byte
	if err := h.DB.QueryRow(r.Context(), `SELECT raw_message FROM sent_emails WHERE id = $1`, id).Scan(&raw); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	filename := "sentinelmail-sent-" + item.ID.String() + ".eml"
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	http.ServeContent(w, r, filename, time.Time{}, bytes.NewReader(raw))
}

func (h *Handler) resend(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.ParseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	item, ok := h.readAllowed(w, r, id, false)
	if !ok {
		return
	}
	if item.RelayHost == nil || strings.TrimSpace(*item.RelayHost) == "" {
		httpx.WriteError(w, http.StatusConflict, "original email has no relay host recorded")
		return
	}
	var raw []byte
	if err := h.DB.QueryRow(r.Context(), `SELECT raw_message FROM sent_emails WHERE id = $1`, id).Scan(&raw); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	port := 25
	if item.RelayPort != nil && *item.RelayPort > 0 {
		port = *item.RelayPort
	}
	subject := ""
	if item.Subject != nil {
		subject = *item.Subject
	}
	metadata := resendMetadata(item.Metadata, item.ID)
	rec := Record{
		OrganizationID:    item.OrganizationID,
		DomainID:          item.DomainID,
		MailLogID:         item.MailLogID,
		QuarantineEntryID: item.QuarantineEntryID,
		Kind:              item.Kind,
		FromAddr:          item.FromAddr,
		ToAddrs:           item.ToAddrs,
		Subject:           subject,
		RelayHost:         *item.RelayHost,
		RelayPort:         port,
		Raw:               raw,
		Metadata:          metadata,
	}
	newID, err := InsertPending(r.Context(), h.DB, rec)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "resend log insert failed: "+err.Error())
		return
	}
	sendErr := sendRelayMail(*item.RelayHost, strconv.Itoa(port), item.FromAddr, item.ToAddrs, raw)
	status := "sent"
	errText := ""
	if sendErr != nil {
		status = "failed"
		errText = sendErr.Error()
	}
	_ = Finish(r.Context(), h.DB, newID, status, errText)
	out, ok := h.readAllowed(w, r, newID, true)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handler) readAllowed(w http.ResponseWriter, r *http.Request, id uuid.UUID, withExcerpt bool) (Email, bool) {
	scope, ident, err := tenant.FromContext(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "scope")
		return Email{}, false
	}
	if ident.Role == "org_user" {
		httpx.WriteError(w, http.StatusForbidden, "admin role required")
		return Email{}, false
	}
	query := `SELECT ` + cols
	if withExcerpt {
		query += `, substring(raw_message from 1 for $2)`
	}
	query += ` FROM sent_emails WHERE id = $1`
	var item Email
	var raw []byte
	var scanErr error
	if withExcerpt {
		scanErr = scanWithExcerpt(h.DB.QueryRow(r.Context(), query, id, maxRawExcerptBytes), &item, &raw)
	} else {
		scanErr = scan(h.DB.QueryRow(r.Context(), query, id), &item)
	}
	if scanErr != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Email{}, false
	}
	if !scope.Allows(item.OrganizationID) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return Email{}, false
	}
	if withExcerpt {
		item.RawExcerpt = string(raw)
		item.RawTruncated = item.RawSize > len(raw)
	}
	return item, true
}

func scan(row pgx.Row, e *Email) error {
	return row.Scan(&e.ID, &e.OrganizationID, &e.DomainID, &e.MailLogID, &e.QuarantineEntryID,
		&e.Kind, &e.FromAddr, &e.ToAddrs, &e.Subject, &e.RelayHost, &e.RelayPort,
		&e.Status, &e.Error, &e.RawSize, &e.Metadata, &e.SentAt, &e.CreatedAt, &e.UpdatedAt)
}

func scanWithExcerpt(row pgx.Row, e *Email, raw *[]byte) error {
	return row.Scan(&e.ID, &e.OrganizationID, &e.DomainID, &e.MailLogID, &e.QuarantineEntryID,
		&e.Kind, &e.FromAddr, &e.ToAddrs, &e.Subject, &e.RelayHost, &e.RelayPort,
		&e.Status, &e.Error, &e.RawSize, &e.Metadata, &e.SentAt, &e.CreatedAt, &e.UpdatedAt, raw)
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := stdmail.ParseAddress(value); err == nil && parsed.Address != "" {
		return strings.ToLower(strings.TrimSpace(parsed.Address))
	}
	return strings.ToLower(value)
}

func normalizeAddresses(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = normalizeAddress(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func sanitizeHeader(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 255 {
		return value[:255]
	}
	return value
}

func trimError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1000 {
		return value[:1000]
	}
	return value
}

func resendMetadata(raw json.RawMessage, sourceID uuid.UUID) map[string]any {
	out := map[string]any{
		"resent":               true,
		"resent_from_email_id": sourceID.String(),
	}
	var existing map[string]any
	if len(raw) > 0 && json.Unmarshal(raw, &existing) == nil {
		for key, value := range existing {
			if _, reserved := out[key]; reserved {
				continue
			}
			out[key] = value
		}
	}
	return out
}

func sendRelayMail(host, port, from string, to []string, raw []byte) error {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return fmt.Errorf("relay host is required")
	}
	if port == "" {
		port = "25"
	}
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
	smtpData, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := smtpData.Write(raw); err != nil {
		_ = smtpData.Close()
		return err
	}
	if err := smtpData.Close(); err != nil {
		return err
	}
	return c.Quit()
}
