// Package notifications sends user-facing security notifications.
package notifications

import (
	"context"
	"fmt"
	"html"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/sentemails"
)

type phishingMessage struct {
	MailLogID      uuid.UUID
	OrganizationID uuid.UUID
	DomainID       *uuid.UUID
	FromAddr       string
	ToAddrs        []string
	Subject        string
	ClientIP       string
	Reason         string
	ReceivedAt     time.Time
}

type alertUser struct {
	ID        uuid.UUID
	Email     string
	Frequency string
	LastSent  *time.Time
}

// SendPhishingAlertForMailLog sends recipient alerts for a mail log that has
// been quarantined as phishing. It is best-effort: failures are returned so
// callers can log/surface them, but mail flow must never depend on it.
func SendPhishingAlertForMailLog(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID) error {
	msg, err := loadPhishingMessage(ctx, db, mailLogID)
	if err != nil {
		return err
	}
	users, err := alertUsers(ctx, db, msg)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}

	var firstErr error
	for _, u := range users {
		if !shouldSend(u.Frequency, u.LastSent, time.Now()) {
			continue
		}
		if err := sendOne(ctx, db, msg, u); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := db.Exec(ctx, `
			UPDATE users
			   SET phishing_alert_last_sent_at = now()
			 WHERE id = $1
		`, u.ID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func SendChallengeResponseAlertForMailLog(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID) error {
	msg, err := loadPhishingMessage(ctx, db, mailLogID)
	if err != nil {
		return err
	}
	users, err := challengeUsers(ctx, db, msg)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}
	var firstErr error
	for _, u := range users {
		if err := sendChallengeOne(ctx, db, msg, u); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func loadPhishingMessage(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID) (*phishingMessage, error) {
	var msg phishingMessage
	err := db.QueryRow(ctx, `
		SELECT id, organization_id, domain_id, COALESCE(from_addr, ''),
		       to_addrs, COALESCE(subject, ''), COALESCE(client_ip::text, ''),
		       COALESCE(reason, ''), received_at
		  FROM mail_logs
		 WHERE id = $1
		   AND disposition = 'quarantined'
	`, mailLogID).Scan(&msg.MailLogID, &msg.OrganizationID, &msg.DomainID, &msg.FromAddr,
		&msg.ToAddrs, &msg.Subject, &msg.ClientIP, &msg.Reason, &msg.ReceivedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &msg, nil
}

func alertUsers(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage) ([]alertUser, error) {
	if msg == nil || len(msg.ToAddrs) == 0 {
		return nil, nil
	}
	rows, err := db.Query(ctx, `
		SELECT id, email::text, phishing_alert_frequency, phishing_alert_last_sent_at
		  FROM users
		 WHERE organization_id = $1
		   AND is_active = true
		   AND phishing_alert_frequency <> 'off'
		   AND lower(email::text) = ANY($2)
	`, msg.OrganizationID, lowerAddrs(msg.ToAddrs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alertUser
	for rows.Next() {
		var u alertUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Frequency, &u.LastSent); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func challengeUsers(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage) ([]alertUser, error) {
	if msg == nil || len(msg.ToAddrs) == 0 {
		return nil, nil
	}
	rows, err := db.Query(ctx, `
		SELECT id, email::text, phishing_alert_frequency, phishing_alert_last_sent_at
		  FROM users
		 WHERE organization_id = $1
		   AND is_active = true
		   AND lower(email::text) = ANY($2)
	`, msg.OrganizationID, lowerAddrs(msg.ToAddrs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alertUser
	for rows.Next() {
		var u alertUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Frequency, &u.LastSent); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func lowerAddrs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func shouldSend(frequency string, lastSent *time.Time, now time.Time) bool {
	switch frequency {
	case "immediate":
		return true
	case "daily":
		return lastSent == nil || now.Sub(*lastSent) >= 24*time.Hour
	case "weekly", "":
		return lastSent == nil || now.Sub(*lastSent) >= 7*24*time.Hour
	default:
		return false
	}
}

func sendOne(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage, u alertUser) error {
	host, port, err := gatewayForRecipient(ctx, db, msg.OrganizationID, u.Email)
	if err != nil {
		return err
	}
	from, err := alertFrom(ctx, db, msg.OrganizationID)
	if err != nil {
		return err
	}
	raw, err := buildPhishingAlertEmail(ctx, db, from, u.Email, msg)
	if err != nil {
		return err
	}
	subject := "SentinelMail quarantined a phishing email"
	return sentemails.Send(ctx, db, sentemails.Record{
		OrganizationID: msg.OrganizationID,
		DomainID:       msg.DomainID,
		MailLogID:      &msg.MailLogID,
		Kind:           "phishing_alert",
		FromAddr:       from.Address,
		ToAddrs:        []string{u.Email},
		Subject:        subject,
		RelayHost:      host,
		RelayPort:      port,
		Raw:            raw,
		Metadata:       map[string]any{"alert_user_id": u.ID.String()},
	}, func() error {
		return smtp.SendMail(net.JoinHostPort(host, fmt.Sprint(port)), nil, from.Address, []string{u.Email}, raw)
	})
}

func sendChallengeOne(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage, u alertUser) error {
	host, port, err := gatewayForRecipient(ctx, db, msg.OrganizationID, u.Email)
	if err != nil {
		return err
	}
	from, err := alertFrom(ctx, db, msg.OrganizationID)
	if err != nil {
		return err
	}
	raw, err := buildChallengeResponseEmail(ctx, db, from, u.Email, msg)
	if err != nil {
		return err
	}
	subject := "SentinelMail is holding mail for your approval"
	return sentemails.Send(ctx, db, sentemails.Record{
		OrganizationID: msg.OrganizationID,
		DomainID:       msg.DomainID,
		MailLogID:      &msg.MailLogID,
		Kind:           "challenge_response_alert",
		FromAddr:       from.Address,
		ToAddrs:        []string{u.Email},
		Subject:        subject,
		RelayHost:      host,
		RelayPort:      port,
		Raw:            raw,
		Metadata:       map[string]any{"alert_user_id": u.ID.String()},
	}, func() error {
		return smtp.SendMail(net.JoinHostPort(host, fmt.Sprint(port)), nil, from.Address, []string{u.Email}, raw)
	})
}

func gatewayForRecipient(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, recipient string) (string, int, error) {
	domain := primaryDomain(recipient)
	if domain == "" {
		return "", 0, fmt.Errorf("recipient has no domain")
	}
	var host string
	var port int
	err := db.QueryRow(ctx, `
		SELECT g.host, g.port
		  FROM gateways g
		  JOIN domains d ON d.id = g.domain_id
		 WHERE d.organization_id = $1
		   AND lower(d.name::text) = $2
		   AND d.is_active = true
		   AND g.is_active = true
		 ORDER BY g.priority ASC, g.created_at ASC
		 LIMIT 1
	`, orgID, domain).Scan(&host, &port)
	if err != nil {
		return "", 0, err
	}
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return "", 0, fmt.Errorf("invalid downstream gateway")
	}
	return host, port, nil
}

func alertFrom(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID) (*stdmail.Address, error) {
	name := lookupSetting(ctx, db, &orgID, "brand.name", "")
	if name == "" {
		name = lookupSetting(ctx, db, nil, "ui.brand_name", "SentinelMail Gateway")
	}
	addr := lookupSetting(ctx, db, &orgID, "brand.support_email", "")
	if addr == "" {
		host := lookupSetting(ctx, db, nil, "mail.hostname", "sentinelmail.local")
		addr = "no-reply@" + primaryDomain("x@"+host)
	}
	parsed, err := stdmail.ParseAddress(addr)
	if err != nil || parsed.Address == "" {
		parsed = &stdmail.Address{Address: "no-reply@sentinelmail.local"}
	}
	parsed.Name = name
	return parsed, nil
}

func lookupSetting(ctx context.Context, db *pgxpool.Pool, orgID *uuid.UUID, key, fallback string) string {
	var value string
	var orgArg any
	if orgID != nil {
		orgArg = *orgID
	}
	err := db.QueryRow(ctx, `
		SELECT trim(both '"' from value::text)
		  FROM system_settings
		 WHERE key = $1
		   AND (($2::uuid IS NULL AND organization_id IS NULL) OR organization_id = $2)
		 ORDER BY organization_id NULLS LAST
		 LIMIT 1
	`, key, orgArg).Scan(&value)
	if err != nil || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func buildPhishingAlertEmail(ctx context.Context, db *pgxpool.Pool, from *stdmail.Address, to string, msg *phishingMessage) ([]byte, error) {
	link := quarantineURL(ctx, db, msg, to)
	subject := "SentinelMail quarantined a phishing email"
	text := textAlert(to, msg, link)
	htmlBody := htmlAlert(to, msg, link)
	boundary := "smg-phishing-alert-boundary"
	headers := []string{
		"From: " + from.String(),
		"To: " + (&stdmail.Address{Address: to}).String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + boundary + `"`,
	}
	body := strings.Join(headers, "\r\n") + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		text + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		htmlBody + "\r\n\r\n" +
		"--" + boundary + "--\r\n"
	return []byte(body), nil
}

func buildChallengeResponseEmail(ctx context.Context, db *pgxpool.Pool, from *stdmail.Address, to string, msg *phishingMessage) ([]byte, error) {
	link := quarantineURL(ctx, db, msg, to)
	subject := "SentinelMail is holding mail for your approval"
	text := textChallengeAlert(to, msg, link)
	htmlBody := htmlChallengeAlert(to, msg, link)
	boundary := "smg-challenge-response-boundary"
	headers := []string{
		"From: " + from.String(),
		"To: " + (&stdmail.Address{Address: to}).String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + boundary + `"`,
	}
	body := strings.Join(headers, "\r\n") + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		text + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		htmlBody + "\r\n\r\n" +
		"--" + boundary + "--\r\n"
	return []byte(body), nil
}

func textAlert(to string, msg *phishingMessage, link string) string {
	lines := []string{
		"SentinelMail quarantined a phishing email before it reached your mailbox.",
		"",
		"Recipient: " + to,
		"From: " + emptyDash(msg.FromAddr),
		"Subject: " + emptyDash(msg.Subject),
		"Source IP: " + emptyDash(msg.ClientIP),
		"Reason: " + emptyDash(msg.Reason),
	}
	if link != "" {
		lines = append(lines, "", "Review it here: "+link)
	}
	return strings.Join(lines, "\r\n")
}

func textChallengeAlert(to string, msg *phishingMessage, link string) string {
	lines := []string{
		"SentinelMail is holding a message until you approve or deny the sender.",
		"",
		"Recipient: " + to,
		"From: " + emptyDash(msg.FromAddr),
		"Subject: " + emptyDash(msg.Subject),
		"Source IP: " + emptyDash(msg.ClientIP),
	}
	if link != "" {
		lines = append(lines, "", "Review it here: "+link)
	}
	lines = append(lines, "", "Release the message to allow this sender for your mailbox. Block the sender to deny future mail, or delete only this held message.")
	return strings.Join(lines, "\r\n")
}

func htmlAlert(to string, msg *phishingMessage, link string) string {
	button := ""
	if link != "" {
		escapedLink := html.EscapeString(link)
		button = `<tr><td style="padding:24px 0 4px"><a href="` + escapedLink + `" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px">Review quarantine</a></td></tr>`
	}
	return `<!doctype html><html><body style="margin:0;background:#f4f7fb;color:#102033;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;background:#ffffff;border:1px solid #d8e2ef;border-radius:12px;overflow:hidden">
<tr><td style="background:#0f172a;color:#ffffff;padding:22px 26px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd">SentinelMail Gateway</div><h1 style="margin:8px 0 0;font-size:24px;line-height:1.25">Phishing email quarantined</h1></td></tr>
<tr><td style="padding:26px"><p style="margin:0 0 18px;font-size:16px;line-height:1.5">A phishing email was held before it reached your mailbox.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
` + detailRow("Recipient", to) + detailRow("From", emptyDash(msg.FromAddr)) + detailRow("Subject", emptyDash(msg.Subject)) + detailRow("Source IP", emptyDash(msg.ClientIP)) + detailRow("Reason", emptyDash(msg.Reason)) + `
</table><table role="presentation" cellspacing="0" cellpadding="0">` + button + `</table>
<p style="margin:18px 0 0;color:#64748b;font-size:13px;line-height:1.5">Do not click links in the original message. Review or delete it from SentinelMail quarantine.</p></td></tr>
</table></td></tr></table></body></html>`
}

func htmlChallengeAlert(to string, msg *phishingMessage, link string) string {
	button := ""
	if link != "" {
		escapedLink := html.EscapeString(link)
		button = `<tr><td style="padding:24px 0 4px"><a href="` + escapedLink + `" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px">Review sender</a></td></tr>`
	}
	return `<!doctype html><html><body style="margin:0;background:#f4f7fb;color:#102033;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;background:#ffffff;border:1px solid #d8e2ef;border-radius:12px;overflow:hidden">
<tr><td style="background:#134e4a;color:#ffffff;padding:22px 26px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#99f6e4">SentinelMail Gateway</div><h1 style="margin:8px 0 0;font-size:24px;line-height:1.25">Sender approval required</h1></td></tr>
<tr><td style="padding:26px"><p style="margin:0 0 18px;font-size:16px;line-height:1.5">A message is being held until you decide whether this sender is allowed to reach your mailbox.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
` + detailRow("Recipient", to) + detailRow("From", emptyDash(msg.FromAddr)) + detailRow("Subject", emptyDash(msg.Subject)) + detailRow("Source IP", emptyDash(msg.ClientIP)) + `
</table><table role="presentation" cellspacing="0" cellpadding="0">` + button + `</table>
<p style="margin:18px 0 0;color:#64748b;font-size:13px;line-height:1.5">Release the message to allow this sender for your mailbox. Block the sender to deny future mail, or delete only this held message.</p></td></tr>
</table></td></tr></table></body></html>`
}

func detailRow(label, value string) string {
	return `<tr><td style="padding:10px 14px;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:13px;width:110px">` + html.EscapeString(label) + `</td><td style="padding:10px 14px;border-bottom:1px solid #e2e8f0;font-size:14px;color:#0f172a">` + html.EscapeString(value) + `</td></tr>`
}

func quarantineURL(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage, recipient string) string {
	base := lookupSetting(ctx, db, nil, "link_rewrite.public_base_url", "")
	if base == "" {
		host := lookupSetting(ctx, db, nil, "tls.hostname", "")
		if host != "" {
			base = "https://" + host
		}
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	u.Path = "/quarantine"
	if msg != nil {
		if id := quarantineEntryID(ctx, db, msg.MailLogID, recipient); id != nil {
			q := u.Query()
			q.Set("id", id.String())
			u.RawQuery = q.Encode()
		}
	}
	return u.String()
}

func quarantineEntryID(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID, recipient string) *uuid.UUID {
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	if mailLogID == uuid.Nil || recipient == "" {
		return nil
	}
	var id uuid.UUID
	err := db.QueryRow(ctx, `
		SELECT id
		  FROM quarantine_entries
		 WHERE mail_log_id = $1
		   AND lower(to_addr) = $2
		 ORDER BY received_at DESC
		 LIMIT 1
	`, mailLogID, recipient).Scan(&id)
	if err != nil {
		return nil
	}
	return &id
}

func emptyDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func primaryDomain(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return strings.ToLower(strings.TrimSpace(addr))
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}
