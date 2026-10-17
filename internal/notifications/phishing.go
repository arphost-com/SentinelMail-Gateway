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
	ThreatClass    string
	ReceivedAt     time.Time
}

type alertUser struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	Email                string
	Role                 string
	Frequency            string
	LastSent             *time.Time
	ChallengeFrequency   string
	ChallengeLastAttempt *time.Time
	ChallengeLastSent    *time.Time
}

type pendingApproval struct {
	ToAddr     string
	FromAddr   string
	Subject    string
	ReceivedAt time.Time
}

// SendPhishingAlertForMailLog sends immediate per-message recipient alerts
// for a quarantined mail log. Only users on the immediate cadence are
// notified here; daily and weekly users receive the scheduled quarantine
// digest. It is best-effort: failures are returned so callers can
// log/surface them, but mail flow must never depend on it.
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
		if u.Frequency != "immediate" {
			// Daily and weekly users get the scheduled quarantine digest
			// from RunQuarantineAlertDigests instead of per-message alerts,
			// so a single early message no longer consumes the whole window.
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
		if _, err := sendChallengeOne(ctx, db, msg, u); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RunChallengeResponseDigests sends due aggregate approval reminders and
// retries failed attempts after a short backoff. It is safe to call from a
// periodic background loop; SMTP failures remain observable in sent_emails and
// never block inbound mail handling.
func RunChallengeResponseDigests(ctx context.Context, db *pgxpool.Pool) (int, error) {
	users, err := challengeDigestCandidates(ctx, db)
	if err != nil {
		return 0, err
	}
	sent := 0
	var firstErr error
	for _, u := range users {
		msg, err := latestPendingMessage(ctx, db, u)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if msg == nil {
			continue
		}
		didSend, err := sendChallengeOne(ctx, db, msg, u)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if didSend {
			sent++
		}
	}
	return sent, firstErr
}

func loadPhishingMessage(ctx context.Context, db *pgxpool.Pool, mailLogID uuid.UUID) (*phishingMessage, error) {
	var msg phishingMessage
	err := db.QueryRow(ctx, `
		SELECT ml.id, ml.organization_id, ml.domain_id, COALESCE(ml.from_addr, ''),
		       ml.to_addrs, COALESCE(ml.subject, ''), COALESCE(ml.client_ip::text, ''),
		       COALESCE(ml.reason, ''), ml.received_at,
		       COALESCE((SELECT qe.threat_class
		                   FROM quarantine_entries qe
		                  WHERE qe.mail_log_id = ml.id
		               ORDER BY qe.received_at DESC
		                  LIMIT 1), '')
		  FROM mail_logs ml
		 WHERE ml.id = $1
		   AND ml.disposition = 'quarantined'
	`, mailLogID).Scan(&msg.MailLogID, &msg.OrganizationID, &msg.DomainID, &msg.FromAddr,
		&msg.ToAddrs, &msg.Subject, &msg.ClientIP, &msg.Reason, &msg.ReceivedAt, &msg.ThreatClass)
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
		SELECT id, email::text, role::text, phishing_alert_frequency, phishing_alert_last_sent_at
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
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.Frequency, &u.LastSent); err != nil {
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
		SELECT id, organization_id, email::text, role::text, phishing_alert_frequency, phishing_alert_last_sent_at,
		       challenge_response_alert_frequency, challenge_response_alert_last_attempt_at,
		       challenge_response_alert_last_sent_at
		  FROM users
		 WHERE organization_id = $1
		   AND is_active = true
		   AND (lower(email::text) = ANY($2) OR role = 'org_admin'::user_role)
	`, msg.OrganizationID, lowerAddrs(msg.ToAddrs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alertUser
	for rows.Next() {
		var u alertUser
		if err := rows.Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.Frequency, &u.LastSent,
			&u.ChallengeFrequency, &u.ChallengeLastAttempt, &u.ChallengeLastSent); err != nil {
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
	subject, kind := alertSubjectKind(msg.ThreatClass)
	raw, err := buildPhishingAlertEmail(ctx, db, from, u.Email, msg, subject)
	if err != nil {
		return err
	}
	return sentemails.Send(ctx, db, sentemails.Record{
		OrganizationID: msg.OrganizationID,
		DomainID:       msg.DomainID,
		MailLogID:      &msg.MailLogID,
		Kind:           kind,
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

func sendChallengeOne(ctx context.Context, db *pgxpool.Pool, msg *phishingMessage, u alertUser) (bool, error) {
	now := time.Now()
	if !challengeDigestDue(u.ChallengeFrequency, u.ChallengeLastAttempt, u.ChallengeLastSent, msg.ReceivedAt, now) {
		return false, nil
	}
	claimed, err := claimChallengeDigestAttempt(ctx, db, u.ID, now)
	if err != nil || !claimed {
		return false, err
	}
	pending, err := pendingApprovals(ctx, db, msg.OrganizationID, u)
	if err != nil {
		return false, err
	}
	host, port, err := gatewayForRecipient(ctx, db, msg.OrganizationID, u.Email)
	if err != nil {
		return false, err
	}
	from, err := alertFrom(ctx, db, msg.OrganizationID)
	if err != nil {
		return false, err
	}
	raw, err := buildChallengeResponseEmail(ctx, db, from, u.Email, msg, pending)
	if err != nil {
		return false, err
	}
	subject := "SentinelMail is holding mail for your approval"
	err = sentemails.Send(ctx, db, sentemails.Record{
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
		Metadata: map[string]any{
			"alert_user_id":    u.ID.String(),
			"digest_frequency": u.ChallengeFrequency,
			"pending_count":    len(pending),
		},
	}, func() error {
		return smtp.SendMail(net.JoinHostPort(host, fmt.Sprint(port)), nil, from.Address, []string{u.Email}, raw)
	})
	if err != nil {
		return false, err
	}
	// Record the send time itself. Storing the newest pending message's
	// received time here made hourly and daily digests come due again on the
	// next tick once that message aged past the cadence, which resent the
	// reminder every minute until the message was released or deleted.
	_, err = db.Exec(ctx, `
		UPDATE users
		   SET challenge_response_alert_last_sent_at = $2,
		       challenge_response_alert_last_attempt_at = $2,
		       updated_at = now()
		 WHERE id = $1
	`, u.ID, time.Now())
	return err == nil, err
}

const challengeDigestRetryDelay = 15 * time.Minute

func challengeDigestDue(frequency string, lastAttempt, lastSent *time.Time, newestPending, now time.Time) bool {
	// Back off only an attempt that did not subsequently succeed. A newly held
	// message must still trigger an immediate digest after an earlier success.
	if lastAttempt != nil && (lastSent == nil || lastAttempt.After(*lastSent)) && now.Sub(*lastAttempt) < challengeDigestRetryDelay {
		return false
	}
	switch frequency {
	case "hourly":
		return lastSent == nil || now.Sub(*lastSent) >= time.Hour
	case "daily":
		return lastSent == nil || now.Sub(*lastSent) >= 24*time.Hour
	case "immediate", "":
		return lastSent == nil || newestPending.After(*lastSent)
	default:
		return false
	}
}

func claimChallengeDigestAttempt(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID, now time.Time) (bool, error) {
	var claimed bool
	err := db.QueryRow(ctx, `
		UPDATE users
		   SET challenge_response_alert_last_attempt_at = $2, updated_at = now()
		 WHERE id = $1
		   AND is_active = true
		   AND (challenge_response_alert_last_attempt_at IS NULL
		        OR challenge_response_alert_last_attempt_at <= $2::timestamptz - interval '15 minutes'
		        OR (challenge_response_alert_last_sent_at IS NOT NULL
		            AND challenge_response_alert_last_attempt_at <= challenge_response_alert_last_sent_at))
		RETURNING true
	`, userID, now).Scan(&claimed)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	return claimed, err
}

func challengeDigestCandidates(ctx context.Context, db *pgxpool.Pool) ([]alertUser, error) {
	rows, err := db.Query(ctx, `
		SELECT u.id, u.organization_id, u.email::text, u.role::text,
		       u.phishing_alert_frequency, u.phishing_alert_last_sent_at,
		       u.challenge_response_alert_frequency, u.challenge_response_alert_last_attempt_at,
		       u.challenge_response_alert_last_sent_at
		  FROM users u
		 WHERE u.is_active = true
		   AND u.role IN ('org_user'::user_role, 'org_admin'::user_role)
		   AND EXISTS (
			SELECT 1
			  FROM quarantine_entries qe
			  JOIN mail_logs ml ON ml.id = qe.mail_log_id
			 WHERE qe.organization_id = u.organization_id
			   AND qe.state = 'held'::quarantine_state
			   AND ml.disposition = 'quarantined'::mail_disposition
			   AND lower(COALESCE(ml.reason, '')) = 'pending recipient challenge-response approval'
			   AND (u.role = 'org_admin'::user_role OR lower(qe.to_addr) = lower(u.email::text))
		   )
	 ORDER BY u.organization_id, u.email
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []alertUser{}
	for rows.Next() {
		var u alertUser
		if err := rows.Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.Frequency, &u.LastSent,
			&u.ChallengeFrequency, &u.ChallengeLastAttempt, &u.ChallengeLastSent); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func latestPendingMessage(ctx context.Context, db *pgxpool.Pool, u alertUser) (*phishingMessage, error) {
	clauses := ""
	args := []any{u.OrganizationID}
	if u.Role == "org_user" {
		clauses = " AND lower(qe.to_addr) = lower($2)"
		args = append(args, u.Email)
	}
	var mailLogID uuid.UUID
	err := db.QueryRow(ctx, `
		SELECT ml.id
		  FROM quarantine_entries qe
		  JOIN mail_logs ml ON ml.id = qe.mail_log_id
		 WHERE qe.organization_id = $1
		   AND qe.state = 'held'::quarantine_state
		   AND ml.disposition = 'quarantined'::mail_disposition
		   AND lower(COALESCE(ml.reason, '')) = 'pending recipient challenge-response approval'`+clauses+`
		 ORDER BY qe.received_at DESC
		 LIMIT 1
	`, args...).Scan(&mailLogID)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return loadPhishingMessage(ctx, db, mailLogID)
}

func pendingApprovals(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, u alertUser) ([]pendingApproval, error) {
	clauses := ""
	args := []any{orgID}
	if u.Role == "org_user" {
		clauses = " AND lower(qe.to_addr) = lower($2)"
		args = append(args, u.Email)
	}
	rows, err := db.Query(ctx, `
		SELECT qe.to_addr, COALESCE(qe.from_addr, ''), COALESCE(qe.subject, ''), qe.received_at
		  FROM quarantine_entries qe
		  JOIN mail_logs ml ON ml.id = qe.mail_log_id
		 WHERE qe.organization_id = $1
		   AND qe.state = 'held'::quarantine_state
		   AND ml.disposition = 'quarantined'::mail_disposition
		   AND lower(COALESCE(ml.reason, '')) = 'pending recipient challenge-response approval'`+clauses+`
		 ORDER BY qe.received_at DESC
		 LIMIT 25
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []pendingApproval{}
	for rows.Next() {
		var item pendingApproval
		if err := rows.Scan(&item.ToAddr, &item.FromAddr, &item.Subject, &item.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
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
	addr := lookupSetting(ctx, db, nil, "mail.system_from_address", "")
	if addr == "" {
		addr = lookupSetting(ctx, db, &orgID, "brand.support_email", "")
	}
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

// alertSubjectKind picks the subject line and sent_emails kind for a
// per-message quarantine alert based on the stored threat class.
func alertSubjectKind(threatClass string) (string, string) {
	if threatClass == "PHISHING" {
		return "SentinelMail quarantined a phishing email", "phishing_alert"
	}
	return "SentinelMail quarantined a suspicious email", "quarantine_alert"
}

func buildPhishingAlertEmail(ctx context.Context, db *pgxpool.Pool, from *stdmail.Address, to string, msg *phishingMessage, subject string) ([]byte, error) {
	link := quarantineURL(ctx, db, msg, to)
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

func buildChallengeResponseEmail(ctx context.Context, db *pgxpool.Pool, from *stdmail.Address, to string, msg *phishingMessage, pending []pendingApproval) ([]byte, error) {
	link := quarantineURL(ctx, db, msg, to)
	subject := "SentinelMail is holding mail for your approval"
	text := textChallengeAlert(to, msg, pending, link)
	htmlBody := htmlChallengeAlert(to, msg, pending, link)
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

func alertHeadline(threatClass string) string {
	if threatClass == "PHISHING" {
		return "phishing email"
	}
	return "suspicious email"
}

func alertCategory(threatClass string) string {
	if threatClass == "" {
		return "quarantined"
	}
	return strings.ToLower(strings.ReplaceAll(threatClass, "_", " "))
}

func textAlert(to string, msg *phishingMessage, link string) string {
	lines := []string{
		"SentinelMail quarantined a " + alertHeadline(msg.ThreatClass) + " before it reached your mailbox.",
		"",
		"Recipient: " + to,
		"From: " + emptyDash(msg.FromAddr),
		"Subject: " + emptyDash(msg.Subject),
		"Source IP: " + emptyDash(msg.ClientIP),
		"Category: " + alertCategory(msg.ThreatClass),
		"Reason: " + emptyDash(msg.Reason),
	}
	if link != "" {
		lines = append(lines, "", "Review it here: "+link)
	}
	return strings.Join(lines, "\r\n")
}

func textChallengeAlert(to string, msg *phishingMessage, pending []pendingApproval, link string) string {
	recipients := strings.Join(msg.ToAddrs, ", ")
	lines := []string{
		"SentinelMail is holding a message until you approve or deny the sender.",
		"",
		"Protected recipient: " + recipients,
		"Approval notice sent to: " + to,
		"From: " + emptyDash(msg.FromAddr),
		"Subject: " + emptyDash(msg.Subject),
		"Source IP: " + emptyDash(msg.ClientIP),
	}
	if link != "" {
		lines = append(lines, "", "Review it here: "+link)
	}
	if len(pending) > 0 {
		lines = append(lines, "", fmt.Sprintf("Currently waiting (%d, newest 25 shown):", len(pending)))
		for _, item := range pending {
			lines = append(lines, "- "+item.ReceivedAt.Format("2006-01-02 15:04 MST")+" | "+item.ToAddr+" | "+emptyDash(item.FromAddr)+" | "+emptyDash(item.Subject))
		}
	}
	lines = append(lines, "", "Release the message to allow this sender for that mailbox. Allowed senders must still pass DMARC through aligned SPF or DKIM and have a usable reverse hostname. Block the sender to deny future mail, or delete only this held message.")
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
<tr><td style="background:#0f172a;color:#ffffff;padding:22px 26px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd">SentinelMail Gateway</div><h1 style="margin:8px 0 0;font-size:24px;line-height:1.25">Email quarantined</h1></td></tr>
<tr><td style="padding:26px"><p style="margin:0 0 18px;font-size:16px;line-height:1.5">A ` + alertHeadline(msg.ThreatClass) + ` was held before it reached your mailbox.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
` + detailRow("Recipient", to) + detailRow("From", emptyDash(msg.FromAddr)) + detailRow("Subject", emptyDash(msg.Subject)) + detailRow("Source IP", emptyDash(msg.ClientIP)) + detailRow("Category", alertCategory(msg.ThreatClass)) + detailRow("Reason", emptyDash(msg.Reason)) + `
</table><table role="presentation" cellspacing="0" cellpadding="0">` + button + `</table>
<p style="margin:18px 0 0;color:#64748b;font-size:13px;line-height:1.5">Do not click links in the original message. Review or delete it from SentinelMail quarantine.</p></td></tr>
</table></td></tr></table></body></html>`
}

func htmlChallengeAlert(to string, msg *phishingMessage, pending []pendingApproval, link string) string {
	recipients := strings.Join(msg.ToAddrs, ", ")
	button := ""
	if link != "" {
		escapedLink := html.EscapeString(link)
		button = `<tr><td style="padding:24px 0 4px"><a href="` + escapedLink + `" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px">Review sender</a></td></tr>`
	}
	pendingRows := ""
	for _, item := range pending {
		pendingRows += `<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(item.ReceivedAt.Format("Jan 2 15:04")) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(item.ToAddr) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(emptyDash(item.FromAddr)) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(emptyDash(item.Subject)) + `</td></tr>`
	}
	pendingTable := ""
	if pendingRows != "" {
		pendingTable = `<h2 style="margin:22px 0 8px;font-size:17px">Currently waiting (newest 25)</h2><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:12px"><tr><th align="left">Time</th><th align="left">Recipient</th><th align="left">From</th><th align="left">Subject</th></tr>` + pendingRows + `</table>`
	}
	return `<!doctype html><html><body style="margin:0;background:#f4f7fb;color:#102033;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;background:#ffffff;border:1px solid #d8e2ef;border-radius:12px;overflow:hidden">
<tr><td style="background:#134e4a;color:#ffffff;padding:22px 26px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#99f6e4">SentinelMail Gateway</div><h1 style="margin:8px 0 0;font-size:24px;line-height:1.25">Sender approval required</h1></td></tr>
<tr><td style="padding:26px"><p style="margin:0 0 18px;font-size:16px;line-height:1.5">A message is being held until you decide whether this sender is allowed to reach your mailbox.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
` + detailRow("Protected recipient", recipients) + detailRow("Approval notice", to) + detailRow("From", emptyDash(msg.FromAddr)) + detailRow("Subject", emptyDash(msg.Subject)) + detailRow("Source IP", emptyDash(msg.ClientIP)) + `
</table>` + pendingTable + `<table role="presentation" cellspacing="0" cellpadding="0">` + button + `</table>
<p style="margin:18px 0 0;color:#64748b;font-size:13px;line-height:1.5">Release the message to allow this sender for that mailbox. Allowed senders must still pass DMARC through aligned SPF or DKIM and have a usable reverse hostname. Block the sender to deny future mail, or delete only this held message.</p></td></tr>
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
