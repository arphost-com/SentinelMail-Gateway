package notifications

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/sentemails"
)

// digestItem is one row in a quarantine digest email.
type digestItem struct {
	ReceivedAt  time.Time
	ToAddr      string
	FromAddr    string
	Subject     string
	ThreatClass string
	Tagged      bool
}

const digestItemLimit = 50

// digestLookbackCap bounds how far back a digest reaches when a user has not
// been alerted for a long time, so the queries and the email stay sane.
const digestLookbackCap = 30 * 24 * time.Hour

// RunQuarantineAlertDigests sends due digest emails to users whose
// phishing_alert_frequency is daily or weekly. Each digest lists everything
// held in quarantine or delivered tagged as spam since the user's previous
// alert. Users on immediate frequency are alerted per message at ingest and
// are not handled here. Safe to call from a periodic background loop.
func RunQuarantineAlertDigests(ctx context.Context, db *pgxpool.Pool) (int, error) {
	users, err := quarantineDigestCandidates(ctx, db)
	if err != nil {
		return 0, err
	}
	sent := 0
	var firstErr error
	now := time.Now()
	for _, u := range users {
		if !shouldSend(u.Frequency, u.LastSent, now) {
			continue
		}
		since := digestSince(u.Frequency, u.LastSent, now)
		items, total, err := digestItems(ctx, db, u, since)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if total == 0 {
			continue
		}
		if err := sendQuarantineDigest(ctx, db, u, items, total, since); err != nil {
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
		sent++
	}
	return sent, firstErr
}

// digestSince picks the start of the digest window. It prefers the moment of
// the previous alert so nothing between two digests is skipped, falls back to
// one cadence window for first-time digests, and never reaches back further
// than digestLookbackCap.
func digestSince(frequency string, lastSent *time.Time, now time.Time) time.Time {
	window := 7 * 24 * time.Hour
	if frequency == "daily" {
		window = 24 * time.Hour
	}
	since := now.Add(-window)
	if lastSent != nil {
		since = *lastSent
	}
	if floor := now.Add(-digestLookbackCap); since.Before(floor) {
		since = floor
	}
	return since
}

func quarantineDigestCandidates(ctx context.Context, db *pgxpool.Pool) ([]alertUser, error) {
	rows, err := db.Query(ctx, `
		SELECT id, organization_id, email::text, role::text,
		       phishing_alert_frequency, phishing_alert_last_sent_at
		  FROM users
		 WHERE is_active = true
		   AND phishing_alert_frequency IN ('daily', 'weekly')
	 ORDER BY organization_id, email
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []alertUser{}
	for rows.Next() {
		var u alertUser
		if err := rows.Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.Frequency, &u.LastSent); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// digestItems returns up to digestItemLimit of the newest quarantined or
// spam-tagged messages for the user since the given time, plus the total
// count. org_user sees only their own mailbox; admin roles see their whole
// organization.
func digestItems(ctx context.Context, db *pgxpool.Pool, u alertUser, since time.Time) ([]digestItem, int, error) {
	ownOnly := u.Role == "org_user"

	heldClause := ""
	heldArgs := []any{u.OrganizationID, since}
	if ownOnly {
		heldClause = " AND lower(qe.to_addr) = lower($3)"
		heldArgs = append(heldArgs, u.Email)
	}
	items := []digestItem{}
	total := 0

	var heldCount int
	if err := db.QueryRow(ctx, `
		SELECT count(*)
		  FROM quarantine_entries qe
		  JOIN mail_logs ml ON ml.id = qe.mail_log_id
		 WHERE qe.organization_id = $1
		   AND qe.state = 'held'::quarantine_state
		   AND qe.received_at > $2
		   AND lower(COALESCE(ml.reason, '')) <> 'pending recipient challenge-response approval'`+heldClause,
		heldArgs...).Scan(&heldCount); err != nil {
		return nil, 0, err
	}
	total += heldCount

	rows, err := db.Query(ctx, `
		SELECT qe.received_at, qe.to_addr, COALESCE(qe.from_addr, ''),
		       COALESCE(qe.subject, ''), COALESCE(qe.threat_class, '')
		  FROM quarantine_entries qe
		  JOIN mail_logs ml ON ml.id = qe.mail_log_id
		 WHERE qe.organization_id = $1
		   AND qe.state = 'held'::quarantine_state
		   AND qe.received_at > $2
		   AND lower(COALESCE(ml.reason, '')) <> 'pending recipient challenge-response approval'`+heldClause+`
	 ORDER BY qe.received_at DESC
		 LIMIT `+fmt.Sprint(digestItemLimit), heldArgs...)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var item digestItem
		if err := rows.Scan(&item.ReceivedAt, &item.ToAddr, &item.FromAddr, &item.Subject, &item.ThreatClass); err != nil {
			rows.Close()
			return nil, 0, err
		}
		items = append(items, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	taggedClause := ""
	taggedArgs := []any{u.OrganizationID, since}
	if ownOnly {
		taggedClause = " AND EXISTS (SELECT 1 FROM unnest(ml.to_addrs) AS a(addr) WHERE lower(a.addr) = lower($3))"
		taggedArgs = append(taggedArgs, u.Email)
	}
	var taggedCount int
	if err := db.QueryRow(ctx, `
		SELECT count(*)
		  FROM mail_logs ml
		 WHERE ml.organization_id = $1
		   AND ml.disposition = 'tagged'
		   AND ml.received_at > $2`+taggedClause,
		taggedArgs...).Scan(&taggedCount); err != nil {
		return nil, 0, err
	}
	total += taggedCount

	trows, err := db.Query(ctx, `
		SELECT ml.received_at, array_to_string(ml.to_addrs, ', '), COALESCE(ml.from_addr, ''),
		       COALESCE(ml.subject, '')
		  FROM mail_logs ml
		 WHERE ml.organization_id = $1
		   AND ml.disposition = 'tagged'
		   AND ml.received_at > $2`+taggedClause+`
	 ORDER BY ml.received_at DESC
		 LIMIT `+fmt.Sprint(digestItemLimit), taggedArgs...)
	if err != nil {
		return nil, 0, err
	}
	for trows.Next() {
		var item digestItem
		if err := trows.Scan(&item.ReceivedAt, &item.ToAddr, &item.FromAddr, &item.Subject); err != nil {
			trows.Close()
			return nil, 0, err
		}
		item.Tagged = true
		items = append(items, item)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, 0, err
	}

	sort.Slice(items, func(i, j int) bool { return items[i].ReceivedAt.After(items[j].ReceivedAt) })
	if len(items) > digestItemLimit {
		items = items[:digestItemLimit]
	}
	return items, total, nil
}

func sendQuarantineDigest(ctx context.Context, db *pgxpool.Pool, u alertUser, items []digestItem, total int, since time.Time) error {
	host, port, err := gatewayForRecipient(ctx, db, u.OrganizationID, u.Email)
	if err != nil {
		return err
	}
	from, err := alertFrom(ctx, db, u.OrganizationID)
	if err != nil {
		return err
	}
	link := quarantineURL(ctx, db, nil, "")
	subject := fmt.Sprintf("SentinelMail quarantine digest (%d message", total)
	if total == 1 {
		subject += ")"
	} else {
		subject += "s)"
	}
	text := textQuarantineDigest(u.Email, items, total, since, link)
	htmlBody := htmlQuarantineDigest(u.Email, items, total, since, link)
	boundary := "smg-quarantine-digest-boundary"
	headers := []string{
		"From: " + from.String(),
		"To: " + u.Email,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + boundary + `"`,
	}
	raw := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		text + "\r\n\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		htmlBody + "\r\n\r\n" +
		"--" + boundary + "--\r\n")
	return sentemails.Send(ctx, db, sentemails.Record{
		OrganizationID: u.OrganizationID,
		Kind:           "quarantine_digest",
		FromAddr:       from.Address,
		ToAddrs:        []string{u.Email},
		Subject:        subject,
		RelayHost:      host,
		RelayPort:      port,
		Raw:            raw,
		Metadata: map[string]any{
			"alert_user_id": u.ID.String(),
			"item_count":    len(items),
			"total_count":   total,
			"since":         since.UTC().Format(time.RFC3339),
		},
	}, func() error {
		return smtp.SendMail(net.JoinHostPort(host, fmt.Sprint(port)), nil, from.Address, []string{u.Email}, raw)
	})
}

func digestItemLabel(item digestItem) string {
	if item.Tagged {
		return "tagged as spam"
	}
	if item.ThreatClass == "" {
		return "quarantined"
	}
	return strings.ToLower(strings.ReplaceAll(item.ThreatClass, "_", " "))
}

func textQuarantineDigest(to string, items []digestItem, total int, since time.Time, link string) string {
	lines := []string{
		fmt.Sprintf("SentinelMail held or tagged %d message(s) for %s since %s.", total, to, since.Format("2006-01-02 15:04 MST")),
		"",
	}
	for _, item := range items {
		lines = append(lines, "- "+item.ReceivedAt.Format("2006-01-02 15:04 MST")+" | "+item.ToAddr+" | "+emptyDash(item.FromAddr)+" | "+emptyDash(item.Subject)+" | "+digestItemLabel(item))
	}
	if total > len(items) {
		lines = append(lines, "", fmt.Sprintf("Showing the newest %d of %d messages.", len(items), total))
	}
	if link != "" {
		lines = append(lines, "", "Review quarantine here: "+link)
	}
	lines = append(lines, "", "Messages stay held until you release or delete them. Releasing a message delivers it to the mailbox it was addressed to.")
	return strings.Join(lines, "\r\n")
}

func htmlQuarantineDigest(to string, items []digestItem, total int, since time.Time, link string) string {
	button := ""
	if link != "" {
		escapedLink := html.EscapeString(link)
		button = `<tr><td style="padding:24px 0 4px"><a href="` + escapedLink + `" style="display:inline-block;background:#1d4ed8;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 18px;border-radius:8px">Review quarantine</a></td></tr>`
	}
	rows := ""
	for _, item := range items {
		rows += `<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;white-space:nowrap">` + html.EscapeString(item.ReceivedAt.Format("Jan 2 15:04")) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(item.ToAddr) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(emptyDash(item.FromAddr)) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(emptyDash(item.Subject)) + `</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">` + html.EscapeString(digestItemLabel(item)) + `</td></tr>`
	}
	truncNote := ""
	if total > len(items) {
		truncNote = `<p style="margin:10px 0 0;color:#64748b;font-size:13px">Showing the newest ` + fmt.Sprint(len(items)) + ` of ` + fmt.Sprint(total) + ` messages.</p>`
	}
	return `<!doctype html><html><body style="margin:0;background:#f4f7fb;color:#102033;font-family:Arial,Helvetica,sans-serif">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f7fb;padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:720px;background:#ffffff;border:1px solid #d8e2ef;border-radius:12px;overflow:hidden">
<tr><td style="background:#0f172a;color:#ffffff;padding:22px 26px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd">SentinelMail Gateway</div><h1 style="margin:8px 0 0;font-size:24px;line-height:1.25">Quarantine digest</h1></td></tr>
<tr><td style="padding:26px"><p style="margin:0 0 18px;font-size:16px;line-height:1.5">SentinelMail held or tagged <strong>` + fmt.Sprint(total) + `</strong> message(s) for ` + html.EscapeString(to) + ` since ` + html.EscapeString(since.Format("Jan 2 15:04 MST")) + `.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:12px"><tr><th align="left" style="padding:8px">Time</th><th align="left" style="padding:8px">Recipient</th><th align="left" style="padding:8px">From</th><th align="left" style="padding:8px">Subject</th><th align="left" style="padding:8px">Status</th></tr>` + rows + `</table>` + truncNote + `<table role="presentation" cellspacing="0" cellpadding="0">` + button + `</table>
<p style="margin:18px 0 0;color:#64748b;font-size:13px;line-height:1.5">Messages stay held until you release or delete them. Do not click links inside a quarantined message.</p></td></tr>
</table></td></tr></table></body></html>`
}
