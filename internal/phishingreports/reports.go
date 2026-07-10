// Package phishingreports records confirmed or user-reported phishing events
// for reporting and follow-up.
package phishingreports

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/notifications"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
)

func RecordFromScan(ctx context.Context, db *pgxpool.Pool, scanJobID uuid.UUID, verdict string, evidence []byte) error {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if !json.Valid(evidence) || len(evidence) == 0 {
		evidence = []byte(`{}`)
	}
	if !reportableScanVerdict(verdict, evidence) {
		return nil
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO phishing_reports
		  (organization_id, domain_id, mail_log_id, scan_job_id, source, status,
		   phishing_type, verdict, evidence, reported_at)
		SELECT sj.organization_id,
		       ml.domain_id,
		       sj.mail_log_id,
		       sj.id,
		       'scanner',
		       'auto_verified',
		       CASE
		         WHEN $2 = 'malware' THEN 'malware'
		         WHEN sj.kind = 'qr' THEN 'qr phishing'
		         WHEN sj.kind = 'sandbox' THEN 'browser phishing'
		         ELSE 'phishing'
		       END,
		       $2,
		       $3::jsonb,
		       now()
		  FROM scan_jobs sj
		  LEFT JOIN mail_logs ml ON ml.id = sj.mail_log_id
		 WHERE sj.id = $1
		ON CONFLICT (scan_job_id) WHERE scan_job_id IS NOT NULL
		DO UPDATE SET
		  domain_id = EXCLUDED.domain_id,
		  mail_log_id = EXCLUDED.mail_log_id,
		  status = EXCLUDED.status,
		  phishing_type = EXCLUDED.phishing_type,
		  verdict = EXCLUDED.verdict,
		  evidence = EXCLUDED.evidence,
		  reported_at = EXCLUDED.reported_at,
		  updated_at = now()
	`, scanJobID, verdict, string(evidence))
	if err != nil {
		return err
	}
	mailLogID, err := quarantineScannerHit(ctx, tx, scanJobID, verdict)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if mailLogID != nil {
		_ = notifications.SendPhishingAlertForMailLog(ctx, db, *mailLogID)
	}
	return nil
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func quarantineScannerHit(ctx context.Context, db execer, scanJobID uuid.UUID, verdict string) (*uuid.UUID, error) {
	threatClass := "PHISHING"
	reason := "scanner verified phishing"
	switch verdict {
	case "malware":
		threatClass = "MALWARE"
		reason = "scanner verified malware"
	case "suspicious":
		reason = "scanner detected suspicious phishing indicators"
	}

	var mailLogID uuid.UUID
	var orgID uuid.UUID
	var previousDisposition string
	err := db.QueryRow(ctx, `
		WITH target AS (
			SELECT ml.id, ml.organization_id, ml.disposition::text AS previous_disposition
			  FROM scan_jobs sj
			  JOIN mail_logs ml ON ml.id = sj.mail_log_id
			 WHERE sj.id = $1
			   AND ml.disposition <> 'rejected'
		)
		UPDATE mail_logs ml
		   SET disposition = CASE
		                       WHEN target.previous_disposition = 'quarantined' THEN 'quarantined'::mail_disposition
		                       ELSE 'tagged'::mail_disposition
		                     END,
		       reason = $2
		  FROM target
		 WHERE ml.id = target.id
		RETURNING ml.id, ml.organization_id, target.previous_disposition
	`, scanJobID, reason).Scan(&mailLogID, &orgID, &previousDisposition)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Async scanner verdicts arrive after SMTP delivery has already completed.
	// Do not create held quarantine copies or send quarantine alerts for mail
	// that has already reached the inbox; keep it visible as tagged mail so
	// the recipient can unsubscribe, whitelist, or report it from the inbox.
	if previousDisposition != "quarantined" {
		return nil, nil
	}
	retentionDays := settings.QuarantineRetentionDays(ctx, db, orgID)
	_, err = db.Exec(ctx, `
		INSERT INTO quarantine_entries
		  (organization_id, mail_log_id, domain_id, from_addr, to_addr, subject,
		   rspamd_score, threat_class, storage_key, size_bytes, expires_at, received_at)
		SELECT ml.organization_id,
		       ml.id,
		       ml.domain_id,
		       NULLIF(ml.from_addr, ''),
		       recipient,
		       NULLIF(ml.subject, ''),
		       ml.rspamd_score,
		       $2,
		       '',
		       NULLIF(ml.size_bytes, 0),
		       now() + ($3::int * interval '1 day'),
		       ml.received_at
		  FROM scan_jobs sj
		  JOIN mail_logs ml ON ml.id = sj.mail_log_id
		  CROSS JOIN LATERAL unnest(ml.to_addrs) AS recipient
		 WHERE sj.id = $1
		   AND NOT EXISTS (
		     SELECT 1
		       FROM quarantine_entries qe
		      WHERE qe.mail_log_id = ml.id
		        AND lower(qe.to_addr) = lower(recipient)
		        AND qe.state = 'held'
		   )
	`, scanJobID, threatClass, retentionDays)
	if err != nil {
		return nil, err
	}
	return &mailLogID, nil
}

func RecordFromMailbox(ctx context.Context, db *pgxpool.Pool, mailboxMessageID uuid.UUID, verdict string, reporterUserID uuid.UUID) error {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if !reportableUserVerdict(verdict) {
		return nil
	}
	_, err := db.Exec(ctx, `
		INSERT INTO phishing_reports
		  (organization_id, domain_id, mail_log_id, mailbox_message_id, source, status,
		   phishing_type, verdict, reporter_user_id, evidence, reported_at)
		SELECT mm.organization_id,
		       mm.domain_id,
		       mm.mail_log_id,
		       mm.id,
		       'user',
		       'user_reported',
		       CASE WHEN $2 = 'malware' THEN 'malware' ELSE 'phishing' END,
		       $2,
		       $3,
		       jsonb_build_object(
		         'from_addr', COALESCE(mm.from_addr, ''),
		         'to_addr', mm.to_addr,
		         'subject', COALESCE(mm.subject, '')
		       ),
		       now()
		  FROM mailbox_messages mm
		 WHERE mm.id = $1
		ON CONFLICT (mailbox_message_id) WHERE mailbox_message_id IS NOT NULL
		DO UPDATE SET
		  domain_id = EXCLUDED.domain_id,
		  mail_log_id = EXCLUDED.mail_log_id,
		  status = EXCLUDED.status,
		  phishing_type = EXCLUDED.phishing_type,
		  verdict = EXCLUDED.verdict,
		  reporter_user_id = EXCLUDED.reporter_user_id,
		  evidence = EXCLUDED.evidence,
		  reported_at = EXCLUDED.reported_at,
		  updated_at = now()
	`, mailboxMessageID, verdict, reporterUserID)
	return err
}

func RecordFromQuarantine(ctx context.Context, db *pgxpool.Pool, quarantineEntryID uuid.UUID, verdict string, reporterUserID uuid.UUID) error {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if !reportableUserVerdict(verdict) {
		return nil
	}
	_, err := db.Exec(ctx, `
		INSERT INTO phishing_reports
		  (organization_id, domain_id, mail_log_id, quarantine_entry_id, source, status,
		   phishing_type, verdict, reporter_user_id, evidence, reported_at)
		SELECT qe.organization_id,
		       qe.domain_id,
		       qe.mail_log_id,
		       qe.id,
		       'user',
		       'user_reported',
		       CASE WHEN $2 = 'malware' THEN 'malware' ELSE 'phishing' END,
		       $2,
		       $3,
		       jsonb_build_object(
		         'from_addr', COALESCE(qe.from_addr, ''),
		         'to_addr', qe.to_addr,
		         'subject', COALESCE(qe.subject, ''),
		         'quarantine_entry_id', qe.id
		       ),
		       now()
		  FROM quarantine_entries qe
		 WHERE qe.id = $1
		ON CONFLICT (quarantine_entry_id) WHERE quarantine_entry_id IS NOT NULL
		DO UPDATE SET
		  domain_id = EXCLUDED.domain_id,
		  mail_log_id = EXCLUDED.mail_log_id,
		  status = EXCLUDED.status,
		  phishing_type = EXCLUDED.phishing_type,
		  verdict = EXCLUDED.verdict,
		  reporter_user_id = EXCLUDED.reporter_user_id,
		  evidence = EXCLUDED.evidence,
		  reported_at = EXCLUDED.reported_at,
		  updated_at = now()
	`, quarantineEntryID, verdict, reporterUserID)
	return err
}

func reportableScanVerdict(verdict string, evidence []byte) bool {
	switch verdict {
	case "phishing", "malicious", "malware":
		return true
	case "suspicious":
		return suspiciousScanIndicatesPhishing(evidence)
	default:
		return false
	}
}

func suspiciousScanIndicatesPhishing(evidence []byte) bool {
	var result struct {
		FinalURL string   `json:"final_url"`
		Reasons  []string `json:"reasons"`
		FeedHits []string `json:"feed_hits"`
	}
	if err := json.Unmarshal(evidence, &result); err != nil {
		return false
	}
	if len(result.FeedHits) > 0 {
		return true
	}
	u, err := url.Parse(result.FinalURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.ToLower(u.EscapedPath())
	query := strings.ToLower(u.RawQuery)
	for _, reason := range result.Reasons {
		reason = strings.ToLower(reason)
		if strings.Contains(reason, "form posts to different domain") || strings.Contains(reason, "urlhaus") {
			return true
		}
		if strings.Contains(reason, "password input") && phishingURLIntent(host, path, query) {
			return true
		}
	}
	return phishingURLIntent(host, path, query)
}

func phishingURLIntent(host, path, query string) bool {
	for _, token := range []string{"login", "signin", "sign-in", "verify", "account", "password", "secure", "review"} {
		if strings.Contains(host, token+".") || strings.Contains(path, token) || strings.Contains(query, token) {
			return true
		}
	}
	return false
}

func reportableUserVerdict(verdict string) bool {
	switch verdict {
	case "phishing", "malware":
		return true
	default:
		return false
	}
}
