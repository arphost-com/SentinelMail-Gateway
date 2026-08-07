package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type campaignRecord struct {
	ID                uuid.UUID
	MessageCount      int64
	UniqueSourceIPs   int
	Fingerprint       string
	HasRepresentative bool
}

func recordCampaign(
	ctx context.Context,
	db *pgxpool.Pool,
	orgID, domainID *uuid.UUID,
	disposition, threatClass string,
	ev *Event,
) (campaignRecord, error) {
	if db == nil || orgID == nil || ev == nil {
		return campaignRecord{}, nil
	}
	fingerprint, senderKey, recipientKey, subjectKey, contentHash := campaignFingerprint(ev)
	var campaign campaignRecord
	err := db.QueryRow(ctx, `
		INSERT INTO mail_campaigns
		  (organization_id, domain_id, fingerprint, sender_key, recipient_key,
		   normalized_subject, content_hash, threat_class, latest_disposition)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9)
		ON CONFLICT (organization_id, fingerprint, bucket_date) DO UPDATE SET
		  domain_id = COALESCE(mail_campaigns.domain_id, EXCLUDED.domain_id),
		  threat_class = COALESCE(NULLIF(EXCLUDED.threat_class, ''), mail_campaigns.threat_class),
		  latest_disposition = EXCLUDED.latest_disposition,
		  message_count = mail_campaigns.message_count + 1,
		  last_seen = now(),
		  updated_at = now()
		RETURNING id, message_count, unique_source_ips, fingerprint,
		          representative_quarantine_id IS NOT NULL
	`, orgID, domainID, fingerprint, senderKey, recipientKey, subjectKey,
		contentHash, threatClass, disposition).Scan(
		&campaign.ID, &campaign.MessageCount, &campaign.UniqueSourceIPs, &campaign.Fingerprint,
		&campaign.HasRepresentative,
	)
	if err != nil {
		return campaignRecord{}, err
	}
	if validCampaignIP(ev.ClientIP) {
		tag, err := db.Exec(ctx, `
			INSERT INTO mail_campaign_sources (campaign_id, client_ip)
			VALUES ($1, $2::inet)
			ON CONFLICT (campaign_id, client_ip) DO UPDATE SET
			  last_seen = now(),
			  hit_count = mail_campaign_sources.hit_count + 1
		`, campaign.ID, ev.ClientIP)
		if err != nil {
			return campaignRecord{}, err
		}
		if tag.RowsAffected() > 0 {
			if err := db.QueryRow(ctx, `
				UPDATE mail_campaigns
				   SET unique_source_ips = (
				         SELECT count(*)::int FROM mail_campaign_sources WHERE campaign_id = $1
				       ),
				       updated_at = now()
				 WHERE id = $1
				 RETURNING unique_source_ips
			`, campaign.ID).Scan(&campaign.UniqueSourceIPs); err != nil {
				return campaignRecord{}, err
			}
		}
	}
	return campaign, nil
}

func campaignFingerprint(ev *Event) (fingerprint, senderKey, recipientKey, subjectKey, contentHash string) {
	if ev == nil {
		return "", "", "", "", ""
	}
	from := strings.ToLower(strings.TrimSpace(ev.From))
	senderDomain := emailDomain(from)
	senderKey = from + "|" + senderDomain
	if len(ev.To) > 0 {
		recipientKey = strings.ToLower(strings.TrimSpace(ev.To[0]))
	}
	subjectKey = normalizeCampaignText(ev.Subject, 512)
	stableBody := normalizeCampaignText(ev.BodyText, 8192)
	bodySum := sha256.Sum256([]byte(stableBody))
	contentHash = hex.EncodeToString(bodySum[:])
	sum := sha256.Sum256([]byte(strings.Join([]string{
		senderKey, recipientKey, subjectKey, contentHash,
	}, "\x00")))
	fingerprint = hex.EncodeToString(sum[:])
	return fingerprint, senderKey, recipientKey, subjectKey, contentHash
}

func normalizeCampaignText(value string, maxRunes int) string {
	fields := strings.Fields(strings.ToLower(value))
	var b strings.Builder
	runes := 0
	for _, field := range fields {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") ||
			strings.HasPrefix(field, "www.") {
			field = "<url>"
		}
		for _, r := range field {
			if runes >= maxRunes {
				return strings.TrimSpace(b.String())
			}
			switch {
			case unicode.IsLetter(r):
				b.WriteRune(r)
			case unicode.IsDigit(r):
				b.WriteByte('#')
			case r == '@' || r == '.' || r == '-' || r == '_':
				b.WriteRune(r)
			default:
				b.WriteByte(' ')
			}
			runes++
		}
		b.WriteByte(' ')
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func validCampaignIP(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(value)
	return err == nil
}

func highConfidenceCampaign(disposition, reason, threatClass string) bool {
	if disposition != "quarantined" || threatClass == "CHALLENGE_RESPONSE" {
		return false
	}
	reason = strings.ToLower(reason)
	if strings.Contains(reason, "failed spf/dkim/dmarc") ||
		strings.Contains(reason, "authentication unavailable") {
		return false
	}
	return true
}
