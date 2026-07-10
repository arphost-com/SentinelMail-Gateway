// Package classifier stores recipient feedback and applies lightweight learned
// sender/subject classifications during ingest.
package classifier

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Observation struct {
	OrganizationID   uuid.UUID
	DomainID         *uuid.UUID
	UserEmail        string
	FromAddr         string
	Subject          string
	Verdict          string
	MailboxMessageID uuid.UUID
	MailLogID        uuid.UUID
	BodyText         string
	UserID           uuid.UUID
}

type Match struct {
	Verdict     string
	SampleCount int
}

type Analysis struct {
	EmailType string   `json:"email_type"`
	Warning   string   `json:"scam_warning,omitempty"`
	Signals   []string `json:"scam_signals,omitempty"`
	Links     []Link   `json:"scam_links,omitempty"`
}

type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

var subjectTokenRE = regexp.MustCompile(`[a-z0-9]+`)

type AuthSignals struct {
	SPFPass   bool
	DKIMPass  bool
	DMARCPass bool
	SPFFail   bool
	DKIMFail  bool
	DMARCFail bool
}

func Learn(ctx context.Context, db *pgxpool.Pool, obs Observation) error {
	verdict := strings.ToLower(strings.TrimSpace(obs.Verdict))
	if verdict == "" || verdict == "unreviewed" {
		return nil
	}
	body := obs.BodyText
	if len(body) > 512 {
		body = body[:512]
	}
	fingerprint := SubjectFingerprint(obs.Subject)
	if err := upsert(ctx, db, obs, verdict, fingerprint, body); err != nil {
		return err
	}
	if shouldLearnSenderLevel(verdict, fingerprint, obs.FromAddr) {
		return upsert(ctx, db, obs, verdict, "", body)
	}
	return nil
}

func upsert(ctx context.Context, db *pgxpool.Pool, obs Observation, verdict, fingerprint, body string) error {
	_, err := db.Exec(ctx, `
		INSERT INTO user_mail_classifications
		  (organization_id, domain_id, user_email, from_addr, subject_fingerprint,
		   verdict, sample_count, last_mailbox_message_id, last_mail_log_id,
		   last_body_excerpt, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $10)
		ON CONFLICT (organization_id, (lower(user_email)), (lower(from_addr)), subject_fingerprint)
		DO UPDATE SET
		  domain_id = EXCLUDED.domain_id,
		  verdict = EXCLUDED.verdict,
		  sample_count = user_mail_classifications.sample_count + 1,
		  last_mailbox_message_id = EXCLUDED.last_mailbox_message_id,
		  last_mail_log_id = EXCLUDED.last_mail_log_id,
		  last_body_excerpt = EXCLUDED.last_body_excerpt,
		  updated_by = EXCLUDED.updated_by,
		  updated_at = now()
	`, obs.OrganizationID, obs.DomainID, normalizeEmail(obs.UserEmail), normalizeEmail(obs.FromAddr),
		fingerprint, verdict, obs.MailboxMessageID, obs.MailLogID, body, obs.UserID)
	return err
}

func Lookup(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, userEmail, fromAddr, subject string) (*Match, error) {
	fingerprint := SubjectFingerprint(subject)
	m, err := lookup(ctx, db, orgID, userEmail, fromAddr, fingerprint, false)
	if err != nil || m != nil || fingerprint == "" {
		return m, err
	}
	return lookup(ctx, db, orgID, userEmail, fromAddr, "", true)
}

func lookup(ctx context.Context, db *pgxpool.Pool, orgID uuid.UUID, userEmail, fromAddr, fingerprint string, threatOnly bool) (*Match, error) {
	var m Match
	err := db.QueryRow(ctx, `
		SELECT verdict, sample_count
		  FROM user_mail_classifications
		 WHERE organization_id = $1
		   AND lower(user_email) = $2
		   AND lower(from_addr) = $3
		   AND subject_fingerprint = $4
		   AND ($5::boolean = false OR verdict IN ('spam', 'phishing', 'malware'))
		 ORDER BY updated_at DESC
		 LIMIT 1
	`, orgID, normalizeEmail(userEmail), normalizeEmail(fromAddr), fingerprint, threatOnly).
		Scan(&m.Verdict, &m.SampleCount)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func shouldLearnSenderLevel(verdict, fingerprint, fromAddr string) bool {
	if fingerprint == "" || normalizeEmail(fromAddr) == "" {
		return false
	}
	switch verdict {
	case "spam", "phishing", "malware":
		return true
	default:
		return false
	}
}

func SubjectFingerprint(subject string) string {
	tokens := subjectTokenRE.FindAllString(strings.ToLower(subject), -1)
	if len(tokens) == 0 {
		return ""
	}
	kept := make([]string, 0, min(len(tokens), 8))
	for _, token := range tokens {
		if len(token) <= 2 {
			continue
		}
		kept = append(kept, token)
		if len(kept) == 8 {
			break
		}
	}
	return strings.Join(kept, " ")
}

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func AnalyzeCommonScam(subject, body string) Analysis {
	text := normalizeSuspiciousText(subject + "\n" + body)
	switch {
	case any(text, "password", "verify your account", "confirm your account", "login", "sign in") &&
		any(text, "urgent", "suspended", "locked", "unusual activity", "security alert"):
		return warn("Credential phishing", "Similar to common credential phishing: urgent account/security language asks the user to verify or sign in.",
			links("CISA: Recognize and report phishing", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing", "FTC: Phishing scams", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"),
			"account verification", "urgency", "credential request")
	case any(text, "package", "delivery", "shipment", "courier", "tracking number") &&
		any(text, "missed", "unpaid postage", "reschedule", "shipping preferences", "tracking"):
		return warn("Package delivery scam", "Similar to common delivery scams: shipment or postage problem language pushes the user toward a link or payment.",
			links("FTC: How to recognize phishing", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams", "FTC: Report fraud", "https://reportfraud.ftc.gov/"),
			"delivery issue", "payment or update request")
	case any(text, "invoice", "payment due", "wire transfer", "ach", "bank details", "payroll", "direct deposit") &&
		any(text, "urgent", "overdue", "new account", "change", "update", "attached"):
		return warn("Business email compromise", "Similar to common BEC scams: invoice, payment, bank-detail, payroll, or wire-transfer wording with urgency or change requests.",
			links("FBI: Business email compromise", "https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams/business-email-compromise", "IC3: Business email compromise PSA", "https://www.ic3.gov/PSA/2024/PSA240911"),
			"payment request", "urgency or change request")
	case any(text, "gift card", "prepaid card", "crypto", "cryptocurrency", "digital wallet", "wire transfer") &&
		any(text, "buy", "send", "payment", "refund", "fee", "tax", "utility"):
		return warn("Payment scam", "Similar to common payment scams: gift card, prepaid, peer-to-peer, or crypto payment language.",
			links("FTC: Gift cards and payment scams", "https://consumer.ftc.gov/articles/gift-card-scams", "FTC: Utility payment scam", "https://www.ftc.gov/node/45978"),
			"unusual payment method")
	case any(text, "bank", "account", "payment", "transaction", "invoice", "merchant") &&
		any(text, "deducted", "charged", "transaction", "invoice", "pending", "awaiting verification") &&
		any(text, "did not authorize", "unauthorized", "cancel", "secure your account", "dispute") &&
		any(text, "call support", "call our support", "support team", "helpline", "customer support"):
		return warn("Payment support scam", "Similar to common refund and payment-support scams: a claimed charge or transaction pushes the user to call a fake support number.",
			links("FTC: Impersonation scams", "https://consumer.ftc.gov/features/impersonation-scams", "FTC: How to recognize phishing", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"),
			"unauthorized transaction lure", "phone support call-to-action")
	case any(text, "tax refund", "refund", "rebate", "prize", "reward", "points expiring", "free gift") &&
		any(text, "claim", "expires", "limited time", "click", "confirm"):
		return warn("Reward/refund scam", "Similar to common reward, refund, and expiring-points scams that ask users to claim or confirm personal details.",
			links("FTC: Phishing scams", "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams", "FTC: Report fraud", "https://reportfraud.ftc.gov/"),
			"reward/refund lure", "time pressure")
	case any(text, "tax document", "tax documents", "tax return", "tax forms", "tax statement", "tax refund") &&
		any(text, "ready", "available", "view", "open", "download", "confirm", "verify"):
		return warn("Tax document phishing", "Similar to common tax-document phishing: tax forms or statements are presented as ready or available to push the user toward a link.",
			links("IRS: Tax scams/consumer alerts", "https://www.irs.gov/newsroom/tax-scams-consumer-alerts", "CISA: Recognize and report phishing", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
			"tax document lure", "link or download prompt")
	case any(text, "investment", "trading", "profit", "returns", "wallet", "crypto", "cryptocurrency") &&
		any(text, "guaranteed", "exclusive", "limited", "mentor", "opportunity"):
		return warn("Investment scam", "Similar to common investment scams: guaranteed returns, crypto/trading language, or exclusive opportunity wording.",
			links("FTC: Investment scams", "https://consumer.ftc.gov/articles/investment-scams", "IC3: File a complaint", "https://www.ic3.gov/"),
			"investment lure", "unrealistic returns")
	case any(text, "vertigo", "dizziness", "brain damage", "blood sugar", "diabetes", "joint pain", "memory loss", "tinnitus", "hearing loss") &&
		any(text, "miracle", "shocking cause", "secret", "breakthrough", "stop", "erase", "reverse", "cure", "ucla", "harvard", "scientists") &&
		any(text, "watch the video", "video presentation", "click here", "find out", "research report", "essential nutrient", "crucial nutrient"):
		return warn("Medical miracle scam", "Similar to common health scams: exaggerated cure or reversal claims use scientific-sounding authority and push the user toward a sales/video link.",
			links("FTC: Common health scams", "https://consumer.ftc.gov/articles/common-health-scams", "FDA: Health fraud", "https://www.fda.gov/drugs/bioterrorism-and-drug-preparedness/how-spot-health-fraud"),
			"health cure claim", "scientific authority lure", "video click-through")
	case any(text, "scientists reveal", "doctors reveal", "astonishing", "breakthrough", "discovery", "secret", "miracle") &&
		any(text, "back pain", "joint pain", "nerve pain", "blood sugar", "weight loss", "prostate", "tinnitus", "hearing", "vision", "neuropathy"):
		return warn("Health miracle spam", "Similar to common health-product spam: miracle, secret, or discovery wording tied to pain, weight, or chronic-health claims.",
			links("FTC: Health products compliance guidance", "https://www.ftc.gov/business-guidance/resources/health-products-compliance-guidance", "FTC: Report fraud", "https://reportfraud.ftc.gov/"),
			"health miracle claim", "spam lead-generation wording")
	case any(text, "septic system", "roof", "windows", "gutter", "gutters", "hvac", "solar", "water heater", "foundation") &&
		any(text, "working properly", "repair", "replacement", "inspection", "estimate", "quote", "contractor", "service", "homeowner"):
		return warn("Home services lead-gen spam", "Similar to common home-services lead-generation spam: household repair or inspection wording sent without prior context.",
			links("FTC: Report fraud", "https://reportfraud.ftc.gov/"),
			"home service solicitation", "lead-generation wording")
	case any(text, "remote job", "mystery shopper", "car wrap", "work from home", "training", "equipment") &&
		any(text, "check", "deposit", "bank account", "payment", "upfront"):
		return warn("Job scam", "Similar to common job scams: remote-work offer with checks, equipment, training, or banking/payment requests.",
			links("FTC: Job scams", "https://consumer.ftc.gov/articles/job-scams", "FTC: Report fraud", "https://reportfraud.ftc.gov/"),
			"job lure", "payment setup")
	case any(text, "virus", "infected", "tech support", "computer locked", "call support", "renew antivirus"):
		return warn("Tech support scam", "Similar to common tech-support scams: infection or locked-device language designed to trigger a support call or payment.",
			links("FTC: Tech support scams", "https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams"),
			"device warning")
	case any(text, ".exe", ".scr", ".js", ".vbs", "enable macros", "protected document", "password protected attachment"):
		return warn("Malware lure", "Similar to common malware delivery emails: executable, script, macro, or protected attachment language.",
			links("CISA: Avoiding social engineering and phishing", "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks"),
			"risky attachment language")
	default:
		return Analysis{EmailType: "Clean or uncategorized"}
	}
}

func normalizeSuspiciousText(value string) string {
	mapped := strings.Map(func(r rune) rune {
		switch r {
		case 'Α', 'А', 'Ꭺ':
			return 'A'
		case 'Β', 'В':
			return 'B'
		case 'С', 'Ϲ':
			return 'C'
		case 'Е', 'Ε':
			return 'E'
		case 'Η', 'Н':
			return 'H'
		case 'Ι', 'І':
			return 'I'
		case 'Κ', 'К':
			return 'K'
		case 'Μ', 'М':
			return 'M'
		case 'Ν':
			return 'N'
		case 'Ο', 'О':
			return 'O'
		case 'Ρ', 'Р':
			return 'P'
		case 'Τ', 'Т':
			return 'T'
		case 'Χ', 'Х':
			return 'X'
		case 'Υ', 'У':
			return 'Y'
		case 'Ζ', 'Ꮓ':
			return 'Z'
		case 'а', 'α':
			return 'a'
		case 'с', 'ϲ':
			return 'c'
		case 'ԁ':
			return 'd'
		case 'е':
			return 'e'
		case 'һ':
			return 'h'
		case 'і', 'ι':
			return 'i'
		case 'ј':
			return 'j'
		case 'κ':
			return 'k'
		case 'ӏ':
			return 'l'
		case 'м':
			return 'm'
		case 'ո':
			return 'n'
		case 'о', 'ο':
			return 'o'
		case 'р':
			return 'p'
		case 'ѕ':
			return 's'
		case 'τ':
			return 't'
		case 'υ':
			return 'u'
		case 'ѵ':
			return 'v'
		case 'х':
			return 'x'
		case 'у':
			return 'y'
		default:
			return r
		}
	}, value)
	return strings.ToLower(mapped)
}

func warn(kind, warning string, related []Link, signals ...string) Analysis {
	return Analysis{EmailType: kind, Warning: warning, Signals: signals, Links: related}
}

func links(values ...string) []Link {
	out := []Link{}
	for i := 0; i+1 < len(values); i += 2 {
		out = append(out, Link{Label: values[i], URL: values[i+1]})
	}
	return out
}

func any(text string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}
