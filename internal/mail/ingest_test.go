package mail

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
	"github.com/arphost/sentinelmail-gateway/internal/settings"
	"github.com/arphost/sentinelmail-gateway/internal/threatfeed"
)

func TestVerifySigRequiresHMACSHA256(t *testing.T) {
	h := &IngestHandler{Secret: []byte("test-secret")}
	body := []byte(`{"to":["admin@sentinelmail.local"],"score":0}`)

	mac := hmac.New(sha256.New, h.Secret)
	mac.Write(body)
	if !h.verifySig(body, hex.EncodeToString(mac.Sum(nil))) {
		t.Fatal("expected valid HMAC-SHA256 signature")
	}

	plain := sha256.Sum256(append([]byte("test-secret"), body...))
	if h.verifySig(body, hex.EncodeToString(plain[:])) {
		t.Fatal("accepted plain SHA256(secret || body), which Rspamd must not send")
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := map[string]bool{
		"https://example.com/path": true,
		" HTTP://example.com ":     true,
		"mailto:user@example.com":  false,
		"example.com/path":         false,
		"":                         false,
	}
	for input, want := range tests {
		if got := isHTTPURL(input); got != want {
			t.Fatalf("isHTTPURL(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestStorageKeyFallsBackToDBBlob(t *testing.T) {
	if got := storageKey(&Event{StorageKey: "object-key", RawMessageB64: "abc"}); got != "object-key" {
		t.Fatalf("storageKey kept %q, want object-key", got)
	}
	if got := storageKey(&Event{RawMessageB64: "abc"}); got != "db" {
		t.Fatalf("storageKey fallback = %q, want db", got)
	}
	if got := storageKey(&Event{}); got != "" {
		t.Fatalf("empty storageKey = %q, want empty", got)
	}
}

func TestRspamdSymbolsSurviveIngestPayload(t *testing.T) {
	body := []byte(`{
		"from":"sender@example.net",
		"to":["admin@example.com"],
		"score":11.4,
		"symbols":{
			"RBL_SPAMHAUS_ZEN":{"score":4.0,"description":"listed"},
			"PHISHING_URL":{"score":7.4,"options":["https://login.example.test"]}
		}
	}`)
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if len(ev.Symbols) != 2 {
		t.Fatalf("symbols len = %d, want 2", len(ev.Symbols))
	}
	symbolsJSON, err := json.Marshal(ev.Symbols)
	if err != nil {
		t.Fatalf("marshal symbols: %v", err)
	}
	got := string(symbolsJSON)
	for _, want := range []string{"RBL_SPAMHAUS_ZEN", "PHISHING_URL", "login.example.test"} {
		if !strings.Contains(got, want) {
			t.Fatalf("symbols json %q missing %q", got, want)
		}
	}
}

func TestClassifyThreatFromRspamdSymbols(t *testing.T) {
	tests := []struct {
		name    string
		symbols map[string]any
		score   float64
		want    string
	}{
		{name: "phishing", symbols: map[string]any{"PHISHING_URL": map[string]any{"score": 8}}, want: "PHISHING"},
		{name: "zero score phishing informational", symbols: map[string]any{"PHISHING_CHECK": map[string]any{"score": 0}}, want: ""},
		{name: "virus", symbols: map[string]any{"CLAM_VIRUS": map[string]any{"score": 10}}, want: "VIRUS"},
		{name: "reputation", symbols: map[string]any{"RBL_SPAMHAUS_ZEN": map[string]any{"score": 4}}, want: "REPUTATION"},
		{name: "zero score reputation informational", symbols: map[string]any{"RECEIVED_SPAMHAUS_PBL": map[string]any{"score": 0}}, want: ""},
		{name: "score spam", symbols: map[string]any{}, score: 10, want: "SPAM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyThreat(&Event{Symbols: tt.symbols, Score: tt.score})
			if got != tt.want {
				t.Fatalf("classifyThreat = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestThreatSignalTagsPositivePhishingSymbol(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"PHISHING_URL": map[string]any{"score": 8}}}
	got, reason := applyThreatSignalDisposition("delivered", "", ev)
	if got != "tagged" {
		t.Fatalf("disposition = %q, want tagged", got)
	}
	if reason != "phishing signal hit" {
		t.Fatalf("reason = %q, want phishing signal hit", reason)
	}
}

func TestThreatSignalIgnoresZeroScorePhishingSymbol(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"PHISHING_CHECK": map[string]any{"score": 0}}}
	got, reason := applyThreatSignalDisposition("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("zero-score phishing symbol changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestThreatSignalQuarantinesPositiveVirusSymbol(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"CLAM_VIRUS": map[string]any{"score": 10}}}
	got, reason := applyThreatSignalDisposition("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "malware signal hit" {
		t.Fatalf("reason = %q, want malware signal hit", reason)
	}
}

func TestCommonScamDetectionLeavesOrdinaryNewsletterDelivered(t *testing.T) {
	ev := &Event{
		From:     "news@example-retailer.test",
		To:       []string{"barry@qreg.net"},
		Subject:  "New seasonal picks are available",
		BodyText: "Browse new items and saved recommendations.",
		Score:    -8.1,
		Action:   "no action",
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("legitimate newsletter changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestCommonScamDetectionAllowsAuthenticatedGoogleVerification(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "no-reply@accounts.google.com",
		FromName:  "Google",
		To:        []string{"barry@qreg.net"},
		Subject:   "Google verification code",
		BodyText:  "Use this code to sign in and verify your account. This is a security alert for your account.",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        map[string]any{"score": -0.2},
			"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
			"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
			"PHISHING":           map[string]any{"score": 2.0},
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("auth changed official Google verification mail to %q/%q", got, reason)
	}
	got, reason = applyCommonScamDetection(got, reason, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("official Google verification mail changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("official Google verification threat = %q, want empty", threat)
	}
}

func TestCommonScamDetectionQuarantinesSpoofedGoogleVerification(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "no-reply@google-alerts.example",
		FromName:  "Google",
		To:        []string{"barry@qreg.net"},
		Subject:   "Google verification code",
		BodyText:  "Use this code to sign in and verify your account. This is a security alert for your account.",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        map[string]any{"score": -0.2},
			"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
			"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
		},
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("spoofed Google verification changed to %q/%q, want quarantined", got, reason)
	}
	if reason != "detected credential phishing" {
		t.Fatalf("reason = %q, want detected credential phishing", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("spoofed Google verification threat = %q, want PHISHING", threat)
	}
}

func TestCommonScamDetectionQuarantinesHomoglyphTaxDocumentPhishing(t *testing.T) {
	ev := &Event{
		From:    "An4mmwbiyQL2tuyJQqvfBxw==@in.constantcontact.com",
		To:      []string{"barry@qreg.net"},
		Subject: "Υоur tах dосumеntѕ аrе rеаdу !",
		Score:   1.869,
		Action:  "no action",
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected tax document phishing" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestCommonScamDetectionQuarantinesPaymentSupportPhoneScam(t *testing.T) {
	ev := &Event{
		From:    "admin@criticalmineralsafrica.com",
		To:      []string{"barry@qreg.net"},
		Subject: "Transaction PP-TXN-7382-DF",
		BodyText: `Hello Customer,

We wanted to let you know that $738.40 has been successfully deducted from your account today.

Date June 4, 2026
Amount Deducted $738.40
Merchant BestDigitalMart - Lagos, Nigeria
Transaction ID PP-TXN-7382-DF
Status Pending - Awaiting Verification

If you did not authorize this transaction, please call our support team immediately to cancel it and secure your account.

Call Support: 2127-556-656 1+`,
		Score:  -0.1,
		Action: "no action",
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected payment support scam" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestCommonScamDetectionQuarantinesMedicalMiracleScam(t *testing.T) {
	ev := &Event{
		From:    "VirginaJJohnson@notify.mail.wademiley.com",
		To:      []string{"barry@qreg.net"},
		Subject: "UCLA vertigo research report",
		BodyText: `A group of scientists from UCLA unveiled a shocking cause for vertigo.

And no, it's not old age or an ear disease.

98% of your dizziness bouts are caused by the lack of this crucial nutrient, which should feed and nourish the brain cells responsible for balance.

Simply by adding this essential nutrient to your diet you stop vertigo in its tracks, as well as erase all the brain damage it has done so far.

Watch the Video Presentation
Click Here To Find Out All About The Vertigo Nutrient`,
		Score:  -0.1,
		Action: "no action",
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected medical miracle scam" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestCommonScamDetectionQuarantinesHomoglyphWalletAccessPhishing(t *testing.T) {
	ev := &Event{
		From:    "user5915@fs.uni-lj.si",
		To:      []string{"barry@qreg.net"},
		Subject: "Restore Full Ԝаllеt Access — Sync Now",
		Score:   -0.01,
		Action:  "no action",
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected wallet access phishing" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestCommonScamDetectionQuarantinesHealthMiracleSpam(t *testing.T) {
	ev := &Event{
		From:    "Samantha@info.smartlifekart.com",
		To:      []string{"barry@qreg.net"},
		Subject: "scientists reveal an astonishing back pain discovery",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected health miracle spam" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "SPAM" {
		t.Fatalf("threat = %q, want SPAM", threat)
	}
}

func TestCommonScamDetectionQuarantinesAuthenticatedHealthLeadGenerationSpam(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		body    string
	}{
		{name: "pancreas reset", subject: "Could your pancreas need a reset?", body: "Scientists describe a blood sugar reset and claim the real cause starts in the pancreas."},
		{name: "brain health video", subject: "Explore practical brain health tips", body: "A memory discovery could change your routine. Watch this video to learn more."},
		{name: "sleep wake-up breakthrough", subject: "What if your sleep problem starts with 3AM wake-ups?", body: "A doctor reveals a breakthrough. Click here to watch the video presentation."},
		{name: "nail fungus curiosity", subject: "What happens after you rub your nail this way?", body: "This nail fungus cure is presented as a simple discovery. Find out more."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &Event{
				From:     "newsletter@live.example.test",
				To:       []string{"recipient@example.test"},
				Subject:  tt.subject,
				BodyText: tt.body,
				Symbols: map[string]any{
					"R_SPF_ALLOW":        true,
					"R_DKIM_ALLOW":       true,
					"DMARC_POLICY_ALLOW": true,
				},
			}
			got, reason := applyCommonScamDetection("delivered", "", ev)
			if got != "quarantined" {
				t.Fatalf("disposition = %q, want quarantined", got)
			}
			if reason != "detected health lead-generation spam" {
				t.Fatalf("reason = %q, want detected health lead-generation spam", reason)
			}
			if threat := classifyThreat(ev); threat != "SPAM" {
				t.Fatalf("threat = %q, want SPAM", threat)
			}
		})
	}
}

func TestCommonScamDetectionAllowsAuthenticatedHealthEducation(t *testing.T) {
	ev := &Event{
		From:     "education@hospital.example.test",
		To:       []string{"recipient@example.test"},
		Subject:  "Practical brain health tips",
		BodyText: "Maintain a regular sleep schedule, exercise, and discuss memory concerns with your clinician.",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("authenticated health education changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("authenticated health education threat = %q, want empty", threat)
	}
}

func TestCommonScamDetectionQuarantinesHomeServicesLeadGenSpam(t *testing.T) {
	ev := &Event{
		From:    "Sanborsn@info.fitlifepaths.com",
		To:      []string{"barry@qreg.net"},
		Subject: "Is your septic system working properly?",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyCommonScamDetection("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "detected home services lead-gen spam" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "SPAM" {
		t.Fatalf("threat = %q, want SPAM", threat)
	}
}

func TestCommonScamPolicyToggleDisablesQuarantine(t *testing.T) {
	ev := &Event{
		From:    "Samantha@info.smartlifekart.com",
		To:      []string{"barry@qreg.net"},
		Subject: "scientists reveal an astonishing back pain discovery",
	}
	pol := &policies.Policy{Settings: map[string]any{"common_scam_detection_enabled": false}}
	got, reason := applyCommonScamDetectionWithPolicy("delivered", "", pol, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("disabled common scam detection changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreatWithOptions(ev, defaultBrandAnalysisOptions(), pol); threat != "" {
		t.Fatalf("disabled common scam threat = %q, want empty", threat)
	}
}

func TestCommonScamCategoryToggleOnlyDisablesThatCategory(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"common_scam_health_miracle_enabled": false}}
	health := &Event{Subject: "scientists reveal an astonishing back pain discovery"}
	got, reason := applyCommonScamDetectionWithPolicy("delivered", "", pol, health)
	if got != "delivered" || reason != "" {
		t.Fatalf("disabled health category changed to %q/%q, want delivered/empty", got, reason)
	}
	leadGen := &Event{
		Subject:  "What if your sleep problem starts with 3AM wake-ups?",
		BodyText: "A doctor reveals a breakthrough. Click here to watch the video presentation.",
	}
	got, reason = applyCommonScamDetectionWithPolicy("delivered", "", pol, leadGen)
	if got != "delivered" || reason != "" {
		t.Fatalf("disabled health lead-generation category changed to %q/%q, want delivered/empty", got, reason)
	}

	home := &Event{Subject: "Is your septic system working properly?"}
	got, reason = applyCommonScamDetectionWithPolicy("delivered", "", pol, home)
	if got != "quarantined" || reason != "detected home services lead-gen spam" {
		t.Fatalf("home services category changed to %q/%q, want quarantined/home services", got, reason)
	}
}

func TestBrandImpersonationQuarantinesDocusignClaimFromUnrelatedDomain(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "noreply@techdevelopments.co",
		FromName:  "DocuSign",
		Subject:   "Complete with DocuSign: vendor agreement",
		BodyText:  "Please review and sign the attached document.",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("auth changed message to %q/%q, want delivered/empty", got, reason)
	}
	got, reason = applyBrandImpersonationDetection(got, reason, "", nil, ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if !strings.Contains(reason, "brand impersonation: docusign") || !strings.Contains(reason, "display name claims docusign") {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestBrandImpersonationQuarantinesBodyOnlySignatureLure(t *testing.T) {
	// Sanitized from a delivered template: the authenticated third-party sender
	// does not claim the brand in its name or subject.
	ev := &Event{
		Direction: "inbound",
		From:      "bounces@mailer.example",
		FromName:  "DocsAdmin",
		Subject:   "Recent document is ready to view now",
		BodyText: "A document is ready for review and electronic signature. Review & Sign. " +
			"Status: Signature Pending. Delivered through DocuSign's electronic signature platform.",
		URLs: []string{
			"https://click.mailer.example/q/tracking-token",
			"https://documents.example.invalid/docssummary/",
		},
		Symbols: map[string]any{"R_DKIM_ALLOW": true, "DMARC_POLICY_ALLOW": true},
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "quarantined" || !strings.Contains(reason, "body claims docusign signature workflow") {
		t.Fatalf("body-only lure changed to %q/%q, want quarantine", got, reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestBrandImpersonationQuarantinesBodyOnlyEnvelopeLure(t *testing.T) {
	ev := &Event{
		Direction: "inbound", From: "bounces@mailer.example", FromName: "DocsAdmin",
		Subject: "Confidential document shared with you for review",
		BodyText: "We placed the document in your DocuSign envelope for review and electronic approval. " +
			"Signature status: Signature Pending. Review & Sign.",
		URLs: []string{"https://documents.example.invalid/review/"},
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "quarantined" || !strings.Contains(reason, "body claims docusign signature workflow") {
		t.Fatalf("body-only envelope lure changed to %q/%q, want quarantine", got, reason)
	}
}

func TestBrandImpersonationBodyOnlySignatureLureFalsePositiveGuards(t *testing.T) {
	base := Event{
		Direction: "inbound", From: "bounces@mailer.example", FromName: "DocsAdmin",
		Subject:  "Recent document is ready to view now",
		BodyText: "Review & Sign. Signature Pending. Delivered through DocuSign's electronic signature platform.",
		URLs:     []string{"https://documents.example.invalid/review/"},
	}
	for name, change := range map[string]func(*Event){
		"official link": func(ev *Event) {
			ev.URLs = []string{"https://click.mailer.example/q/tracking-token", "https://apps.docusign.com/review/"}
		},
		"official sender":    func(ev *Event) { ev.From = "notice@docusign.net" },
		"ordinary mention":   func(ev *Event) { ev.BodyText = "Our team uses DocuSign for signatures." },
		"no action link":     func(ev *Event) { ev.URLs = nil },
		"unrelated document": func(ev *Event) { ev.BodyText = "Review & Sign. Signature Pending. The document is in our own portal." },
	} {
		t.Run(name, func(t *testing.T) {
			ev := base
			change(&ev)
			got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, &ev)
			if got != "delivered" || reason != "" {
				t.Fatalf("legitimate example changed to %q/%q", got, reason)
			}
		})
	}
}

func TestBrandImpersonationMainPolicyToggleDisablesDetection(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "noreply@techdevelopments.co",
		FromName:  "DocuSign",
		Subject:   "Complete with DocuSign: vendor agreement",
		BodyText:  "Please review and sign the attached document.",
	}
	pol := &policies.Policy{Settings: map[string]any{"brand_impersonation_enabled": false}}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", pol, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("disabled brand impersonation changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreatWithBrandOptions(ev, brandAnalysisOptionsFromPolicy(pol)); threat != "" {
		t.Fatalf("disabled brand impersonation threat = %q, want empty", threat)
	}
}

func TestBrandImpersonationDisplayNameToggleCanReduceQuarantine(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "noreply@techdevelopments.co",
		FromName:  "DocuSign",
		Subject:   "Complete with DocuSign: vendor agreement",
		BodyText:  "Please review and sign the attached document.",
	}
	pol := &policies.Policy{Settings: map[string]any{"brand_impersonation_display_name_enabled": false}}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", pol, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("display-name-only disable changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestBrandImpersonationLinkMismatchBoostsSuspiciousSubject(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "billing@vendor.example",
		Subject:   "Apple billing receipt",
		BodyText:  "Review your Apple purchase details.",
		URLs:      []string{"https://apple-billing-review.example/path"},
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "quarantined" {
		t.Fatalf("link mismatch disposition = %q/%q, want quarantined", got, reason)
	}
	if !strings.Contains(reason, "link points to unrelated domain apple-billing-review.example") {
		t.Fatalf("reason = %q, want link mismatch detail", reason)
	}
}

func TestBrandImpersonationQuarantinesICloudVerificationToMicrosoftOAuth(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "mail@serviceautopilot.com",
		FromName:  "Service Autopilot",
		To:        []string{"barry@qreg.net"},
		Subject:   "Final reminder",
		BodyText: `Hello,

This is the final reminder that your iCloud account is pending verification.

You are required to complete verification immediately to avoid permanent loss of contact, notes, mail, photos and many more.

Click the link below and sign in to complete verification immediately.`,
		URLs: []string{
			"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=ZGtpbmdAb3JlZ29uY2xlYW4uY29t&scope=openid&prompt=none&client_id=aff42d52-9e62-4400-9f29-a920774580cc",
			"http://crm.serviceautopilot.com/?rk=8a195422-57f6-4e07-8e87-9463a9d61492&el=65035b90-d1f7-420f-a0df-ca31ede50712",
		},
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("auth changed authenticated marketing sender to %q/%q, want delivered/empty", got, reason)
	}
	got, reason = applyBrandImpersonationDetection(got, reason, "", nil, ev)
	if got != "quarantined" {
		t.Fatalf("iCloud OAuth lure disposition = %q/%q, want quarantined", got, reason)
	}
	for _, want := range []string{
		"brand impersonation: apple",
		"account or payment pressure asks the recipient to update details",
		"link points to unrelated domain login.microsoftonline.com",
	} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason = %q, want containing %q", reason, want)
		}
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestBrandImpersonationAllowsDocusignSystemDomain(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "dse@na2.docusign.net",
		FromName:  "DocuSign",
		Subject:   "Complete with DocuSign: vendor agreement",
		BodyText:  "Please review and sign the document.",
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("official sender changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestBrandImpersonationAllowsAuthenticatedNewsletterMentioningOtherBrands(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "bounce@mail.cointracker.io",
		FromName:  "CoinTracker",
		Subject:   "Crypto portfolio update",
		BodyText:  "Review your connected Google account and follow CoinTracker on Twitter.",
		URLs:      []string{"https://twitter.com/cointracker", "https://fonts.googleapis.com/css"},
		Symbols: map[string]any{
			"R_SPF_ALLOW": true, "R_DKIM_ALLOW": true, "DMARC_POLICY_ALLOW": true,
		},
	}
	profiles := []protectedBrandProfile{{
		name: "google", terms: []string{"google", "gmail", "google account"},
		senderDomains: []string{"google.com"}, cues: []string{"account", "security", "login"},
	}}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "delivered" || reason != "" {
		t.Fatalf("authenticated newsletter changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreatWithProfiles(ev, defaultBrandAnalysisOptions(), nil, profiles); threat != "" {
		t.Fatalf("authenticated newsletter threat = %q, want empty", threat)
	}
}

func TestBrandImpersonationAllowsAuthenticatedDealsNewsletterWithBrandInSubject(t *testing.T) {
	ev := &Event{
		Direction:       "inbound",
		From:            "bounce@email.twentytwowords.com",
		FromName:        "22 Words",
		Subject:         "Amazon PLUS Walmart Deals Just Released Today!",
		BodyText:        "Today's Amazon Prime and Walmart shopping deals are available now.",
		URLs:            []string{"https://links.22w.co/click/deals"},
		ListUnsubscribe: "<https://links.22w.co/unsubscribe?id=123>",
		Symbols: map[string]any{
			"R_SPF_ALLOW": true, "R_DKIM_ALLOW": true, "DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("authenticated deals newsletter changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("authenticated deals newsletter threat = %q, want empty", threat)
	}
}

func TestBrandImpersonationAllowsOfficialBrandSenderMentioningOtherBrands(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "bounces@em7877.tm.openai.com",
		FromName:  "ChatGPT",
		Subject:   "[Task Update] Weekly finances update",
		BodyText:  "Your portfolio includes services from Google and other providers.",
		URLs:      []string{"https://twitter.com/openai"},
		Symbols: map[string]any{
			"R_SPF_ALLOW": true, "R_DKIM_ALLOW": true, "DMARC_POLICY_ALLOW": true,
		},
	}
	profiles := []protectedBrandProfile{
		{name: "openai", terms: []string{"openai", "chatgpt"}, senderDomains: []string{"openai.com"}, cues: []string{"account"}},
		{name: "google", terms: []string{"google", "gmail"}, senderDomains: []string{"google.com"}, cues: []string{"account", "security"}},
	}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "delivered" || reason != "" {
		t.Fatalf("official brand sender changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreatWithProfiles(ev, defaultBrandAnalysisOptions(), nil, profiles); threat != "" {
		t.Fatalf("official brand sender threat = %q, want empty", threat)
	}
}

func TestBrandImpersonationAllowsAuthenticatedPayPalAppleReceipt(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "service@paypal.com",
		FromName:  "PayPal",
		To:        []string{"barry@qreg.net"},
		Subject:   "Apple Services: $9.99 USD",
		BodyText:  "You sent a payment of $9.99 USD to Apple Services. Transaction ID 1234567890.",
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("auth changed PayPal receipt to %q/%q, want delivered/empty", got, reason)
	}
	got, reason = applyBrandImpersonationDetection(got, reason, "", nil, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("authenticated PayPal receipt changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("authenticated PayPal receipt threat = %q, want empty", threat)
	}
}

func TestBrandImpersonationQuarantinesUnauthenticatedPayPalAppleReceipt(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "service@paypal-alerts.test",
		FromName:  "PayPal",
		To:        []string{"barry@qreg.net"},
		Subject:   "Apple Services: $9.99 USD",
		BodyText:  "You sent a payment of $9.99 USD to Apple Services. Transaction ID 1234567890.",
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
	if got != "quarantined" {
		t.Fatalf("unauthenticated PayPal-style receipt changed to %q/%q, want quarantined", got, reason)
	}
	if !strings.Contains(reason, "brand impersonation: paypal") {
		t.Fatalf("reason = %q, want brand impersonation: paypal", reason)
	}
}

func TestBrandImpersonationProfilesQuarantineUnrelatedDomains(t *testing.T) {
	for _, profile := range protectedBrandProfiles {
		t.Run(profile.name, func(t *testing.T) {
			ev := &Event{
				Direction: "inbound",
				From:      "alerts@unrelated-sender.test",
				FromName:  profile.terms[0],
				Subject:   profile.terms[0] + " account notice",
			}
			got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
			if got != "quarantined" {
				t.Fatalf("disposition = %q, want quarantined", got)
			}
			if want := "brand impersonation: " + profile.name; !strings.Contains(reason, want) {
				t.Fatalf("reason = %q, want containing %q", reason, want)
			}
			if threat := classifyThreat(ev); threat != "PHISHING" {
				t.Fatalf("threat = %q, want PHISHING", threat)
			}
		})
	}
}

func TestBrandImpersonationProfilesAllowTrustedDomains(t *testing.T) {
	for _, profile := range protectedBrandProfiles {
		t.Run(profile.name, func(t *testing.T) {
			ev := &Event{
				Direction: "inbound",
				From:      "alerts@" + profile.senderDomains[0],
				FromName:  profile.terms[0],
				Subject:   profile.terms[0] + " account notice",
			}
			got, reason := applyBrandImpersonationDetection("delivered", "", "", nil, ev)
			if got != "delivered" || reason != "" {
				t.Fatalf("trusted sender changed to %q/%q, want delivered/empty", got, reason)
			}
		})
	}
}

func TestBrandImpersonationSkipsExplicitlyAllowedSender(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "contracts@customer-custom-domain.test",
		FromName:  "DocuSign",
		Subject:   "Complete with DocuSign: vendor agreement",
	}
	got, reason := applyBrandImpersonationDetection("delivered", "", "allow", nil, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("allowed sender changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestAuthEnforcementQuarantinesFailedAuthentication(t *testing.T) {
	ev := &Event{
		Symbols: map[string]any{
			"R_SPF_SOFTFAIL": true,
			"DMARC_NA":       true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "sender failed SPF/DKIM/DMARC authentication" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestAuthEnforcementQuarantinesMissingAuthenticationResults(t *testing.T) {
	got, reason := applyAuthEnforcement("delivered", "", &Event{Symbols: map[string]any{}})
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "sender authentication results missing" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestAuthEnforcementAllowsDeliveryStatusNotification(t *testing.T) {
	ev := deliveryStatusNotificationEvent()
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("delivery status notification changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestAuthEnforcementQuarantinesNullSenderWithoutDSNEvidence(t *testing.T) {
	ev := &Event{Direction: "inbound", From: "", Subject: "Ordinary message", Symbols: map[string]any{}}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "quarantined" || reason != "sender authentication results missing" {
		t.Fatalf("null sender without DSN evidence changed to %q/%q, want quarantine/missing auth", got, reason)
	}
}

func TestAuthEnforcementSkipsOutboundMail(t *testing.T) {
	got, reason := applyAuthEnforcement("delivered", "", &Event{Direction: "outbound", Symbols: map[string]any{}})
	if got != "delivered" || reason != "" {
		t.Fatalf("outbound mail changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestAuthEnforcementLeavesFullyAuthenticatedMail(t *testing.T) {
	ev := &Event{
		Symbols: map[string]any{
			"R_SPF_ALLOW":        true,
			"R_DKIM_ALLOW":       true,
			"DMARC_POLICY_ALLOW": true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("fully authenticated mail changed to %q/%q", got, reason)
	}
}

func TestAuthEnforcementAllowsDKIMPassWithSPFSoftfail(t *testing.T) {
	ev := &Event{
		Symbols: map[string]any{
			"R_SPF_SOFTFAIL": true,
			"R_DKIM_ALLOW":   true,
			"DMARC_NA":       true,
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("DKIM-authenticated mail changed to %q/%q", got, reason)
	}
}

func TestAuthEnforcementQuarantinesDMARCRejectPolicy(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"DMARC_POLICY_REJECT": true}}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "sender failed DMARC reject policy" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRejectThresholdRejectsRegardlessOfQuarantineAction(t *testing.T) {
	got, reason := decide(&policies.Policy{SpamThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 15}, &Event{Score: 20})
	if got != "rejected" {
		t.Fatalf("disposition = %q, want rejected", got)
	}
	if reason != "score >= reject_threshold" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestQuarantineActionTagOnlyAppliesBelowRejectThreshold(t *testing.T) {
	pol := &policies.Policy{
		SpamThreshold:       5,
		QuarantineThreshold: 10,
		RejectThreshold:     15,
		QuarantineAction:    "tag",
	}
	got, reason := decide(pol, &Event{Score: 11})
	if got != "tagged" || reason != "score >= quarantine_threshold" {
		t.Fatalf("score 11 disposition = %q/%q, want tagged/quarantine threshold", got, reason)
	}
	got, reason = decide(pol, &Event{Score: 20})
	if got != "rejected" || reason != "score >= reject_threshold" {
		t.Fatalf("score 20 disposition = %q/%q, want rejected/reject threshold", got, reason)
	}
}

func TestQuarantineActionDeliverAllowsOverThresholdDelivery(t *testing.T) {
	pol := &policies.Policy{
		SpamThreshold:       5,
		QuarantineThreshold: 10,
		RejectThreshold:     15,
		QuarantineAction:    "deliver",
	}
	got, reason := decide(pol, &Event{Score: 12})
	if got != "delivered" {
		t.Fatalf("disposition = %q, want delivered", got)
	}
	if reason != "score >= quarantine_threshold" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestDeepAnalysisEligibleRequiresExplicitSafeConfiguration(t *testing.T) {
	ev := &Event{Direction: "inbound", Score: 6, To: []string{"user@example.test"}}
	config := settings.DeepAnalysisConfig{Enabled: true, MinScore: 4, TimeoutMinutes: 15}
	ai := settings.AIConfig{Mode: "suspicious", Available: true}
	if !deepAnalysisEligible("tagged", ev, config, ai) {
		t.Fatal("eligible tagged message was not held")
	}
	for name, eligible := range map[string]bool{
		"disabled hold":   deepAnalysisEligible("tagged", ev, settings.DeepAnalysisConfig{Enabled: false, MinScore: 4}, ai),
		"disabled ai":     deepAnalysisEligible("tagged", ev, config, settings.AIConfig{Mode: "disabled", Available: true}),
		"missing key":     deepAnalysisEligible("tagged", ev, config, settings.AIConfig{Mode: "suspicious", Available: false}),
		"delivered":       deepAnalysisEligible("delivered", ev, config, ai),
		"below score":     deepAnalysisEligible("tagged", &Event{Direction: "inbound", Score: 3.9}, config, ai),
		"outbound":        deepAnalysisEligible("tagged", &Event{Direction: "outbound", Score: 6}, config, ai),
		"multi recipient": deepAnalysisEligible("tagged", &Event{Direction: "inbound", Score: 6, To: []string{"one@example.test", "two@example.test"}}, config, ai),
	} {
		if eligible {
			t.Fatalf("%s unexpectedly eligible", name)
		}
	}
}

func TestThreatCandidatesExtractTypedSignalsWithoutUnboundedFanout(t *testing.T) {
	ev := &Event{
		ClientIP: "192.0.2.10",
		From:     "offers@campaign.example",
		URLs: []string{
			"https://landing.example/offer",
			"javascript:alert(1)",
			"https://landing.example/second",
			"https://another.example/path",
			"https://third.example/path",
			"https://fourth.example/path",
		},
	}
	got := threatCandidates(ev)
	if len(got) > 8 {
		t.Fatalf("candidate count = %d, want <= 8", len(got))
	}
	want := map[threatfeed.Kind]bool{threatfeed.KindIP: false, threatfeed.KindDomain: false, threatfeed.KindURL: false}
	for _, candidate := range got {
		want[candidate.kind] = true
		if strings.HasPrefix(candidate.value, "javascript:") {
			t.Fatal("unsafe URL scheme was accepted")
		}
	}
	for kind, found := range want {
		if !found {
			t.Fatalf("missing %s candidate", kind)
		}
	}
}

func TestDeliveryStatusNotificationBypassesScoreBasedQuarantine(t *testing.T) {
	ev := deliveryStatusNotificationEvent()
	got, reason := decide(&policies.Policy{SpamThreshold: 5, QuarantineThreshold: 7, RejectThreshold: 15}, ev)
	if got != "quarantined" || reason != "score >= quarantine_threshold" {
		t.Fatalf("test setup disposition = %q/%q, want quarantined/score threshold", got, reason)
	}
	got, reason = applyDeliveryStatusNotificationDisposition(got, reason, ev)
	if got != "delivered" || reason != "delivery status notification" {
		t.Fatalf("delivery status notification changed to %q/%q, want delivered/dsn", got, reason)
	}
}

func TestDeliveryStatusNotificationStillAllowsReputationQuarantine(t *testing.T) {
	ev := deliveryStatusNotificationEvent()
	ev.Symbols["RBL_SPAMHAUS_ZEN"] = map[string]any{"score": 4.0}
	got, reason := applyDeliveryStatusNotificationDisposition("quarantined", "score >= quarantine_threshold", ev)
	got, reason = applyReputationBlocklist(got, reason, ev)
	if got != "quarantined" || reason != "reputation blocklist hit" {
		t.Fatalf("reputation-listed delivery status notification changed to %q/%q, want quarantine/reputation", got, reason)
	}
}

func TestQuarantineFirstConvertsInboundReject(t *testing.T) {
	got, reason := applyQuarantineFirst("rejected", "manual reject", &Event{Direction: "inbound"})
	if got != "quarantined" || reason != "manual reject" {
		t.Fatalf("inbound reject changed to %q/%q, want quarantined/manual reject", got, reason)
	}
}

func TestQuarantineFirstPreservesSenderBlacklistReject(t *testing.T) {
	got, reason := applyQuarantineFirst("rejected", "sender matched blacklist", &Event{Direction: "inbound"})
	if got != "rejected" || reason != "sender matched blacklist" {
		t.Fatalf("sender blacklist reject changed to %q/%q, want rejected/sender matched blacklist", got, reason)
	}
}

func TestSenderListActionRejectsBlockedSender(t *testing.T) {
	got, reason := applySenderListAction("delivered", "", "block", true)
	if got != "rejected" {
		t.Fatalf("disposition = %q, want rejected", got)
	}
	if reason != "sender matched blacklist" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestSenderListActionIgnoresBlockWhenBlacklistDisabled(t *testing.T) {
	got, reason := applySenderListAction("delivered", "", "block", false)
	if got != "delivered" || reason != "" {
		t.Fatalf("disabled blacklist changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestEffectiveSenderListAction(t *testing.T) {
	tests := []struct {
		name             string
		action           string
		blacklistEnabled bool
		want             string
	}{
		{name: "allow", action: "allow", blacklistEnabled: true, want: "allow"},
		{name: "enabled block", action: "block", blacklistEnabled: true, want: "block"},
		{name: "disabled block", action: "block", blacklistEnabled: false, want: ""},
		{name: "none", action: "", blacklistEnabled: true, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveSenderListAction(tt.action, tt.blacklistEnabled); got != tt.want {
				t.Fatalf("effectiveSenderListAction() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordSenderListSymbol(t *testing.T) {
	ev := &Event{}
	recordSenderListSymbol(ev, "block")
	symbol, ok := ev.Symbols["SMG_SENDER_BLACKLIST"].(map[string]any)
	if !ok {
		t.Fatalf("block symbol missing or wrong type: %#v", ev.Symbols)
	}
	if symbol["score"] != 20.0 || symbol["group"] != "sentinelmail" {
		t.Fatalf("unexpected block symbol: %#v", symbol)
	}

	recordSenderListSymbol(ev, "allow")
	if _, ok := ev.Symbols["SMG_SENDER_ALLOWLIST"]; !ok {
		t.Fatalf("allow symbol missing: %#v", ev.Symbols)
	}
}

func TestSenderListActionDoesNotAllowQuarantineThreshold(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "score >= quarantine_threshold", "allow", true)
	if got != "quarantined" || reason != "score >= quarantine_threshold" {
		t.Fatalf("allowlist changed to %q/%q, want quarantined/threshold", got, reason)
	}
}

func TestSenderListActionDoesNotAllowHardQuarantine(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "sender failed SPF/DKIM/DMARC authentication", "allow", true)
	if got != "quarantined" || reason != "sender failed SPF/DKIM/DMARC authentication" {
		t.Fatalf("allowlist changed hard quarantine to %q/%q", got, reason)
	}
}

func TestSenderListActionDoesNotAllowReputationQuarantine(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "reputation blocklist hit", "allow", true)
	if got != "quarantined" || reason != "reputation blocklist hit" {
		t.Fatalf("allowlist changed reputation quarantine to %q/%q", got, reason)
	}
}

func TestSenderListActionDoesNotAllowCachedThreatHit(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "cached threat intelligence hit: urlhaus", "allow", true)
	if got != "quarantined" || reason != "cached threat intelligence hit: urlhaus" {
		t.Fatalf("allowlist changed cached threat quarantine to %q/%q", got, reason)
	}
}

func TestSenderListActionAllowsPhishingSignalTag(t *testing.T) {
	got, reason := applySenderListAction("tagged", "phishing signal hit", "allow", true)
	if got != "delivered" || reason != "sender matched allowlist" {
		t.Fatalf("allowlist changed phishing tag to %q/%q, want delivered/allowlist", got, reason)
	}
}

func TestSenderListActionCannotOverrideLearnedThreatVerdict(t *testing.T) {
	for _, verdict := range []string{"spam", "phishing", "malware"} {
		t.Run(verdict, func(t *testing.T) {
			reason := "user classified similar mail as " + verdict
			gotDisposition, gotReason := applySenderListAction("quarantined", reason, "allow", true)
			if gotDisposition != "quarantined" || gotReason != reason {
				t.Fatalf("applySenderListAction() = %q, %q; want quarantined, %q", gotDisposition, gotReason, reason)
			}
		})
	}
}

func TestRspamdSenderBlocklistRejectsSender(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"SMG_SENDER_BLACKLIST": true}}
	got, reason := applyRspamdSenderBlocklist("delivered", "", ev)
	if got != "rejected" {
		t.Fatalf("disposition = %q, want rejected", got)
	}
	if reason != "sender matched blacklist" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestReputationBlocklistQuarantinesLowScoreMail(t *testing.T) {
	ev := &Event{Score: -2.0, Symbols: map[string]any{"RBL_SPAMHAUS_ZEN": map[string]any{"score": 4.0}}}
	got, reason := applyReputationBlocklist("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "reputation blocklist hit" {
		t.Fatalf("reason = %q", reason)
	}
	if threat := classifyThreat(ev); threat != "REPUTATION" {
		t.Fatalf("threat = %q, want REPUTATION", threat)
	}
}

func TestAuthenticatedFirstPartyRspamdURIBLDoesNotQuarantineFigureStatement(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "msprvs1=20675RgQILFIP=bounces-205586-3@outbound.figure.com",
		Subject:   "Figure Loan Statement",
		Score:     5.1,
		Symbols: map[string]any{
			"R_SPF_ALLOW":        map[string]any{"score": 0.0},
			"R_DKIM_ALLOW":       map[string]any{"score": 0.0},
			"DMARC_POLICY_ALLOW": map[string]any{"score": 0.0, "options": []any{"outbound.figure.com", "reject"}},
			"RSPAMD_URIBL":       map[string]any{"score": 4.5, "options": []any{"figure.com:url"}},
		},
	}
	got, reason := applyReputationBlocklist("tagged", "score >= spam_threshold", ev)
	if got != "tagged" || reason != "score >= spam_threshold" {
		t.Fatalf("authenticated first-party URL changed to %q/%q, want tagged/score reason", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("authenticated first-party URL threat = %q, want empty", threat)
	}
}

func TestRspamdURIBLStillQuarantinesUnrelatedOrUnauthenticatedURL(t *testing.T) {
	tests := []Event{
		{
			From: "sender@example.com",
			Symbols: map[string]any{
				"DMARC_POLICY_ALLOW": map[string]any{"score": 0.0},
				"RSPAMD_URIBL":       map[string]any{"score": 4.5, "options": []any{"credential-harvest.test:url"}},
			},
		},
		{
			From: "sender@example.com",
			Symbols: map[string]any{
				"RSPAMD_URIBL": map[string]any{"score": 4.5, "options": []any{"example.com:url"}},
			},
		},
	}
	for i := range tests {
		got, reason := applyReputationBlocklist("delivered", "", &tests[i])
		if got != "quarantined" || reason != "reputation blocklist hit" {
			t.Fatalf("case %d changed to %q/%q, want quarantined/reputation", i, got, reason)
		}
	}
}

func TestGenericPhishingHeuristicDoesNotCountAsReputationHit(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"PHISHING": map[string]any{"score": 2.0}}}
	got, reason := applyReputationBlocklist("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("generic phishing heuristic changed to %q/%q, want delivered/empty", got, reason)
	}
	got, reason = applyThreatSignalDisposition(got, reason, ev)
	if got != "tagged" || reason != "phishing signal hit" {
		t.Fatalf("generic phishing heuristic changed to %q/%q, want tagged/phishing signal hit", got, reason)
	}
}

func TestOpenPhishStillCountsAsReputationHit(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"OPENPHISH_URL": map[string]any{"score": 7.0}}}
	got, reason := applyReputationBlocklist("delivered", "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "reputation blocklist hit" {
		t.Fatalf("reason = %q, want reputation blocklist hit", reason)
	}
	if threat := classifyThreat(ev); threat != "PHISHING" {
		t.Fatalf("threat = %q, want PHISHING", threat)
	}
}

func TestReputationAllowlistDoesNotQuarantine(t *testing.T) {
	ev := &Event{Symbols: map[string]any{"RCVD_IN_DNSWL": true}}
	got, reason := applyReputationBlocklist("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("allowlist symbol changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestMailcowWhitelistPreventsRocketMortgagePhishingHeuristicQuarantine(t *testing.T) {
	ev := &Event{
		From:    "bounce@example.p.rocketmortgage.com",
		To:      []string{"barry@qreg.net"},
		Subject: "Save up to $20,000 on your next home purchase.",
		Score:   -9995.23,
		Symbols: map[string]any{
			"MAILCOW_WHITE":      map[string]any{"score": -9999.0},
			"BAYES_HAM":          map[string]any{"score": -5.5},
			"PHISHING":           map[string]any{"score": 2.0},
			"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
			"DMARC_POLICY_ALLOW": map[string]any{"score": 0.0},
			"R_SPF_FAIL":         map[string]any{"score": 0.0},
			"HAS_LIST_UNSUB":     map[string]any{"score": -0.01},
		},
	}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("auth changed whitelisted marketing mail to %q/%q", got, reason)
	}
	got, reason = applyReputationBlocklist(got, reason, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("mailcow-whitelisted marketing mail changed to %q/%q, want delivered/empty", got, reason)
	}
	got, reason = applyThreatSignalDisposition(got, reason, ev)
	if got != "tagged" || reason != "phishing signal hit" {
		t.Fatalf("phishing heuristic changed to %q/%q, want tagged/phishing signal hit", got, reason)
	}
}

func TestURIBLBlockedDoesNotCountAsReputationHit(t *testing.T) {
	ev := &Event{Symbols: map[string]any{
		"R_SPF_ALLOW":        map[string]any{"score": -0.2},
		"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
		"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
		"URIBL_BLOCKED":      map[string]any{"score": 0.0},
	}}
	got, reason := applyReputationBlocklist("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("URIBL lookup failure changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("threat = %q, want empty", threat)
	}
}

func TestDNSWLLookupFailureDoesNotMaskDBLSpam(t *testing.T) {
	ev := &Event{Symbols: map[string]any{
		"R_SPF_ALLOW":        map[string]any{"score": -0.2},
		"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
		"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
		"DNSWL_BLOCKED":      map[string]any{"score": 0.0},
		"DBL_SPAM":           map[string]any{"score": 6.5},
	}}
	got, reason := applyReputationBlocklist("tagged", "score >= spam_threshold", ev)
	if got != "quarantined" || reason != "reputation blocklist hit" {
		t.Fatalf("DBL_SPAM with DNSWL_BLOCKED changed to %q/%q, want quarantined/reputation", got, reason)
	}
	if threat := classifyThreat(ev); threat != "REPUTATION" {
		t.Fatalf("threat = %q, want REPUTATION", threat)
	}
}

func TestReceivedSpamhausPBLZeroScoreDoesNotCountAsReputationHit(t *testing.T) {
	ev := &Event{Symbols: map[string]any{
		"R_SPF_ALLOW":           map[string]any{"score": -0.2},
		"R_DKIM_ALLOW":          map[string]any{"score": -0.2},
		"DMARC_POLICY_ALLOW":    map[string]any{"score": -0.5},
		"RECEIVED_SPAMHAUS_PBL": map[string]any{"score": 0.0},
		"RWL_MAILSPIKE_GOOD":    map[string]any{"score": -0.1},
		"DNSWL_BLOCKED":         map[string]any{"score": 0.0},
		"DWL_DNSWL_BLOCKED":     map[string]any{"score": 0.0},
		"URIBL_BLOCKED":         map[string]any{"score": 0.0},
		"RCVD_VIA_SMTP_AUTH":    map[string]any{"score": 0.0},
		"PREVIOUSLY_DELIVERED":  map[string]any{"score": 0.0},
		"MID_RHS_MATCH_FROM":    map[string]any{"score": 0.0},
		"FROM_EQ_ENVFROM":       map[string]any{"score": 0.0},
		"TO_MATCH_ENVRCPT_ALL":  map[string]any{"score": 0.0},
		"RCPT_COUNT_ONE":        map[string]any{"score": 0.0},
		"RCVD_TLS_LAST":         map[string]any{"score": 0.0},
		"ARC_NA":                map[string]any{"score": 0.0},
		"ASN":                   map[string]any{"score": 0.0},
		"DKIM_TRACE":            map[string]any{"score": 0.0},
		"FROM_HAS_DN":           map[string]any{"score": 0.0},
		"MIME_GOOD":             map[string]any{"score": -0.1},
		"MIME_TRACE":            map[string]any{"score": 0.0},
		"MV_CASE":               map[string]any{"score": 0.5},
		"RCVD_COUNT_TWO":        map[string]any{"score": 0.0},
		"TO_DN_ALL":             map[string]any{"score": 0.0},
	}}
	got, reason := applyAuthEnforcement("delivered", "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("authenticated Test 2-like mail changed to %q/%q after auth", got, reason)
	}
	got, reason = applyReputationBlocklist(got, reason, ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("zero-score received-chain PBL changed to %q/%q, want delivered/empty", got, reason)
	}
	if threat := classifyThreat(ev); threat != "" {
		t.Fatalf("threat = %q, want empty", threat)
	}
}

func TestChallengeResponseHoldsUnknownInboundSender(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{Direction: "inbound", From: "sender@example.net", To: []string{"user@example.com"}}
	got, reason := applyChallengeResponseHold("delivered", "", pol, "", ev)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != challenge.ReasonPendingApproval {
		t.Fatalf("reason = %q", reason)
	}
}

func TestChallengeResponseNotifiesUnknownSenderWithMissingAuthentication(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{Direction: "inbound", From: "sender@example.net", To: []string{"user@example.com"}}
	got, reason := applyChallengeResponseHold("quarantined", "sender authentication results missing", pol, "", ev)
	if got != "quarantined" || reason != challenge.ReasonPendingApproval {
		t.Fatalf("missing-auth unknown sender changed to %q/%q, want pending approval", got, reason)
	}
}

func TestChallengeResponseDoesNotOfferDetectedPhishingForApproval(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{
		Direction: "inbound", From: "attacker@example.net", To: []string{"user@example.com"},
		Subject:  "Wallet access verification required",
		BodyText: "Verify your wallet seed phrase immediately to restore access.",
	}
	got, reason := applyChallengeResponseHold("quarantined", "sender authentication results missing", pol, "", ev)
	if got != "quarantined" || reason != "sender authentication results missing" {
		t.Fatalf("detected phishing changed to %q/%q", got, reason)
	}
}

func TestChallengeResponseSkipsAllowedSender(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{
		Direction: "inbound", From: "sender@example.net", To: []string{"user@example.com"},
		ClientHostname: "mail.example.net",
		Symbols:        map[string]any{"DMARC_POLICY_ALLOW": true, "R_SPF_ALLOW": true},
	}
	got, reason := applyChallengeResponseHold("delivered", "", pol, "allow", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("allowed sender changed to %q/%q", got, reason)
	}
}

func TestChallengeResponseHoldsAllowedSenderWithoutVerifiedSource(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	tests := []Event{
		{Direction: "inbound", ClientHostname: "mail.example.net", Symbols: map[string]any{"R_SPF_ALLOW": true}},
		{Direction: "inbound", ClientHostname: "mail.example.net", Symbols: map[string]any{"DMARC_POLICY_ALLOW": true}},
		{Direction: "inbound", Symbols: map[string]any{"DMARC_POLICY_ALLOW": true, "R_DKIM_ALLOW": true}},
	}
	for _, ev := range tests {
		got, reason := applyChallengeResponseHold("delivered", "", pol, "allow", &ev)
		if got != "quarantined" || reason != challenge.ReasonPendingApproval {
			t.Fatalf("unverified allow changed to %q/%q", got, reason)
		}
	}
}

func TestChallengeResponseSkipsOutboundMail(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{Direction: "outbound", From: "user@example.com", To: []string{"recipient@example.net"}}
	got, reason := applyChallengeResponseHold("delivered", "", pol, "", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("outbound mail changed to %q/%q", got, reason)
	}
}

func TestChallengeResponseSkipsDeliveryStatusNotification(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	got, reason := applyChallengeResponseHold("delivered", "", pol, "", deliveryStatusNotificationEvent())
	if got != "delivered" || reason != "" {
		t.Fatalf("delivery status notification changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestChallengeResponseModeEnabledForInactiveMailbox(t *testing.T) {
	if !challengeResponseModeEnabled(true, "disabled", false) {
		t.Fatal("inactive mailbox must not bypass an enabled organization policy")
	}
	if challengeResponseModeEnabled(false, "enabled", false) {
		t.Fatal("inactive mailbox override must not enable a disabled organization policy")
	}
	if challengeResponseModeEnabled(true, "disabled", true) {
		t.Fatal("active mailbox disabled override was ignored")
	}
}

func TestLearnedNotSpamDoesNotOverrideRejected(t *testing.T) {
	got, reason := applyLearnedClassification("rejected", "sender matched blacklist", &classifier.Match{Verdict: "not_spam", SampleCount: 1})
	if got != "rejected" || reason != "sender matched blacklist" {
		t.Fatalf("learned not_spam changed hard reject to %q/%q", got, reason)
	}
}

func deliveryStatusNotificationEvent() *Event {
	raw := "From: MAILER-DAEMON@example.com\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n" +
		"\r\n--dsn\r\nContent-Type: message/delivery-status\r\n\r\n"
	return &Event{
		Direction:     "inbound",
		From:          "",
		To:            []string{"barry@qreg.net"},
		Subject:       "Undelivered Mail Returned to Sender",
		Score:         8.3,
		RawMessageB64: base64.StdEncoding.EncodeToString([]byte(raw)),
		Symbols: map[string]any{
			"BOUNCE": map[string]any{"score": -0.1, "options": []any{"DSN"}},
		},
	}
}

func TestLearnedNotSpamDoesNotOverrideHardQuarantine(t *testing.T) {
	got, reason := applyLearnedClassification("quarantined", "sender failed SPF/DKIM/DMARC authentication", &classifier.Match{Verdict: "not_spam", SampleCount: 1})
	if got != "quarantined" || reason != "sender failed SPF/DKIM/DMARC authentication" {
		t.Fatalf("learned not_spam changed hard quarantine to %q/%q", got, reason)
	}
}

func TestLearnedNotSpamDoesNotOverrideChallengeHold(t *testing.T) {
	got, reason := applyLearnedClassification("quarantined", challenge.ReasonPendingApproval, &classifier.Match{Verdict: "not_spam", SampleCount: 1})
	if got != "quarantined" || reason != challenge.ReasonPendingApproval {
		t.Fatalf("learned not_spam changed challenge hold to %q/%q", got, reason)
	}
}

func TestMailboxCopiesOnlyForDeliveredOrTagged(t *testing.T) {
	for _, disposition := range []string{"delivered", "tagged"} {
		if !shouldCreateMailboxCopy(disposition) {
			t.Fatalf("should create mailbox copy for %q", disposition)
		}
	}
	for _, disposition := range []string{"quarantined", "rejected", "deferred", "failed"} {
		if shouldCreateMailboxCopy(disposition) {
			t.Fatalf("should not create mailbox copy for %q", disposition)
		}
	}
}

func TestDatabaseBrandProfileQuarantinesSpotifyPaymentLure(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "bounces@smtpapi.worldlibertyfinancial.com.co",
		FromName:  "Spotify",
		ReplyTo:   "Spotify@worldlibertyfinancial.com.co",
		Subject:   "Action Required: Update Your Payment Details",
		BodyText:  "We still can't process your payment. You'll lose Spotify Premium. UPDATE DETAILS",
		URLs:      []string{"https://maillinkforward.encharge.io/ls/click?id=example"},
		Symbols: map[string]any{
			"R_SPF_ALLOW":        map[string]any{"score": -0.2},
			"R_DKIM_ALLOW":       map[string]any{"score": -0.2},
			"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
		},
	}
	profiles := append([]protectedBrandProfile(nil), protectedBrandProfiles...)
	profiles = append(profiles, protectedBrandProfile{
		name:          "Spotify",
		terms:         []string{"spotify", "spotify premium"},
		senderDomains: []string{"spotify.com", "scdn.co"},
		cues:          []string{"payment", "billing", "premium", "update"},
	})
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined; reason=%q", got, reason)
	}
	if !strings.Contains(strings.ToLower(reason), "spotify") {
		t.Fatalf("reason = %q, want Spotify brand evidence", reason)
	}
}

func TestDatabaseBrandProfileAllowsAuthenticatedSpotifySender(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "no-reply@spotify.com",
		FromName:  "Spotify",
		Subject:   "Your Spotify Premium receipt",
		BodyText:  "Your payment was received.",
		URLs:      []string{"https://spotify.com/account"},
		Symbols: map[string]any{
			"DMARC_POLICY_ALLOW": map[string]any{"score": -0.5},
		},
	}
	profiles := []protectedBrandProfile{{
		name:          "Spotify",
		terms:         []string{"spotify", "spotify premium"},
		senderDomains: []string{"spotify.com", "scdn.co"},
		cues:          []string{"payment", "billing", "premium", "update"},
	}}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "delivered" || reason != "" {
		t.Fatalf("official Spotify sender changed to %q/%q", got, reason)
	}
}

func TestDatabaseBrandProfileAllowsLegitimateMarketingMentionWithOnlyStaticAssets(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "newsletter@music-news.example",
		FromName:  "Music News",
		Subject:   "Spotify Premium payment options compared",
		BodyText:  "Our independent guide compares Spotify Premium billing plans.",
		URLs:      []string{"https://cdn.music-news.example/images/spotify-premium.png"},
		Symbols:   map[string]any{"DMARC_POLICY_ALLOW": true},
	}
	profiles := []protectedBrandProfile{{
		name: "spotify", terms: []string{"spotify", "spotify premium"},
		senderDomains: []string{"spotify.com", "scdn.co"},
		cues:          []string{"payment", "billing", "premium", "update"},
	}}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "delivered" || reason != "" {
		t.Fatalf("independent marketing mention changed to %q/%q, want delivered/empty", got, reason)
	}
}

func TestDatabaseBrandProfileQuarantinesAuthenticatedLookalikeDomain(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "billing@spotify-account-security.example",
		FromName:  "Spotify Support",
		Subject:   "Spotify payment failed",
		BodyText:  "Your subscription will end. Update payment now to restore access.",
		URLs:      []string{"https://spotify-account-security.example/update-payment"},
		Symbols: map[string]any{
			"R_SPF_ALLOW": true, "R_DKIM_ALLOW": true, "DMARC_POLICY_ALLOW": true,
		},
	}
	profiles := []protectedBrandProfile{{
		name: "spotify", terms: []string{"spotify", "spotify premium"},
		senderDomains: []string{"spotify.com", "scdn.co"},
		cues:          []string{"payment", "billing", "premium", "update"},
	}}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "quarantined" {
		t.Fatalf("authenticated lookalike changed to %q/%q, want quarantined", got, reason)
	}
}

func TestDatabaseBrandProfileQuarantinesPaymentPressureWithoutURL(t *testing.T) {
	ev := &Event{
		Direction: "inbound",
		From:      "billing@unrelated-sender.example",
		Subject:   "Action required for Spotify Premium",
		BodyText:  "We cannot process your payment. Your subscription will end. Update your details now.",
	}
	profiles := []protectedBrandProfile{{
		name: "spotify", terms: []string{"spotify", "spotify premium"},
		senderDomains: []string{"spotify.com", "scdn.co"},
		cues:          []string{"payment", "billing", "premium", "update"},
	}}
	got, reason := applyBrandImpersonationDetectionWithProfiles("delivered", "", "", nil, ev, profiles)
	if got != "quarantined" {
		t.Fatalf("payment pressure changed to %q/%q, want quarantined", got, reason)
	}
	if !strings.Contains(reason, "account or payment pressure") {
		t.Fatalf("reason = %q, want pressure signal", reason)
	}
}

func TestPrioritizedSandboxURLsPrefersCTAOverImagesAndUnsubscribe(t *testing.T) {
	ev := &Event{
		ListUnsubscribe: "<https://mailer.example/unsubscribe?id=123>",
		URLs: []string{
			"https://cdn.example/images/header.png",
			"https://mailer.example/unsubscribe?id=123",
			"https://tracking.example/open.gif?id=123",
			"https://redirect.example/ls/click?id=cta",
			"https://account.example/verify-payment",
		},
	}
	got := prioritizedSandboxURLs(ev)
	if len(got) != 2 {
		t.Fatalf("prioritized URL count = %d, want 2 actionable targets: %#v", len(got), got)
	}
	if got[0] != "https://account.example/verify-payment" ||
		got[1] != "https://redirect.example/ls/click?id=cta" {
		t.Fatalf("prioritized URLs = %#v, want account CTA then redirect CTA", got)
	}
	for _, candidate := range got {
		if strings.Contains(candidate, "unsubscribe") || strings.Contains(candidate, "header.png") {
			t.Fatalf("low-value URL selected ahead of CTA: %q", candidate)
		}
	}
}

func TestPrioritizedSandboxURLsDeduplicatesAndRejectsUnsafeSchemes(t *testing.T) {
	ev := &Event{URLs: []string{
		"javascript:alert(1)",
		"mailto:user@example.com",
		"https://safe.example/login?first=1",
		"https://safe.example/login?second=2",
	}}
	got := prioritizedSandboxURLs(ev)
	if len(got) != 1 || got[0] != "https://safe.example/login?first=1" {
		t.Fatalf("prioritized URLs = %#v, want one normalized HTTPS target", got)
	}
}
