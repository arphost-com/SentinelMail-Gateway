package mail

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arphost/sentinelmail-gateway/internal/challenge"
	"github.com/arphost/sentinelmail-gateway/internal/classifier"
	"github.com/arphost/sentinelmail-gateway/internal/policies"
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

func TestRejectThresholdQuarantinesForReview(t *testing.T) {
	got, reason := decide(&policies.Policy{SpamThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 15}, &Event{Score: 20})
	if got != "quarantined" {
		t.Fatalf("disposition = %q, want quarantined", got)
	}
	if reason != "score >= reject_threshold" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestQuarantineActionTagDeliversOverThresholdAsTagged(t *testing.T) {
	pol := &policies.Policy{
		SpamThreshold:       5,
		QuarantineThreshold: 10,
		RejectThreshold:     15,
		QuarantineAction:    "tag",
	}
	for _, score := range []float64{11, 20} {
		got, reason := decide(pol, &Event{Score: score})
		if got != "tagged" {
			t.Fatalf("score %v disposition = %q, want tagged", score, got)
		}
		if reason == "" {
			t.Fatalf("score %v reason is empty", score)
		}
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

func TestSenderListActionAllowsScoreBasedQuarantine(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "score >= quarantine_threshold", "allow", true)
	if got != "delivered" || reason != "sender matched allowlist" {
		t.Fatalf("allowlist changed to %q/%q, want delivered/allowlist", got, reason)
	}
}

func TestSenderListActionDoesNotAllowHardQuarantine(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "sender failed SPF/DKIM/DMARC authentication", "allow", true)
	if got != "quarantined" || reason != "sender failed SPF/DKIM/DMARC authentication" {
		t.Fatalf("allowlist changed hard quarantine to %q/%q", got, reason)
	}
}

func TestSenderListActionAllowsReputationQuarantine(t *testing.T) {
	got, reason := applySenderListAction("quarantined", "reputation blocklist hit", "allow", true)
	if got != "delivered" || reason != "sender matched allowlist" {
		t.Fatalf("allowlist changed reputation quarantine to %q/%q, want delivered/allowlist", got, reason)
	}
}

func TestSenderListActionAllowsPhishingSignalTag(t *testing.T) {
	got, reason := applySenderListAction("tagged", "phishing signal hit", "allow", true)
	if got != "delivered" || reason != "sender matched allowlist" {
		t.Fatalf("allowlist changed phishing tag to %q/%q, want delivered/allowlist", got, reason)
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

func TestChallengeResponseSkipsAllowedSender(t *testing.T) {
	pol := &policies.Policy{Settings: map[string]any{"challenge_response_enabled": true}}
	ev := &Event{Direction: "inbound", From: "sender@example.net", To: []string{"user@example.com"}}
	got, reason := applyChallengeResponseHold("delivered", "", pol, "allow", ev)
	if got != "delivered" || reason != "" {
		t.Fatalf("allowed sender changed to %q/%q", got, reason)
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

func TestLearnedNotSpamDoesNotOverrideRejected(t *testing.T) {
	got, reason := applyLearnedClassification("rejected", "sender matched blacklist", &classifier.Match{Verdict: "not_spam", SampleCount: 1})
	if got != "rejected" || reason != "sender matched blacklist" {
		t.Fatalf("learned not_spam changed hard reject to %q/%q", got, reason)
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
