package mail

import (
	"fmt"
	"testing"
)

func TestCampaignFingerprintIgnoresTransportIDsIPsAndTrackingURLs(t *testing.T) {
	first := &Event{
		MessageID: "<one@example>", ClientIP: "178.90.227.243/32",
		From: "admin@trustcard4you.com", To: []string{"barry@qreg.net"},
		Subject:  "Get Your Trust Card Today!",
		BodyText: "Claim card 123456 at https://tracking-one.example/click?id=123456",
	}
	second := &Event{
		MessageID: "<two@example>", ClientIP: "192.0.2.9",
		From: "ADMIN@trustcard4you.com", To: []string{"BARRY@qreg.net"},
		Subject:  "  Get Your Trust Card Today! ",
		BodyText: "Claim card 654321 at https://tracking-two.example/click?id=654321",
	}
	firstFingerprint, _, _, _, _ := campaignFingerprint(first)
	secondFingerprint, _, _, _, _ := campaignFingerprint(second)
	if firstFingerprint != secondFingerprint {
		t.Fatalf("transport variation split campaign: %s != %s", firstFingerprint, secondFingerprint)
	}
}

func TestCampaignFingerprintSeparatesRecipientsAndSubjects(t *testing.T) {
	base := Event{
		From: "admin@trustcard4you.com", To: []string{"barry@qreg.net"},
		Subject: "Get Your Trust Card Today!", BodyText: "Claim your card.",
	}
	baseFingerprint, _, _, _, _ := campaignFingerprint(&base)
	otherRecipient := base
	otherRecipient.To = []string{"other@qreg.net"}
	recipientFingerprint, _, _, _, _ := campaignFingerprint(&otherRecipient)
	otherSubject := base
	otherSubject.Subject = "Unrelated notice"
	subjectFingerprint, _, _, _, _ := campaignFingerprint(&otherSubject)
	if baseFingerprint == recipientFingerprint || baseFingerprint == subjectFingerprint {
		t.Fatal("campaign fingerprint did not separate recipient or subject")
	}
}

func TestTrustCardIncidentShapeAggregates1718Messages(t *testing.T) {
	campaigns := map[string]int{}
	sourceIPs := map[string]struct{}{}
	for i := 0; i < 1718; i++ {
		ipIndex := i % 1101
		ip := fmt.Sprintf("198.51.%d.%d", ipIndex/254, ipIndex%254+1)
		ev := &Event{
			MessageID: fmt.Sprintf("<trust-%d@botnet.example>", i),
			ClientIP:  ip,
			From:      "admin@trustcard4you.com", To: []string{"barry@qreg.net"},
			Subject:  "Get Your Trust Card Today!",
			BodyText: fmt.Sprintf("Get your card at https://bot-%d.example/click?id=%06d", i, i),
		}
		fingerprint, _, _, _, _ := campaignFingerprint(ev)
		campaigns[fingerprint]++
		sourceIPs[ip] = struct{}{}
		if !highConfidenceCampaign("quarantined", "deterministic phishing", "PHISHING") {
			t.Fatal("Trust Card-shaped phishing was not high confidence")
		}
	}
	if len(campaigns) != 1 {
		t.Fatalf("campaign count = %d, want one representative campaign", len(campaigns))
	}
	for _, count := range campaigns {
		if count != 1718 {
			t.Fatalf("campaign copy count = %d, want 1718", count)
		}
	}
	if len(sourceIPs) != 1101 {
		t.Fatalf("unique source IPs = %d, want 1101", len(sourceIPs))
	}
}

func TestHighConfidenceCampaignDoesNotAggregateChallengeOrAuthOnlyMail(t *testing.T) {
	if highConfidenceCampaign("quarantined", "challenge response pending", "CHALLENGE_RESPONSE") {
		t.Fatal("challenge-response mail must not be flood-suppressed")
	}
	if highConfidenceCampaign("quarantined", "sender failed SPF/DKIM/DMARC authentication", "") {
		t.Fatal("authentication-only quarantine must not be flood-suppressed")
	}
}
