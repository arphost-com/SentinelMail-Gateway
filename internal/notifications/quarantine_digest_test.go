package notifications

import (
	"strings"
	"testing"
	"time"
)

func TestDigestSince(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	lastWeek := now.Add(-8 * 24 * time.Hour)
	ancient := now.Add(-90 * 24 * time.Hour)

	tests := []struct {
		name      string
		frequency string
		lastSent  *time.Time
		want      time.Time
	}{
		{name: "daily first digest covers one day", frequency: "daily", want: now.Add(-24 * time.Hour)},
		{name: "weekly first digest covers one week", frequency: "weekly", want: now.Add(-7 * 24 * time.Hour)},
		{name: "resumes from previous alert", frequency: "daily", lastSent: &lastWeek, want: lastWeek},
		{name: "lookback is capped", frequency: "weekly", lastSent: &ancient, want: now.Add(-digestLookbackCap)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := digestSince(tt.frequency, tt.lastSent, now); !got.Equal(tt.want) {
				t.Fatalf("digestSince() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTextQuarantineDigestListsEveryItem(t *testing.T) {
	since := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	items := []digestItem{
		{ReceivedAt: since.Add(2 * time.Hour), ToAddr: "a@example.com", FromAddr: "spam@bad.example", Subject: "Buy now", ThreatClass: "SPAM"},
		{ReceivedAt: since.Add(time.Hour), ToAddr: "a@example.com", FromAddr: "phish@bad.example", Subject: "Reset your password", ThreatClass: "PHISHING"},
		{ReceivedAt: since.Add(30 * time.Minute), ToAddr: "b@example.com", FromAddr: "tag@bad.example", Subject: "Newsletter", Tagged: true},
	}
	text := textQuarantineDigest("a@example.com", items, 7, since, "https://mx.example.com/quarantine")
	for _, want := range []string{"spam@bad.example", "phish@bad.example", "tag@bad.example", "tagged as spam", "phishing", "Showing the newest 3 of 7"} {
		if !strings.Contains(text, want) {
			t.Fatalf("digest text missing %q in:\n%s", want, text)
		}
	}
	htmlBody := htmlQuarantineDigest("a@example.com", items, 7, since, "https://mx.example.com/quarantine")
	for _, want := range []string{"Reset your password", "tagged as spam", "Showing the newest 3 of 7"} {
		if !strings.Contains(htmlBody, want) {
			t.Fatalf("digest html missing %q", want)
		}
	}
}

func TestAlertSubjectKind(t *testing.T) {
	if subj, kind := alertSubjectKind("PHISHING"); kind != "phishing_alert" || !strings.Contains(subj, "phishing") {
		t.Fatalf("unexpected phishing subject/kind %q %q", subj, kind)
	}
	for _, class := range []string{"SPAM", "REPUTATION", "VIRUS", ""} {
		if subj, kind := alertSubjectKind(class); kind != "quarantine_alert" || !strings.Contains(subj, "suspicious") {
			t.Fatalf("unexpected subject/kind for %q, got %q %q", class, subj, kind)
		}
	}
}

func TestAlertCategory(t *testing.T) {
	if got := alertCategory(""); got != "quarantined" {
		t.Fatalf("alertCategory empty = %q", got)
	}
	if got := alertCategory("CHALLENGE_RESPONSE"); got != "challenge response" {
		t.Fatalf("alertCategory = %q", got)
	}
}
