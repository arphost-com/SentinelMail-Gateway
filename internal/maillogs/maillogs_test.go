package maillogs

import (
	"strings"
	"testing"
)

func TestMailLogEmailTypeCaseMatchesReportBuckets(t *testing.T) {
	got := mailLogEmailTypeCase("mail_logs")
	for _, want := range []string{
		"User confirmed clean",
		"User reported threat",
		"User reported spam",
		"Scanner confirmed threat",
		"Possible phishing",
		"Likely spam",
		"Clean or wanted mail",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("mailLogEmailTypeCase missing %q in %s", want, got)
		}
	}
}

func TestMailLogThreatCategoryCaseMatchesReportBuckets(t *testing.T) {
	got := mailLogThreatCategoryCase("mail_logs")
	for _, want := range []string{
		"Sender blocklist",
		"Reputation blocklist",
		"Phishing / impersonation",
		"Malware",
		"Spam content",
		"Rejected / failed",
		"Clean or low risk",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("mailLogThreatCategoryCase missing %q in %s", want, got)
		}
	}
}
