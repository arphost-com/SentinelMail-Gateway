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
	for _, want := range []string{
		"DMARC_POLICY_REJECT",
		"COALESCE((s.value->>'score')::numeric, 0) > 0",
		"upper(s.key) NOT LIKE '%_BLOCKED'",
		"upper(s.key) NOT LIKE '%DNSFAIL%'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("mailLogThreatCategoryCase missing false-positive guard %q in %s", want, got)
		}
	}
	for _, unwanted := range []string{
		"upper(s.key) LIKE '%DMARC%'",
		"upper(s.key) LIKE '%VIRUS%'",
	} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("mailLogThreatCategoryCase still contains broad match %q in %s", unwanted, got)
		}
	}
}
