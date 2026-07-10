package smtpevents

import (
	"strings"
	"testing"
)

func TestParseQueryBool(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", " yes ", "on"} {
		if !parseQueryBool(value) {
			t.Fatalf("parseQueryBool(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "0", "false", "off", "no", "maybe"} {
		if parseQueryBool(value) {
			t.Fatalf("parseQueryBool(%q) = true, want false", value)
		}
	}
}

func TestSMTPEventNoiseClauseUsesBlocklistedDeliveryNoiseOnly(t *testing.T) {
	clause := smtpEventNoiseClause()
	for _, want := range []string{
		"event_type IN ('deferred', 'bounced', 'failed')",
		"le.action = 'block'::listentry_action",
		"le.scope IN ('system'::listentry_scope, 'org'::listentry_scope, 'domain'::listentry_scope)",
		"to_addr",
	} {
		if !strings.Contains(clause, want) {
			t.Fatalf("smtpEventNoiseClause() missing %q in %s", want, clause)
		}
	}
}
