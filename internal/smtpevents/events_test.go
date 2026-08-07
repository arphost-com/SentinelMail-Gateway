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

func TestNormalizeTerminalEventTypes(t *testing.T) {
	tests := map[string]string{
		"sent":       "delivered",
		"delivered":  "delivered",
		"discard":    "discarded",
		"discarded":  "discarded",
		"reject":     "reject",
		"bounced":    "bounced",
		"failed":     "failed",
		"deferred":   "deferred",
		"not-a-type": "",
	}
	for input, want := range tests {
		if got := normalizeEventType(input); got != want {
			t.Fatalf("normalizeEventType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTerminalActionForEvent(t *testing.T) {
	tests := map[string]string{
		"delivered":  "delivered",
		"discarded":  "discarded",
		"reject":     "rejected",
		"bounced":    "bounced",
		"failed":     "failed",
		"deferred":   "",
		"tls_error":  "",
		"disconnect": "",
	}
	for input, want := range tests {
		if got := terminalActionForEvent(input); got != want {
			t.Fatalf("terminalActionForEvent(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCorrelateTerminalOutcomeCastsOccurredAtAsTimestamp(t *testing.T) {
	for _, want := range []string{
		"$6::timestamptz - interval '24 hours'",
		"$6::timestamptz + interval '5 minutes'",
		"received_at - $6::timestamptz",
		"terminal_at = $6::timestamptz",
	} {
		if !strings.Contains(correlateTerminalOutcomeSQL, want) {
			t.Fatalf("correlateTerminalOutcomeSQL missing %q", want)
		}
	}
}
