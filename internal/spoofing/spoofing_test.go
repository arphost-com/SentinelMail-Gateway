package spoofing

import (
	"encoding/json"
	"testing"
)

func TestAnalyzeFlagsDMARCRejectReason(t *testing.T) {
	got := Analyze("sender failed DMARC reject policy", nil)
	if got.Status != "suspected_spoof" {
		t.Fatalf("status = %q, want suspected_spoof", got.Status)
	}
	if got.Warning == "" {
		t.Fatal("expected spoof warning")
	}
	if len(got.Signals) != 1 || got.Signals[0] != "DMARC reject policy failed" {
		t.Fatalf("signals = %#v", got.Signals)
	}
}

func TestAnalyzeFlagsAuthSymbols(t *testing.T) {
	symbols, _ := json.Marshal(map[string]any{
		"R_SPF_SOFTFAIL":        true,
		"DMARC_POLICY_REJECT":   map[string]any{"score": 4},
		"R_DKIM_REJECT":         true,
		"DMARC_POLICY_REJECT_2": true,
	})
	got := Analyze("", symbols)
	if got.Status != "suspected_spoof" {
		t.Fatalf("status = %q, want suspected_spoof", got.Status)
	}
	want := []string{"SPF softfail", "DKIM failed"}
	for _, signal := range want {
		if !hasString(got.Signals, signal) {
			t.Fatalf("signals %#v missing %q", got.Signals, signal)
		}
	}
	if !hasString(got.Signals, "DMARC reject policy failed") {
		t.Fatalf("signals %#v missing DMARC reject", got.Signals)
	}
}

func TestAnalyzeIgnoresAuthenticatedSymbols(t *testing.T) {
	symbols, _ := json.Marshal(map[string]any{
		"R_SPF_ALLOW":        true,
		"R_DKIM_ALLOW":       true,
		"DMARC_POLICY_ALLOW": true,
	})
	got := Analyze("", symbols)
	if got.Status != "" || got.Warning != "" || len(got.Signals) != 0 {
		t.Fatalf("expected no warning, got %#v", got)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
