// Package spoofing turns stored mail authentication results into UI-friendly
// warnings for messages that look sender-spoofed.
package spoofing

import (
	"encoding/json"
	"strings"
)

type Result struct {
	Status  string   `json:"auth_status,omitempty"`
	Warning string   `json:"spoof_warning,omitempty"`
	Signals []string `json:"spoof_signals,omitempty"`
}

func Analyze(reason string, symbols json.RawMessage) Result {
	reason = strings.TrimSpace(reason)
	symbolNames := symbolNames(symbols)
	signals := make([]string, 0, 4)

	if containsFold(reason, "sender failed DMARC reject policy") {
		signals = append(signals, "DMARC reject policy failed")
	}
	if containsFold(reason, "sender failed DMARC quarantine policy") {
		signals = append(signals, "DMARC quarantine policy failed")
	}
	if containsFold(reason, "sender failed SPF/DKIM/DMARC authentication") {
		signals = append(signals, "SPF, DKIM, or DMARC failed")
	}
	if containsFold(reason, "sender authentication results missing") {
		signals = append(signals, "Sender authentication results missing")
	}

	if hasSymbol(symbolNames, "DMARC_POLICY_REJECT") {
		signals = append(signals, "DMARC reject policy failed")
	}
	if hasSymbol(symbolNames, "DMARC_POLICY_QUARANTINE") {
		signals = append(signals, "DMARC quarantine policy failed")
	}
	if hasSymbol(symbolNames, "R_SPF_FAIL") || hasSymbol(symbolNames, "R_SPF_PERMFAIL") {
		signals = append(signals, "SPF failed")
	}
	if hasSymbol(symbolNames, "R_SPF_SOFTFAIL") {
		signals = append(signals, "SPF softfail")
	}
	if hasSymbolContaining(symbolNames, "DKIM", "FAIL", "REJECT") {
		signals = append(signals, "DKIM failed")
	}

	signals = unique(signals)
	if len(signals) == 0 {
		return Result{}
	}
	return Result{
		Status:  "suspected_spoof",
		Warning: "Possible spoofed email: the sender domain did not pass normal mail authentication checks.",
		Signals: signals,
	}
}

func symbolNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	out := make([]string, 0, len(obj))
	for name := range obj {
		out = append(out, strings.ToUpper(strings.TrimSpace(name)))
	}
	return out
}

func hasSymbol(names []string, want string) bool {
	want = strings.ToUpper(want)
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func hasSymbolContaining(names []string, required string, alternatives ...string) bool {
	required = strings.ToUpper(required)
	for _, name := range names {
		if !strings.Contains(name, required) {
			continue
		}
		for _, alt := range alternatives {
			if strings.Contains(name, strings.ToUpper(alt)) {
				return true
			}
		}
	}
	return false
}

func containsFold(value, substr string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(substr))
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
