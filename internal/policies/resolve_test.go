package policies

import (
	"os"
	"strings"
	"testing"
)

func TestHardcodedDefaultIsSafe(t *testing.T) {
	// The hardcoded fallback exists to keep the gateway safe when the DB has
	// no policies at all. If anyone weakens it, future-them will appreciate
	// the test breaking on the change.
	d := hardcodedDefault
	if d.QuarantineAction != "quarantine" {
		t.Errorf("default action should be quarantine, got %q", d.QuarantineAction)
	}
	if d.RejectThreshold <= d.QuarantineThreshold {
		t.Errorf("reject threshold (%v) must be > quarantine (%v)", d.RejectThreshold, d.QuarantineThreshold)
	}
	if d.QuarantineThreshold <= d.SpamThreshold {
		t.Errorf("quarantine threshold (%v) must be > spam (%v)", d.QuarantineThreshold, d.SpamThreshold)
	}
	if !d.EnableGreylist {
		t.Error("greylisting should be on by default")
	}
	if !d.SenderBlacklistEnabled() {
		t.Error("sender blacklist should be enabled by default")
	}
	if d.ChallengeResponseEnabled() {
		t.Error("challenge-response should be off by default")
	}
	if !d.BrandImpersonationEnabled() {
		t.Error("brand impersonation should be enabled by default")
	}
	if !d.BrandImpersonationDisplayNameEnabled() || !d.BrandImpersonationSubjectEnabled() || !d.BrandImpersonationLinkMismatchEnabled() || !d.BrandImpersonationThirdPartyReceiptsEnabled() {
		t.Error("brand impersonation sub-options should be enabled by default")
	}
}

func TestSenderBlacklistEnabledSetting(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{name: "missing", settings: nil, want: true},
		{name: "true", settings: map[string]any{"sender_blacklist_enabled": true}, want: true},
		{name: "false", settings: map[string]any{"sender_blacklist_enabled": false}, want: false},
		{name: "string false", settings: map[string]any{"sender_blacklist_enabled": "false"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Settings: tt.settings}
			if got := p.SenderBlacklistEnabled(); got != tt.want {
				t.Fatalf("SenderBlacklistEnabled = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallengeResponseEnabledSetting(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{name: "missing", settings: nil, want: false},
		{name: "true", settings: map[string]any{"challenge_response_enabled": true}, want: true},
		{name: "false", settings: map[string]any{"challenge_response_enabled": false}, want: false},
		{name: "string true", settings: map[string]any{"challenge_response_enabled": "true"}, want: true},
		{name: "string off", settings: map[string]any{"challenge_response_enabled": "off"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Settings: tt.settings}
			if got := p.ChallengeResponseEnabled(); got != tt.want {
				t.Fatalf("ChallengeResponseEnabled = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBrandImpersonationSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantMain bool
		wantName bool
		wantSubj bool
		wantLink bool
		wantSafe bool
	}{
		{name: "missing", settings: nil, wantMain: true, wantName: true, wantSubj: true, wantLink: true, wantSafe: true},
		{name: "main false", settings: map[string]any{"brand_impersonation_enabled": false}, wantMain: false, wantName: true, wantSubj: true, wantLink: true, wantSafe: true},
		{name: "string off", settings: map[string]any{"brand_impersonation_enabled": "off"}, wantMain: false, wantName: true, wantSubj: true, wantLink: true, wantSafe: true},
		{name: "sub false", settings: map[string]any{
			"brand_impersonation_enabled":                      true,
			"brand_impersonation_display_name_enabled":         false,
			"brand_impersonation_subject_enabled":              false,
			"brand_impersonation_link_mismatch_enabled":        false,
			"brand_impersonation_third_party_receipts_enabled": false,
		}, wantMain: true, wantName: false, wantSubj: false, wantLink: false, wantSafe: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Settings: tt.settings}
			if got := p.BrandImpersonationEnabled(); got != tt.wantMain {
				t.Fatalf("BrandImpersonationEnabled = %v, want %v", got, tt.wantMain)
			}
			if got := p.BrandImpersonationDisplayNameEnabled(); got != tt.wantName {
				t.Fatalf("BrandImpersonationDisplayNameEnabled = %v, want %v", got, tt.wantName)
			}
			if got := p.BrandImpersonationSubjectEnabled(); got != tt.wantSubj {
				t.Fatalf("BrandImpersonationSubjectEnabled = %v, want %v", got, tt.wantSubj)
			}
			if got := p.BrandImpersonationLinkMismatchEnabled(); got != tt.wantLink {
				t.Fatalf("BrandImpersonationLinkMismatchEnabled = %v, want %v", got, tt.wantLink)
			}
			if got := p.BrandImpersonationThirdPartyReceiptsEnabled(); got != tt.wantSafe {
				t.Fatalf("BrandImpersonationThirdPartyReceiptsEnabled = %v, want %v", got, tt.wantSafe)
			}
		})
	}
}

func TestCommonScamSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantMain bool
		wantCat  bool
	}{
		{name: "missing", settings: nil, wantMain: true, wantCat: true},
		{name: "main false", settings: map[string]any{"common_scam_detection_enabled": false}, wantMain: false, wantCat: true},
		{name: "category false", settings: map[string]any{"common_scam_health_miracle_enabled": false}, wantMain: true, wantCat: false},
		{name: "string off", settings: map[string]any{"common_scam_health_miracle_enabled": "off"}, wantMain: true, wantCat: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Settings: tt.settings}
			if got := p.CommonScamDetectionEnabled(); got != tt.wantMain {
				t.Fatalf("CommonScamDetectionEnabled = %v, want %v", got, tt.wantMain)
			}
			if got := p.CommonScamCategoryEnabled("health_miracle"); got != tt.wantCat {
				t.Fatalf("CommonScamCategoryEnabled = %v, want %v", got, tt.wantCat)
			}
		})
	}
}

// TestResolverCTEHasNoAmbiguousColumns guards against a regression of the
// "column reference 'id' is ambiguous" Postgres error we hit when the
// recursive CTE used a column literally named `id`, which collided with
// policies.id in the SELECT list when JOINed. The fix renamed it to
// `org_id`. We scan the actual resolve.go source — a brittle but cheap
// substitute for a real DB integration test that would catch the same.
func TestResolverCTEHasNoAmbiguousColumns(t *testing.T) {
	raw, err := os.ReadFile("resolve.go")
	if err != nil {
		t.Fatalf("read resolve.go: %v", err)
	}
	src := string(raw)
	if strings.Contains(src, "ancestors(id,") {
		t.Error("recursive CTE column is named `id` again — Postgres will hit " +
			"\"column reference 'id' is ambiguous\". Use a distinct name (org_id).")
	}
	if !strings.Contains(src, "ancestors(org_id") {
		t.Error("expected CTE to declare `ancestors(org_id, ...)` so the SELECT is unambiguous")
	}
}
