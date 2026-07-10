package senderlists

import (
	"strings"
	"testing"
)

func TestNormalizeSenderDomainAcceptsDomainWideForms(t *testing.T) {
	tests := map[string]string{
		"lifelovelupus.com":                   "lifelovelupus.com",
		"@lifelovelupus.com":                  "lifelovelupus.com",
		"*@lifelovelupus.com":                 "lifelovelupus.com",
		"reply@lifelovelupus.com":             "lifelovelupus.com",
		"Life Love <reply@lifelovelupus.com>": "lifelovelupus.com",
	}

	for input, want := range tests {
		got, err := NormalizeSenderDomain(input)
		if err != nil {
			t.Fatalf("NormalizeSenderDomain(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("NormalizeSenderDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeSenderDomainRejectsURL(t *testing.T) {
	if got, err := NormalizeSenderDomain("https://lifelovelupus.com/path"); err == nil {
		t.Fatalf("NormalizeSenderDomain accepted URL as %q", got)
	}
}

func TestNormalizeSenderDomainPattern(t *testing.T) {
	tests := map[string]string{
		"lifelovelupus.com":   "*@lifelovelupus.com",
		"@lifelovelupus.com":  "*@lifelovelupus.com",
		"*@lifelovelupus.com": "*@lifelovelupus.com",
	}
	for input, wantPattern := range tests {
		_, pattern, err := NormalizeSenderDomainPattern(input)
		if err != nil {
			t.Fatalf("NormalizeSenderDomainPattern(%q) returned error: %v", input, err)
		}
		if pattern != wantPattern {
			t.Fatalf("NormalizeSenderDomainPattern(%q) pattern = %q, want %q", input, pattern, wantPattern)
		}
	}
}

func TestNormalizeSenderDomainPatternRejectsAddress(t *testing.T) {
	if _, pattern, err := NormalizeSenderDomainPattern("reply@lifelovelupus.com"); err == nil {
		t.Fatalf("NormalizeSenderDomainPattern accepted address as %q", pattern)
	}
}

func TestRootSenderDomainUsesRegistrableDomain(t *testing.T) {
	tests := map[string]string{
		"return@luies8.t-skills.com":        "t-skills.com",
		"return@live1.dormanhealthcare.com": "dormanhealthcare.com",
		"alerts@mail.example.co.uk":         "example.co.uk",
	}
	for input, want := range tests {
		got, err := RootSenderDomain(input)
		if err != nil {
			t.Fatalf("RootSenderDomain(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("RootSenderDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPatternsForAddressIncludesParentDomains(t *testing.T) {
	got := PatternsForAddress("return@luies8.t-skills.com")
	want := []string{
		"return@luies8.t-skills.com",
		"*@luies8.t-skills.com",
		"luies8.t-skills.com",
		"@luies8.t-skills.com",
		"*@t-skills.com",
		"t-skills.com",
		"@t-skills.com",
	}
	if len(got) != len(want) {
		t.Fatalf("PatternsForAddress length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PatternsForAddress[%d] = %q, want %q; got %#v", i, got[i], want[i], got)
		}
	}
}

func TestListSQLPreservesLikePatterns(t *testing.T) {
	sql := listSQL(" WHERE (le.organization_id IS NULL OR le.organization_id = ANY($1))", 2, 3)
	for _, want := range []string{"LIKE '*@%'", "LIKE '@%'", "NOT LIKE '%@%'", "LIKE '%.' ||"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("listSQL missing %q in:\n%s", want, sql)
		}
	}
	for _, bad := range []string{"%!(", "%!s", "%!d", "%!@", "%!'"} {
		if strings.Contains(sql, bad) {
			t.Fatalf("listSQL contains fmt corruption marker %q in:\n%s", bad, sql)
		}
	}
}
