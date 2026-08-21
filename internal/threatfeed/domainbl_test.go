package threatfeed

import (
	"strings"
	"testing"
)

func TestDomainBLUsesDomainKind(t *testing.T) {
	feed := NewDomainBL("spamhaus_dbl", "dbl.spamhaus.org")
	if feed.Kind() != KindDomain {
		t.Fatalf("Kind() = %q, want %q", feed.Kind(), KindDomain)
	}
}

func TestNormalizeLookupValueCanonicalizesDomains(t *testing.T) {
	if got := normalizeLookupValue(KindDomain, " Example.COM. "); got != "example.com" {
		t.Fatalf("normalizeLookupValue() = %q", got)
	}
}

func TestThreatCacheKeyDoesNotExposeObservedValue(t *testing.T) {
	key := threatCacheKey(KindURL, "https://example.test/path?token=secret")
	if key == "" || strings.Contains(key, "example.test") || strings.Contains(key, "secret") {
		t.Fatalf("unsafe cache key %q", key)
	}
}
