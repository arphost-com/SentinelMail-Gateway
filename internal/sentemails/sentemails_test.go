package sentemails

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeAddressesDeduplicatesAndParsesDisplayNames(t *testing.T) {
	got := normalizeAddresses([]string{
		`"Abuse Desk" <Abuse@Example.COM>`,
		"abuse@example.com",
		" ops@example.net ",
		"",
	})
	want := []string{"abuse@example.com", "ops@example.net"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSanitizeHeaderRemovesNewlinesAndTruncates(t *testing.T) {
	input := "Subject\r\nBcc: victim@example.com"
	got := sanitizeHeader(input)
	if got != "Subject  Bcc: victim@example.com" {
		t.Fatalf("got %q", got)
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if len(sanitizeHeader(string(long))) != 255 {
		t.Fatal("long header was not truncated")
	}
}

func TestResendMetadataPreservesOriginalAndMarksSource(t *testing.T) {
	sourceID := uuid.New()
	raw := json.RawMessage(`{"source_ip":"203.0.113.5","resent":false}`)
	got := resendMetadata(raw, sourceID)
	if got["resent"] != true {
		t.Fatalf("resent = %#v, want true", got["resent"])
	}
	if got["resent_from_email_id"] != sourceID.String() {
		t.Fatalf("source id = %#v, want %s", got["resent_from_email_id"], sourceID)
	}
	if got["source_ip"] != "203.0.113.5" {
		t.Fatalf("source_ip = %#v", got["source_ip"])
	}
}
