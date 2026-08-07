package brandintel

import (
	"strings"
	"testing"
)

func TestParsePhishTankCSVRanksKnownTargets(t *testing.T) {
	input := `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
1,https://one.example,https://phishtank.example/1,2026-07-29T01:00:00+00:00,yes,2026-07-29T01:01:00+00:00,yes,Spotify
2,https://two.example,https://phishtank.example/2,2026-07-29T02:00:00+00:00,yes,2026-07-29T02:01:00+00:00,yes,Microsoft
3,https://three.example,https://phishtank.example/3,2026-07-29T03:00:00+00:00,yes,2026-07-29T03:01:00+00:00,yes,Spotify
4,https://four.example,https://phishtank.example/4,2026-07-29T04:00:00+00:00,yes,2026-07-29T04:01:00+00:00,yes,Unknown
`
	got, err := parsePhishTankCSV(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("observations = %d, want 2: %#v", len(got), got)
	}
	if got[0].Name != "Spotify" || got[0].Count != 2 {
		t.Fatalf("top target = %#v, want Spotify count 2", got[0])
	}
	if got[0].FirstSeen.IsZero() || got[0].LastSeen.IsZero() {
		t.Fatalf("Spotify observation times missing: %#v", got[0])
	}
}

func TestParsePhishTankCSVRequiresTargetColumn(t *testing.T) {
	_, err := parsePhishTankCSV(strings.NewReader("phish_id,url\n1,https://example.test\n"))
	if err == nil {
		t.Fatal("expected missing target column error")
	}
}
