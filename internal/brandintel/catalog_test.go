package brandintel

import "testing"

func TestDefaultCatalogHasSupportedSizeAndSpotify(t *testing.T) {
	profiles, err := parseDefaults(defaultBrands)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 100 || len(profiles) > 1000 {
		t.Fatalf("default profile count = %d, want 100..1000", len(profiles))
	}
	var spotify *seedProfile
	for i := range profiles {
		if profiles[i].Slug == "spotify" {
			spotify = &profiles[i]
			break
		}
	}
	if spotify == nil {
		t.Fatal("Spotify profile missing")
	}
	if len(spotify.OfficialDomains) == 0 || spotify.OfficialDomains[0] != "spotify.com" {
		t.Fatalf("Spotify domains = %#v", spotify.OfficialDomains)
	}
}

func TestParseDefaultsRejectsDuplicateSlugs(t *testing.T) {
	_, err := parseDefaults(`
one|One|one|one.example|identity|10
one|One Again|one again|one-again.example|identity|9
`)
	if err == nil {
		t.Fatal("expected duplicate slug error")
	}
}
