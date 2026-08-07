package brandintel

import "testing"

func TestMergeBrandUpdateNormalizesReviewedProfile(t *testing.T) {
	current := BrandDTO{
		Slug: "spotify", Name: "Spotify", Aliases: []string{"spotify"},
		OfficialDomains: []string{"spotify.com"}, Protected: false, Active: true,
	}
	aliases := []string{" Spotify ", "SPOTIFY PREMIUM", "spotify"}
	domains := []string{" Spotify.com ", "SCdn.co"}
	protected := true
	priority := 920
	got, err := mergeBrandUpdate(current, updateBrandRequest{
		Aliases: &aliases, OfficialDomains: &domains, Protected: &protected, Priority: &priority,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Aliases) != 2 || got.Aliases[1] != "spotify premium" {
		t.Fatalf("aliases = %#v", got.Aliases)
	}
	if len(got.OfficialDomains) != 2 || got.OfficialDomains[1] != "scdn.co" {
		t.Fatalf("domains = %#v", got.OfficialDomains)
	}
	if !got.Protected || got.Priority != 920 {
		t.Fatalf("protected/priority = %v/%d", got.Protected, got.Priority)
	}
}

func TestMergeBrandUpdateRejectsProtectedProfileWithoutValidatedDomain(t *testing.T) {
	current := BrandDTO{Slug: "observed", Name: "Observed", Aliases: []string{"observed"}, Active: true}
	protected := true
	_, err := mergeBrandUpdate(current, updateBrandRequest{Protected: &protected})
	if err == nil {
		t.Fatal("expected protected profile without domain to fail")
	}
}

func TestMergeBrandUpdateRejectsURLAsOfficialDomain(t *testing.T) {
	current := BrandDTO{Slug: "spotify", Name: "Spotify", Aliases: []string{"spotify"}, Active: true}
	domains := []string{"https://spotify.com/login"}
	_, err := mergeBrandUpdate(current, updateBrandRequest{OfficialDomains: &domains})
	if err == nil {
		t.Fatal("expected URL-shaped official domain to fail")
	}
}

func TestValidDomainAcceptsRegionalAndPunycodeDomains(t *testing.T) {
	for _, domain := range []string{"amazon.co.uk", "xn--bcher-kva.example", "email.spotify.com"} {
		if !validDomain(domain) {
			t.Fatalf("validDomain(%q) = false", domain)
		}
	}
}
