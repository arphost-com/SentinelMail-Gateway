package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestMFAChallengeRoundtrip covers the happy path of the signed challenge
// token used by /auth/login (when MFA-required) and /auth/mfa/verify.
func TestMFAChallengeRoundtrip(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	uid := uuid.New()

	ch := IssueMFAChallenge(secret, uid)
	if ch.Challenge == "" {
		t.Fatal("empty challenge")
	}
	if ch.ExpiresAt.Before(time.Now()) {
		t.Fatal("expires_at in the past")
	}

	got, err := ParseMFAChallenge(secret, ch.Challenge)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != uid {
		t.Errorf("user id roundtrip mismatch: got %s want %s", got, uid)
	}
}

func TestMFAChallengeRejectsTamper(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	ch := IssueMFAChallenge(secret, uuid.New())

	// Flip a byte in the signature half.
	parts := strings.SplitN(ch.Challenge, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected body.sig form, got %q", ch.Challenge)
	}
	// Twiddle a character in the signature; if it happens to round-trip
	// to the same byte, twiddle the next one until different.
	mut := []byte(parts[1])
	for i := range mut {
		old := mut[i]
		mut[i] = mut[i] ^ 1
		if mut[i] != old {
			break
		}
	}
	tampered := parts[0] + "." + string(mut)

	if _, err := ParseMFAChallenge(secret, tampered); err == nil {
		t.Error("expected signature mismatch error, got nil")
	}
}

func TestMFAChallengeRejectsWrongKey(t *testing.T) {
	good := []byte(strings.Repeat("k", 32))
	evil := []byte(strings.Repeat("e", 32))
	ch := IssueMFAChallenge(good, uuid.New())

	if _, err := ParseMFAChallenge(evil, ch.Challenge); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}
