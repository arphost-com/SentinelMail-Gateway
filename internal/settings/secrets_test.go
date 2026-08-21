package settings

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecretEncryptionRoundTrip(t *testing.T) {
	t.Setenv("SMG_SETTINGS_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	ciphertext, err := encryptSecret("provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "provider-secret" || !strings.HasPrefix(ciphertext, encryptedPrefix) {
		t.Fatalf("secret was not encrypted: %q", ciphertext)
	}
	plaintext, err := decryptSecret(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "provider-secret" {
		t.Fatalf("got %q", plaintext)
	}
}

func TestMaskSecretSettingNeverReturnsCiphertext(t *testing.T) {
	setting := Setting{
		Key:   "ai.openai_api_key",
		Value: json.RawMessage(`"enc:v1:sensitive-ciphertext"`),
	}
	maskSecretSetting(&setting)
	if !setting.Configured {
		t.Fatal("expected configured flag")
	}
	if string(setting.Value) != `""` {
		t.Fatalf("secret was returned: %s", setting.Value)
	}
}

func TestSecretEncryptionRejectsMissingOrWrongKey(t *testing.T) {
	t.Setenv("SMG_SETTINGS_ENCRYPTION_KEY", "")
	if _, err := encryptSecret("provider-secret"); err == nil {
		t.Fatal("expected missing key error")
	}

	t.Setenv("SMG_SETTINGS_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	ciphertext, err := encryptSecret("provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMG_SETTINGS_ENCRYPTION_KEY", strings.Repeat("cd", 32))
	if _, err := decryptSecret(ciphertext); err == nil {
		t.Fatal("expected authentication failure with the wrong key")
	}
}
