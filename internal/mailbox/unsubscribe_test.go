package mailbox

import (
	"net"
	"net/url"
	"testing"
)

func TestParseUnsubscribeInfoAllowsHTTPSAndMailto(t *testing.T) {
	info := parseUnsubscribeInfo(
		`<mailto:unsubscribe@example.com?subject=remove>, <https://lists.example.com/unsubscribe?id=123#token>`,
		`List-Unsubscribe=One-Click`,
	)
	if info == nil {
		t.Fatal("info is nil")
	}
	if !info.Available {
		t.Fatal("unsubscribe should be available")
	}
	if !info.OneClick {
		t.Fatal("one-click flag should be detected")
	}
	if len(info.Options) != 2 {
		t.Fatalf("options = %d, want 2", len(info.Options))
	}
	if info.Options[0].Type != "mailto" {
		t.Fatalf("first option type = %q, want mailto", info.Options[0].Type)
	}
	if got, want := info.Options[1].URL, "https://lists.example.com/unsubscribe?id=123"; got != want {
		t.Fatalf("https URL = %q, want %q", got, want)
	}
}

func TestParseUnsubscribeInfoFiltersUnsafeTargets(t *testing.T) {
	info := parseUnsubscribeInfo(
		`<javascript:alert(1)>, <http://lists.example.com/u>, <https://localhost/u>, <https://192.168.1.10/u>, <https://user@lists.example.com/u>, <mailto:unsubscribe@example.com?subject=x%0d%0abcc:y@example.com>, <https://lists.example.com/u>`,
		``,
	)
	if info == nil {
		t.Fatal("info is nil")
	}
	if len(info.Options) != 1 {
		t.Fatalf("options = %d, want 1", len(info.Options))
	}
	if got, want := info.Options[0].URL, "https://lists.example.com/u"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestParseUnsubscribeInfoReturnsNilWhenNoSafeTargets(t *testing.T) {
	info := parseUnsubscribeInfo(`<http://lists.example.com/u>, <mailto:not an address>`, ``)
	if info != nil {
		t.Fatalf("info = %#v, want nil", info)
	}
}

func TestParseMailtoUnsubscribe(t *testing.T) {
	to, subject, body, err := parseMailtoUnsubscribe(
		`mailto:list@example.com?subject=remove%20me&body=unsubscribe%0Athanks`,
		"user@example.net",
	)
	if err != nil {
		t.Fatalf("parseMailtoUnsubscribe returned error: %v", err)
	}
	if len(to) != 1 || to[0].Address != "list@example.com" {
		t.Fatalf("to = %#v, want list@example.com", to)
	}
	if subject != "remove me" {
		t.Fatalf("subject = %q, want remove me", subject)
	}
	if body != "unsubscribe\r\nthanks" {
		t.Fatalf("body = %q, want CRLF-normalized body", body)
	}
}

func TestParseMailtoUnsubscribeDefaultsBody(t *testing.T) {
	_, subject, body, err := parseMailtoUnsubscribe(`mailto:list@example.com`, "User@Example.NET")
	if err != nil {
		t.Fatalf("parseMailtoUnsubscribe returned error: %v", err)
	}
	if subject != "unsubscribe" {
		t.Fatalf("subject = %q, want unsubscribe", subject)
	}
	if body != "Please unsubscribe user@example.net from this mailing list." {
		t.Fatalf("body = %q", body)
	}
}

func TestSafeUnsubscribeURLRequiresHTTPSExternalHost(t *testing.T) {
	tests := map[string]bool{
		"https://lists.example.com/u":      true,
		"http://lists.example.com/u":       false,
		"https://localhost/u":              false,
		"https://192.168.1.10/u":           false,
		"https://user@lists.example.com/u": false,
	}
	for raw, want := range tests {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if got := safeUnsubscribeURL(parsed); got != want {
			t.Fatalf("safeUnsubscribeURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestSafeOutboundIPRejectsPrivateAndAllowsPublic(t *testing.T) {
	if safeOutboundIP(net.ParseIP("192.168.1.10")) {
		t.Fatal("private IP should be rejected")
	}
	if !safeOutboundIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public IP should be allowed")
	}
}

func TestApplyAnalysisDoesNotLabelDeliveredWarningAsPhishing(t *testing.T) {
	msg := &Message{
		Subject:  ptrString("Security alert: confirm your account"),
		BodyText: "There was unusual activity. Sign in to review.",
		Verdict:  "unreviewed",
	}
	applyAnalysis(msg)
	if msg.EmailType != "Clean or wanted mail" {
		t.Fatalf("EmailType = %q, want Clean or wanted mail", msg.EmailType)
	}
	if msg.ScamWarning == "" {
		t.Fatal("expected scam warning to remain available")
	}
}

func TestMailboxEmailTypeUsesPhishingReason(t *testing.T) {
	if got := mailboxEmailType("phishing signal hit"); got != "Possible phishing" {
		t.Fatalf("mailboxEmailType = %q, want Possible phishing", got)
	}
	if got := mailboxEmailType("detected credential phishing"); got != "Likely phishing" {
		t.Fatalf("mailboxEmailType = %q, want Likely phishing", got)
	}
}

func ptrString(value string) *string {
	return &value
}
