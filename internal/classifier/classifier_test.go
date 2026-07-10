package classifier

import "testing"

func TestShouldLearnSenderLevel(t *testing.T) {
	tests := []struct {
		name        string
		verdict     string
		fingerprint string
		from        string
		want        bool
	}{
		{name: "spam", verdict: "spam", fingerprint: "increase length", from: "return@example.com", want: true},
		{name: "phishing", verdict: "phishing", fingerprint: "verify account", from: "login@example.com", want: true},
		{name: "malware", verdict: "malware", fingerprint: "invoice attached", from: "invoice@example.com", want: true},
		{name: "not spam stays exact", verdict: "not_spam", fingerprint: "invoice attached", from: "vendor@example.com", want: false},
		{name: "other stays exact", verdict: "other", fingerprint: "newsletter", from: "news@example.com", want: false},
		{name: "blank subject already sender level", verdict: "spam", fingerprint: "", from: "return@example.com", want: false},
		{name: "blank sender", verdict: "spam", fingerprint: "increase length", from: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldLearnSenderLevel(tt.verdict, tt.fingerprint, tt.from); got != tt.want {
				t.Fatalf("shouldLearnSenderLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectFingerprintKeepsStableTokens(t *testing.T) {
	got := SubjectFingerprint("Increase The Length And Girth Of Your Manhood!!!")
	want := "increase the length and girth your manhood"
	if got != want {
		t.Fatalf("SubjectFingerprint() = %q, want %q", got, want)
	}
}

func TestAnalyzeCommonScamDetectsHomoglyphTaxDocumentPhishing(t *testing.T) {
	got := AnalyzeCommonScam("Υоur tах dосumеntѕ аrе rеаdу !", "")
	if got.EmailType != "Tax document phishing" {
		t.Fatalf("EmailType = %q, want Tax document phishing", got.EmailType)
	}
}

func TestAnalyzeCommonScamDetectsPaymentSupportPhoneScam(t *testing.T) {
	body := `Hello Customer,

We wanted to let you know that $738.40 has been successfully deducted from your account today.

Status Pending - Awaiting Verification

If you did not authorize this transaction, please call our support team immediately to cancel it and secure your account.

Call Support: 2127-556-656 1+`
	got := AnalyzeCommonScam("Transaction pending", body)
	if got.EmailType != "Payment support scam" {
		t.Fatalf("EmailType = %q, want Payment support scam", got.EmailType)
	}
}

func TestAnalyzeCommonScamDetectsMedicalMiracleScam(t *testing.T) {
	body := `A group of scientists from UCLA unveiled a shocking cause for vertigo.

98% of your dizziness bouts are caused by the lack of this crucial nutrient, which should feed and nourish the brain cells responsible for balance.

Simply by adding this essential nutrient to your diet you stop vertigo in its tracks, as well as erase all the brain damage it has done so far.

Watch the Video Presentation
Click Here To Find Out All About The Vertigo Nutrient`
	got := AnalyzeCommonScam("UCLA vertigo research report", body)
	if got.EmailType != "Medical miracle scam" {
		t.Fatalf("EmailType = %q, want Medical miracle scam", got.EmailType)
	}
}

func TestAnalyzeCommonScamDetectsHealthMiracleSpam(t *testing.T) {
	got := AnalyzeCommonScam("scientists reveal an astonishing back pain discovery", "")
	if got.EmailType != "Health miracle spam" {
		t.Fatalf("EmailType = %q, want Health miracle spam", got.EmailType)
	}
}

func TestAnalyzeCommonScamDetectsHomeServicesLeadGenSpam(t *testing.T) {
	got := AnalyzeCommonScam("Is your septic system working properly?", "")
	if got.EmailType != "Home services lead-gen spam" {
		t.Fatalf("EmailType = %q, want Home services lead-gen spam", got.EmailType)
	}
}

func TestAnalyzeCommonScamLeavesOrdinaryPaymentReceiptUncategorized(t *testing.T) {
	body := `Your receipt is ready. You paid Example Store today. Log in directly to view transaction details.`
	got := AnalyzeCommonScam("Receipt for your payment", body)
	if got.EmailType == "Payment support scam" {
		t.Fatalf("ordinary receipt classified as payment support scam: %#v", got)
	}
}
