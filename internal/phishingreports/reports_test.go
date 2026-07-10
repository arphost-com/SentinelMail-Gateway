package phishingreports

import "testing"

func TestReportableScanVerdictIncludesConfirmedThreats(t *testing.T) {
	for _, verdict := range []string{"phishing", "malicious", "malware"} {
		if !reportableScanVerdict(verdict, []byte(`{}`)) {
			t.Fatalf("reportableScanVerdict(%q) = false, want true", verdict)
		}
	}
	for _, verdict := range []string{"clean", "failed", "", "not_spam"} {
		if reportableScanVerdict(verdict, []byte(`{}`)) {
			t.Fatalf("reportableScanVerdict(%q) = true, want false", verdict)
		}
	}
}

func TestSuspiciousScanVerdictRequiresPhishingEvidence(t *testing.T) {
	privacyRedirect := []byte(`{
		"final_url": "https://www.example.com/en-us/privacy/privacystatement",
		"reasons": ["redirected to different host: www.example.com"]
	}`)
	if reportableScanVerdict("suspicious", privacyRedirect) {
		t.Fatal("privacy redirect was reportable, want ignored")
	}

	credentialRedirect := []byte(`{
		"final_url": "https://ahsolutionsco.com/verify.php?next=/index.html",
		"reasons": ["redirected to different host: ahsolutionsco.com"]
	}`)
	if !reportableScanVerdict("suspicious", credentialRedirect) {
		t.Fatal("credential-themed redirect was ignored, want reportable")
	}

	plainLogin := []byte(`{
		"final_url": "https://portal.example.com/?next=post-id",
		"reasons": ["page contains password input"]
	}`)
	if reportableScanVerdict("suspicious", plainLogin) {
		t.Fatal("plain login page was reportable, want ignored")
	}
}
