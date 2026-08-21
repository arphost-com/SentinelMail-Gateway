package phishingreports

import "testing"

func TestReportableScanVerdictIncludesConfirmedThreats(t *testing.T) {
	for _, verdict := range []string{"phishing", "malicious", "malware"} {
		if !reportableScanVerdict(verdict) {
			t.Fatalf("reportableScanVerdict(%q) = false, want true", verdict)
		}
	}
	for _, verdict := range []string{"suspicious", "clean", "failed", "", "not_spam"} {
		if reportableScanVerdict(verdict) {
			t.Fatalf("reportableScanVerdict(%q) = true, want false", verdict)
		}
	}
}

func TestSuspiciousScanVerdictNeverAutoVerifiesPhishing(t *testing.T) {
	// Suspicious is a heuristic finding, not a confirmed threat. The scan job
	// retains its evidence for review, but it must not create an auto-verified
	// phishing report or rewrite an already-completed delivery disposition.
	if reportableScanVerdict("suspicious") {
		t.Fatal("suspicious scan was reportable, want review-only")
	}
}

func TestScannerDetectionReason(t *testing.T) {
	tests := map[string]string{
		"malware":   "scanner verified malware",
		"phishing":  "scanner verified phishing",
		"malicious": "scanner verified phishing",
	}
	for verdict, want := range tests {
		if got := scannerDetectionReason(verdict); got != want {
			t.Fatalf("scannerDetectionReason(%q) = %q, want %q", verdict, got, want)
		}
	}
}
