package notifications

import (
	"testing"
	"time"
)

func TestShouldSendHonorsCadence(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-2 * time.Hour)
	yesterday := now.Add(-25 * time.Hour)
	lastWeek := now.Add(-8 * 24 * time.Hour)

	tests := []struct {
		name      string
		frequency string
		lastSent  *time.Time
		want      bool
	}{
		{name: "immediate always", frequency: "immediate", lastSent: &recent, want: true},
		{name: "daily skips recent", frequency: "daily", lastSent: &recent, want: false},
		{name: "daily after day", frequency: "daily", lastSent: &yesterday, want: true},
		{name: "weekly skips recent", frequency: "weekly", lastSent: &yesterday, want: false},
		{name: "weekly after week", frequency: "weekly", lastSent: &lastWeek, want: true},
		{name: "default weekly no previous alert", frequency: "", lastSent: nil, want: true},
		{name: "off skips", frequency: "off", lastSent: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSend(tt.frequency, tt.lastSent, now); got != tt.want {
				t.Fatalf("shouldSend() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChallengeDigestDueHonorsCadenceAndRetry(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	recentAttempt := now.Add(-5 * time.Minute)
	oldAttempt := now.Add(-16 * time.Minute)
	recentSent := now.Add(-30 * time.Minute)
	recentSuccessAttempt := recentSent.Add(-time.Second)
	equalSuccessAttempt := recentSent
	oldSent := now.Add(-25 * time.Hour)
	newPending := now.Add(-2 * time.Minute)
	oldPending := now.Add(-2 * time.Hour)

	tests := []struct {
		name      string
		frequency string
		attempt   *time.Time
		sent      *time.Time
		pending   time.Time
		want      bool
	}{
		{name: "new immediate approval", frequency: "immediate", attempt: &recentSuccessAttempt, sent: &recentSent, pending: newPending, want: true},
		{name: "successful claim does not back off next message", frequency: "immediate", attempt: &equalSuccessAttempt, sent: &recentSent, pending: newPending, want: true},
		{name: "no duplicate immediate approval", frequency: "immediate", sent: &recentSent, pending: oldPending, want: false},
		{name: "retry backoff", frequency: "immediate", attempt: &recentAttempt, pending: newPending, want: false},
		{name: "retry after backoff", frequency: "immediate", attempt: &oldAttempt, pending: newPending, want: true},
		{name: "hourly waits", frequency: "hourly", sent: &recentSent, pending: newPending, want: false},
		{name: "daily due", frequency: "daily", sent: &oldSent, pending: oldPending, want: true},
		{name: "invalid fails closed", frequency: "off", pending: newPending, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeDigestDue(tt.frequency, tt.attempt, tt.sent, tt.pending, now); got != tt.want {
				t.Fatalf("challengeDigestDue() = %v, want %v", got, tt.want)
			}
		})
	}
}
