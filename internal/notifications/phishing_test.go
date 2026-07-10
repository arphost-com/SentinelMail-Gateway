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
