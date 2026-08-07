package bootstrap

import "testing"

func TestNormalizedSystemFromAddress(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "empty", value: " ", want: ""},
		{name: "mailbox", value: "Abuse-Reports@ARPHost.com", want: "abuse-reports@arphost.com"},
		{name: "display name", value: "SentinelMail <reports@example.com>", want: "reports@example.com"},
		{name: "invalid", value: "not-an-address", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizedSystemFromAddress(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizedSystemFromAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizedSystemFromAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}
