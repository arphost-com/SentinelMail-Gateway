package threatfeed

import "testing"

func TestDNSBLListed(t *testing.T) {
	tests := []struct {
		addr    string
		listed  bool
		wantErr bool
	}{
		{"127.0.0.2", true, false},
		{"127.0.0.4", true, false},
		{"127.0.0.11", true, false},
		{"127.0.0.1", false, true},
		{"127.0.0.12", false, true},
		{"127.255.255.252", false, true},
		{"127.255.255.254", false, true},
		{"127.255.255.255", false, true},
		{"127.0.1.2", false, true},
		{"8.8.8.8", false, true},
		{"::1", false, true},
		{"garbage", false, true},
	}
	for _, tt := range tests {
		listed, err := dnsblListed(tt.addr)
		if listed != tt.listed || (err != nil) != tt.wantErr {
			t.Fatalf("dnsblListed(%q) = %v, err=%v; want listed=%v wantErr=%v", tt.addr, listed, err, tt.listed, tt.wantErr)
		}
	}
}

func TestDomainBLListed(t *testing.T) {
	tests := []struct {
		addr    string
		listed  bool
		wantErr bool
	}{
		{"127.0.1.2", true, false},
		{"127.0.1.4", true, false},
		{"127.0.1.102", true, false},
		{"127.0.1.106", true, false},
		{"127.0.1.255", false, true},
		{"127.0.1.1", false, true},
		{"127.0.0.2", false, true},
		{"127.255.255.254", false, true},
		{"1.2.3.4", false, true},
	}
	for _, tt := range tests {
		listed, err := domainblListed(tt.addr)
		if listed != tt.listed || (err != nil) != tt.wantErr {
			t.Fatalf("domainblListed(%q) = %v, err=%v; want listed=%v wantErr=%v", tt.addr, listed, err, tt.listed, tt.wantErr)
		}
	}
}

func TestFirstListed(t *testing.T) {
	if listed, err := firstListed([]string{"127.255.255.254", "127.0.0.2"}, dnsblListed); !listed || err != nil {
		t.Fatalf("one real listing should win, got %v %v", listed, err)
	}
	if listed, err := firstListed([]string{"127.255.255.254"}, dnsblListed); listed || err == nil {
		t.Fatalf("pure error codes must surface an error, got %v %v", listed, err)
	}
	if listed, err := firstListed(nil, dnsblListed); listed || err != nil {
		t.Fatalf("empty answers are a miss, got %v %v", listed, err)
	}
}
