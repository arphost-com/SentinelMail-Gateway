package threatfeed

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// DNSBL implements an IP-based RBL via DNS A-record queries.
// Spamhaus ZEN, SpamCop, Barracuda — all share this query pattern.
type DNSBL struct {
	FeedName string // human label, e.g. "spamhaus_zen"
	Zone     string // RBL zone, e.g. "zen.spamhaus.org"
	Resolver *net.Resolver
}

func NewDNSBL(name, zone string) *DNSBL {
	return &DNSBL{
		FeedName: name,
		Zone:     zone,
		Resolver: &net.Resolver{PreferGo: true},
	}
}

func (d *DNSBL) Name() string { return d.FeedName }
func (d *DNSBL) Kind() Kind   { return KindIP }

// Refresh is a no-op for DNS-backed RBLs — they're queried live, not cached.
func (d *DNSBL) Refresh(_ context.Context) error { return nil }

func (d *DNSBL) Lookup(ctx context.Context, value string) (Result, error) {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return Result{}, errors.New("dnsbl: invalid IPv4")
	}
	rev := reverseIPv4(ip.To4())
	q := rev + "." + d.Zone

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	addrs, err := d.Resolver.LookupHost(ctx, q)
	if err != nil {
		// NXDOMAIN → not listed. Anything else → couldn't reach DNS; downgrade
		// to a miss so we keep mail flowing (Registry logs the error).
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return Result{Hit: false}, nil
		}
		return Result{}, err
	}
	if len(addrs) > 0 {
		return Result{Hit: true, Source: d.FeedName, Metadata: map[string]any{"response": addrs}}, nil
	}
	return Result{Hit: false}, nil
}

func reverseIPv4(ip net.IP) string {
	parts := strings.Split(ip.String(), ".")
	if len(parts) != 4 {
		return ip.String()
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}
