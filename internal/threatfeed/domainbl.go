package threatfeed

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// DomainBL implements DNS-backed domain reputation lists such as Spamhaus
// DBL. Unlike an IP DNSBL, the value is queried as a normalized domain and is
// never parsed or reversed as an IPv4 address.
type DomainBL struct {
	FeedName string
	Zone     string
	Resolver *net.Resolver
}

func NewDomainBL(name, zone string) *DomainBL {
	return &DomainBL{FeedName: name, Zone: zone, Resolver: &net.Resolver{PreferGo: true}}
}

func (d *DomainBL) Name() string                  { return d.FeedName }
func (d *DomainBL) Kind() Kind                    { return KindDomain }
func (d *DomainBL) Refresh(context.Context) error { return nil }

func (d *DomainBL) Lookup(ctx context.Context, value string) (Result, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if domain == "" || strings.ContainsAny(domain, " /:@") || !strings.Contains(domain, ".") {
		return Result{}, errors.New("domainbl: invalid domain")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := d.Resolver.LookupHost(ctx, domain+"."+d.Zone)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return Result{Hit: false}, nil
		}
		return Result{}, err
	}
	if len(addrs) > 0 {
		return Result{Hit: true, Source: d.FeedName}, nil
	}
	return Result{Hit: false}, nil
}
