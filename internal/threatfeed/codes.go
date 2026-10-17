package threatfeed

import (
	"fmt"
	"net"
)

// DNS reputation lists answer both listings and operational errors as A
// records. Spamhaus uses 127.255.255.0/24 for blocked public resolvers,
// typing errors and exceeded query volume, and DBL answers 127.0.1.255 when
// an IP is queried against the domain list. Treating those as listings turns
// a rate limit into a false positive for every sender, which the registry
// then caches. Only documented listing ranges count as hits; anything else is
// an error the caller logs without caching.

// dnsblListed reports whether an IP blocklist answer is a real listing.
// Spamhaus ZEN documents 127.0.0.2 through 127.0.0.11 and SpamCop uses
// 127.0.0.2, so everything outside 127.0.0.2-127.0.0.11 is not a listing.
func dnsblListed(addr string) (bool, error) {
	ip := net.ParseIP(addr)
	v4 := ip.To4()
	if v4 == nil {
		return false, fmt.Errorf("non IPv4 answer %q", addr)
	}
	if v4[0] != 127 {
		return false, fmt.Errorf("answer %q outside 127.0.0.0/8, possible DNS interception", addr)
	}
	if v4[1] == 255 && v4[2] == 255 {
		return false, fmt.Errorf("list error code %q (blocked resolver, typing error or query volume)", addr)
	}
	if v4[1] == 0 && v4[2] == 0 && v4[3] >= 2 && v4[3] <= 11 {
		return true, nil
	}
	return false, fmt.Errorf("unrecognized return code %q", addr)
}

// domainblListed reports whether a domain blocklist answer is a real listing.
// Spamhaus DBL documents listings inside 127.0.1.0/24 with 127.0.1.255
// reserved for the IP-queries-prohibited error.
func domainblListed(addr string) (bool, error) {
	ip := net.ParseIP(addr)
	v4 := ip.To4()
	if v4 == nil {
		return false, fmt.Errorf("non IPv4 answer %q", addr)
	}
	if v4[0] != 127 {
		return false, fmt.Errorf("answer %q outside 127.0.0.0/8, possible DNS interception", addr)
	}
	if v4[1] == 255 && v4[2] == 255 {
		return false, fmt.Errorf("list error code %q (blocked resolver, typing error or query volume)", addr)
	}
	if v4[1] == 0 && v4[2] == 1 && v4[3] != 255 && v4[3] >= 2 {
		return true, nil
	}
	return false, fmt.Errorf("unrecognized return code %q", addr)
}

// firstListed classifies a full answer set. One real listing makes the value
// listed. If nothing is listed and at least one answer was an error code, the
// error is returned so the registry logs it and avoids caching a false miss
// as a hit.
func firstListed(addrs []string, classify func(string) (bool, error)) (bool, error) {
	var firstErr error
	for _, addr := range addrs {
		listed, err := classify(addr)
		if listed {
			return true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return false, firstErr
}
