package asn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.RWMutex
	cache = map[string]string{}
)

// LookupOrg returns the organisation name for an IP via Team Cymru's DNS service.
// Two TXT lookups: IP → ASN number, then ASN number → org name.
// Results are cached in-process. Returns empty string on failure or timeout.
func LookupOrg(ip string) string {
	mu.RLock()
	if v, ok := cache[ip]; ok {
		mu.RUnlock()
		return v
	}
	mu.RUnlock()

	org := query(ip)

	mu.Lock()
	cache[ip] = org
	mu.Unlock()
	return org
}

func query(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	var originHost string
	if v4 := parsed.To4(); v4 != nil {
		originHost = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		originHost = ipv6Origin(parsed)
	}

	asnNum := txtFirst(originHost)
	if asnNum == "" {
		return ""
	}
	// Response: "16509 | 108.138.0.0/15 | US | arin | 2018-05-31"
	asnNum = strings.TrimSpace(strings.SplitN(asnNum, " | ", 2)[0])

	orgTxt := txtFirst(fmt.Sprintf("AS%s.asn.cymru.com", asnNum))
	if orgTxt == "" {
		return ""
	}
	// Response: "16509 | US | arin | 2005-09-06 | AMAZON-02, US"
	parts := strings.Split(orgTxt, " | ")
	if len(parts) < 2 {
		return ""
	}
	org := strings.TrimSpace(parts[len(parts)-1])

	// Strip trailing 2-letter country code suffix (", US")
	if comma := strings.LastIndex(org, ", "); comma != -1 && len(org)-comma-2 == 2 {
		org = strings.TrimSpace(org[:comma])
	}
	return org
}

func txtFirst(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var r net.Resolver
	txts, err := r.LookupTXT(ctx, host)
	if err != nil || len(txts) == 0 {
		return ""
	}
	return txts[0]
}

// ipv6Origin builds the origin6.asn.cymru.com query for an IPv6 address.
// Nibbles are reversed LSB-first as per ip6.arpa convention.
func ipv6Origin(ip net.IP) string {
	ip = ip.To16()
	nibbles := make([]string, 0, 32)
	for i := len(ip) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", ip[i]&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", ip[i]>>4))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
}
