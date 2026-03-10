package capture

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/linkvectorized/windnet/pkg/asn"
	"github.com/linkvectorized/windnet/pkg/classify"
	"github.com/linkvectorized/windnet/pkg/models"
)

// dnsCache avoids hammering DNS for the same IP repeatedly
type dnsCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

var cache = &dnsCache{cache: make(map[string]string)}

func (c *dnsCache) lookup(ip string) string {
	c.mu.RLock()
	if h, ok := c.cache[ip]; ok {
		c.mu.RUnlock()
		return h
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var r net.Resolver
	addrs, err := r.LookupAddr(ctx, ip)
	hostname := ""
	if err == nil && len(addrs) > 0 {
		hostname = strings.TrimSuffix(addrs[0], ".")
	}

	c.mu.Lock()
	c.cache[ip] = hostname
	c.mu.Unlock()
	return hostname
}

type rawConn struct {
	process    string
	pid        int
	protocol   string
	remoteIP   string
	remotePort int
}

// enrich resolves hostnames, classifies, and deduplicates by protocol+process+IP
func enrich(raw []rawConn) []models.Connection {
	type key struct{ proto, process, ip string }
	grouped := map[key]*models.Connection{}
	order := []key{}

	for _, r := range raw {
		k := key{r.protocol, r.process, r.remoteIP}
		if c, ok := grouped[k]; ok {
			c.Count++
			continue
		}

		hostname := cache.lookup(r.remoteIP)
		company, category := classify.Classify(hostname)

		root := ""
		if hostname != "" {
			parts := strings.Split(strings.TrimSuffix(hostname, "."), ".")
			if len(parts) >= 2 {
				root = parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
		}

		c := &models.Connection{
			Process:    r.process,
			PID:        r.pid,
			Protocol:   r.protocol,
			RemoteIP:   r.remoteIP,
			RemotePort: r.remotePort,
			Hostname:   hostname,
			RootDomain: root,
			Company:    company,
			Category:   category,
			Count:      1,
		}
		grouped[k] = c
		order = append(order, k)
	}

	// Concurrently enrich unknown/suspicious connections via ASN lookup
	var wg sync.WaitGroup
	for _, k := range order {
		c := grouped[k]
		if c.Category == models.CategoryUnknown || c.Category == models.CategorySuspicious {
			wg.Add(1)
			go func(conn *models.Connection) {
				defer wg.Done()
				if org := asn.LookupOrg(conn.RemoteIP); org != "" {
					conn.Company = org
				}
			}(c)
		}
	}
	wg.Wait()

	result := make([]models.Connection, 0, len(order))
	for _, k := range order {
		result = append(result, *grouped[k])
	}
	return result
}
