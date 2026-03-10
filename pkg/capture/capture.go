package capture

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
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

	// Resolve with 2s timeout
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

// Scan captures established TCP and active UDP connections and enriches them.
func Scan(ctx context.Context) ([]models.Connection, error) {
	type result struct {
		out  []byte
		proto string
	}

	ch := make(chan result, 2)

	go func() {
		out, _ := exec.CommandContext(ctx,
			"lsof", "-iTCP", "-sTCP:ESTABLISHED", "-n", "-P", "+c", "0",
		).Output()
		ch <- result{out, "TCP"}
	}()

	go func() {
		out, _ := exec.CommandContext(ctx,
			"lsof", "-iUDP", "-n", "-P", "+c", "0",
		).Output()
		ch <- result{out, "UDP"}
	}()

	var raw []rawConn
	for i := 0; i < 2; i++ {
		r := <-ch
		raw = append(raw, parseConnections(string(r.out), r.proto)...)
	}

	return enrich(raw), nil
}

type rawConn struct {
	process    string
	pid        int
	protocol   string
	remoteIP   string
	remotePort int
}

func parseConnections(output, proto string) []rawConn {
	var conns []rawConn
	seen := map[string]bool{}

	for _, line := range strings.Split(output, "\n") {
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		// Find the -> arrow which marks a connection
		arrowIdx := strings.Index(line, "->")
		if arrowIdx == -1 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		process := fields[0]
		pid, _ := strconv.Atoi(fields[1])

		// Extract remote address from NAME field (last field or second to last before state)
		nameField := fields[len(fields)-1]
		if strings.HasPrefix(nameField, "(") {
			if len(fields) < 2 {
				continue
			}
			nameField = fields[len(fields)-2]
		}

		arrow := strings.Index(nameField, "->")
		if arrow == -1 {
			continue
		}
		remote := nameField[arrow+2:]

		// Parse IP:port — handle IPv6 [::1]:port
		remoteIP, remotePort := splitHostPort(remote)
		if remoteIP == "" {
			continue
		}

		// Skip loopback
		if strings.HasPrefix(remoteIP, "127.") || remoteIP == "::1" || strings.HasPrefix(remoteIP, "fe80") {
			continue
		}

		key := fmt.Sprintf("%s:%d:%s:%d", process, pid, remoteIP, remotePort)
		if seen[key] {
			continue
		}
		seen[key] = true

		conns = append(conns, rawConn{
			process:    process,
			pid:        pid,
			protocol:   proto,
			remoteIP:   remoteIP,
			remotePort: remotePort,
		})
	}
	return conns
}

// splitHostPort handles both IPv4 (1.2.3.4:80) and IPv6 ([::1]:80)
func splitHostPort(addr string) (string, int) {
	if strings.HasPrefix(addr, "[") {
		// IPv6
		end := strings.LastIndex(addr, "]")
		if end == -1 {
			return "", 0
		}
		ip := addr[1:end]
		portStr := ""
		if end+2 < len(addr) {
			portStr = addr[end+2:]
		}
		port, _ := strconv.Atoi(portStr)
		return ip, port
	}
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, 0
	}
	port, _ := strconv.Atoi(addr[lastColon+1:])
	return addr[:lastColon], port
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

	// Concurrently enrich unknown/suspicious connections via RDAP
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
