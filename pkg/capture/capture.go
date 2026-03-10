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

// Scan captures all established TCP connections and enriches them.
func Scan(ctx context.Context) ([]models.Connection, error) {
	out, err := exec.CommandContext(ctx,
		"lsof", "-iTCP", "-sTCP:ESTABLISHED", "-n", "-P", "+c", "0",
	).Output()
	if err != nil {
		// lsof exits non-zero if it finds nothing — that's fine
		if len(out) == 0 {
			return nil, nil
		}
	}

	raw := parseConnections(string(out))
	return enrich(raw), nil
}

type rawConn struct {
	process    string
	pid        int
	remoteIP   string
	remotePort int
}

func parseConnections(output string) []rawConn {
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

// enrich resolves hostnames, classifies, and deduplicates by process+IP
func enrich(raw []rawConn) []models.Connection {
	// Group by process+remoteIP
	type key struct{ process, ip string }
	grouped := map[key]*models.Connection{}
	order := []key{}

	for _, r := range raw {
		k := key{r.process, r.remoteIP}
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

	result := make([]models.Connection, 0, len(order))
	for _, k := range order {
		result = append(result, *grouped[k])
	}
	return result
}
