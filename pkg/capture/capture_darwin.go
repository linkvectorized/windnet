//go:build darwin

package capture

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/linkvectorized/windnet/pkg/models"
)

// Scan captures established TCP and active UDP connections via lsof.
func Scan(ctx context.Context) ([]models.Connection, error) {
	type result struct {
		out   []byte
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

func parseConnections(output, proto string) []rawConn {
	var conns []rawConn
	seen := map[string]bool{}

	for _, line := range strings.Split(output, "\n") {
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

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

		remoteIP, remotePort := splitHostPort(remote)
		if remoteIP == "" {
			continue
		}

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
