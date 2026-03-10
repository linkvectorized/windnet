//go:build linux

package capture

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/linkvectorized/windnet/pkg/models"
)

// Scan captures established TCP and active UDP connections via /proc/net.
func Scan(_ context.Context) ([]models.Connection, error) {
	inodeMap := map[string]rawConn{}

	for _, t := range []struct {
		path  string
		proto string
		tcp   bool
	}{
		{"/proc/net/tcp", "TCP", true},
		{"/proc/net/tcp6", "TCP", true},
		{"/proc/net/udp", "UDP", false},
		{"/proc/net/udp6", "UDP", false},
	} {
		entries, err := readProcNet(t.path, t.proto, t.tcp)
		if err != nil {
			continue
		}
		for inode, r := range entries {
			inodeMap[inode] = r
		}
	}

	if len(inodeMap) == 0 {
		return nil, nil
	}

	// Walk /proc/<pid>/fd to map socket inodes → process names
	var raw []rawConn
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fdPath := range fds {
		link, err := os.Readlink(fdPath)
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := link[8 : len(link)-1]
		r, ok := inodeMap[inode]
		if !ok {
			continue
		}

		// /proc/<pid>/fd/<n> — extract pid
		parts := strings.Split(fdPath, "/")
		if len(parts) < 4 {
			continue
		}
		pid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}

		r.pid = pid
		r.process = strings.TrimSpace(string(commBytes))
		raw = append(raw, r)

		delete(inodeMap, inode)
	}

	return enrich(raw), nil
}

// readProcNet parses a /proc/net/{tcp,tcp6,udp,udp6} file.
// Returns a map of inode → rawConn (without pid/process — filled later).
func readProcNet(path, proto string, tcpOnly bool) (map[string]rawConn, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := map[string]rawConn{}
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 10 {
			continue
		}

		// Field 3: connection state. TCP ESTABLISHED = "01".
		if tcpOnly && fields[3] != "01" {
			continue
		}

		remAddr := fields[2]
		// UDP: skip sockets with no remote (00000000:0000)
		if !tcpOnly {
			colonIdx := strings.Index(remAddr, ":")
			if colonIdx == -1 {
				continue
			}
			if remAddr[colonIdx+1:] == "0000" {
				continue
			}
		}

		remIP, remPort, err := parseHexAddr(remAddr)
		if err != nil {
			continue
		}

		if strings.HasPrefix(remIP, "127.") || remIP == "::1" || strings.HasPrefix(remIP, "fe80") {
			continue
		}

		inode := fields[9]
		entries[inode] = rawConn{
			protocol:   proto,
			remoteIP:   remIP,
			remotePort: remPort,
		}
	}
	return entries, nil
}

// parseHexAddr decodes a /proc/net address like "0101007F:0050" (IPv4)
// or a 32-char hex string (IPv6) into a dotted IP string and port number.
func parseHexAddr(hexAddr string) (string, int, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", hexAddr)
	}

	port64, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}

	switch len(b) {
	case 4:
		// IPv4 — stored little-endian
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return ip.String(), int(port64), nil
	case 16:
		// IPv6 — four 4-byte groups, each little-endian
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		return net.IP(b).String(), int(port64), nil
	default:
		return "", 0, fmt.Errorf("unexpected addr length %d", len(b))
	}
}
