package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/linkvectorized/windnet/pkg/models"
)

// ANSI colours
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	red     = "\033[31m"
	yellow  = "\033[33m"
	green   = "\033[32m"
	cyan    = "\033[36m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	grey    = "\033[90m"
	white   = "\033[97m"
)

func categoryColour(cat models.Category) string {
	switch cat {
	case models.CategoryTracker:
		return red
	case models.CategoryTelemetry:
		return yellow
	case models.CategorySuspicious:
		return red + bold
	case models.CategoryCloud:
		return blue
	case models.CategoryNormal:
		return green
	default:
		return grey
	}
}

func categoryIcon(cat models.Category) string {
	switch cat {
	case models.CategoryTracker:
		return "⚠"
	case models.CategoryTelemetry:
		return "⚡"
	case models.CategorySuspicious:
		return "●"
	case models.CategoryCloud:
		return "☁"
	case models.CategoryNormal:
		return "✓"
	default:
		return "?"
	}
}

func buildReport(conns []models.Connection, hostname, platform string) *models.Report {
	r := &models.Report{
		Connections: conns,
		Hostname:    hostname,
		Platform:    platform,
		TotalConns:  len(conns),
	}
	for _, c := range conns {
		switch c.Category {
		case models.CategoryTracker:
			r.Trackers++
		case models.CategoryTelemetry:
			r.Telemetry++
		case models.CategorySuspicious:
			r.Suspicious++
		case models.CategoryCloud:
			r.Cloud++
		case models.CategoryNormal:
			r.Normal++
		default:
			r.Unknown++
		}
	}
	return r
}

// PrintTable renders the full report to w.
func PrintTable(w io.Writer, conns []models.Connection, hostname, platform, version string) {
	r := buildReport(conns, hostname, platform)

	// Banner
	fmt.Fprintf(w, "%s%s", cyan, bold)
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════════════════════╗")
	fmt.Fprintf(w, "  ║           WINDNET v%s — Network Connection Audit        ║\n", padVersion(version))
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════════════════════╝")
	fmt.Fprintf(w, "%s", reset)
	fmt.Fprintf(w, "%s  Your machine talks to strangers. Now you can see who.%s\n\n", yellow, reset)

	// Meta line
	fmt.Fprintf(w, "  %sHost:%s %-20s %sPlatform:%s %-10s\n",
		grey, reset, hostname,
		grey, reset, platform,
	)

	// Summary counts
	fmt.Fprintf(w, "  Connections: %s%d%s   ", white+bold, r.TotalConns, reset)
	fmt.Fprintf(w, "%s⚠ Trackers: %d%s   ", red, r.Trackers, reset)
	fmt.Fprintf(w, "%s⚡ Telemetry: %d%s   ", yellow, r.Telemetry, reset)
	fmt.Fprintf(w, "%s● Suspicious: %d%s   ", red+bold, r.Suspicious, reset)
	fmt.Fprintf(w, "%s☁ Cloud: %d%s   ", blue, r.Cloud, reset)
	fmt.Fprintf(w, "%s✓ Normal: %d%s\n\n", green, r.Normal, reset)

	if len(conns) == 0 {
		fmt.Fprintf(w, "  %sNo active connections found.%s\n", grey, reset)
		return
	}

	// Sort: suspicious first, then trackers, then telemetry, then rest
	sorted := make([]models.Connection, len(conns))
	copy(sorted, conns)
	sort.Slice(sorted, func(i, j int) bool {
		return categoryOrder(sorted[i].Category) < categoryOrder(sorted[j].Category)
	})

	// Table header
	fmt.Fprintf(w, "  %s%-3s   %-20s   %-20s   %-24s   %-12s   %-6s   %-5s%s\n",
		bold+white, "", "PROCESS", "REMOTE IP", "COMPANY", "CATEGORY", "PROTO", "CONNS", reset)
	fmt.Fprintf(w, "  %s%s%s\n", grey, strings.Repeat("─", 108), reset)

	// Rows
	for _, c := range sorted {

		col := categoryColour(c.Category)
		icon := categoryIcon(c.Category)

		company := c.Company
		if company == "" {
			company = c.RootDomain
		}
		if company == "" {
			company = "Unknown"
		}

		process := c.Process
		if len(process) > 19 {
			process = process[:16] + "..."
		}

		ip := c.RemoteIP
		if len(ip) > 19 {
			ip = ip[:16] + "..."
		}

		if len(company) > 23 {
			company = company[:20] + "..."
		}

		catStr := string(c.Category)

		fmt.Fprintf(w, "  %s%s%s   %-20s   %-20s   %-24s   %-12s   %-6s   %s%-5d%s\n",
			col, icon, reset,
			process,
			ip,
			company,
			catStr,
			c.Protocol,
			col, c.Count, reset,
		)

		if c.Hostname != "" && c.Hostname != c.RemoteIP {
			truncHost := c.Hostname
			if len(truncHost) > 39 {
				truncHost = truncHost[:36] + "..."
			}
			fmt.Fprintf(w, "  %s    %-18s %s%s\n", grey, "", truncHost, reset)
		}

	}

	fmt.Fprintf(w, "  %s%s%s\n\n", grey, strings.Repeat("─", 108), reset)

	// Legend
	fmt.Fprintf(w, "  %sLegend:%s  %s⚠ TRACKER%s  %s⚡ TELEMETRY%s  %s● SUSPICIOUS — no reverse DNS, unknown host%s  %s☁ CLOUD%s  %s✓ NORMAL%s\n\n",
		grey, reset,
		red, reset,
		yellow, reset,
		red+bold, reset,
		blue, reset,
		green, reset,
	)
}

func categoryOrder(c models.Category) int {
	switch c {
	case models.CategorySuspicious:
		return 0
	case models.CategoryTracker:
		return 1
	case models.CategoryTelemetry:
		return 2
	case models.CategoryUnknown:
		return 3
	case models.CategoryCloud:
		return 4
	default:
		return 5
	}
}

func padVersion(v string) string {
	// pad to 5 chars
	for len(v) < 5 {
		v += " "
	}
	return v
}
