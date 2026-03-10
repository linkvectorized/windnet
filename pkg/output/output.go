package output

import (
	"fmt"
	"os"
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
		return "🔴"
	case models.CategoryCloud:
		return "☁"
	case models.CategoryNormal:
		return "✓"
	default:
		return "?"
	}
}

func scoreColour(score int) string {
	switch {
	case score >= 80:
		return green
	case score >= 60:
		return yellow
	default:
		return red
	}
}

func scoreLabel(score int) string {
	switch {
	case score >= 90:
		return "EXCELLENT"
	case score >= 75:
		return "GOOD"
	case score >= 60:
		return "FAIR"
	case score >= 45:
		return "POOR"
	default:
		return "CRITICAL"
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

	// Privacy score: start 100, deduct for bad categories
	score := 100
	score -= r.Trackers * 8
	score -= r.Telemetry * 4
	score -= r.Suspicious * 15
	score -= r.Unknown * 2
	if score < 0 {
		score = 0
	}
	r.PrivacyScore = score
	return r
}

// PrintTable renders the full report to stdout
func PrintTable(conns []models.Connection, hostname, platform, version string) {
	r := buildReport(conns, hostname, platform)

	// Banner
	fmt.Fprintf(os.Stdout, "%s%s", cyan, bold)
	fmt.Println("  ╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("  ║           WINDNET v%s — Network Connection Audit        ║\n", padVersion(version))
	fmt.Println("  ╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("%s", reset)
	fmt.Fprintf(os.Stdout, "%s  Your machine talks to strangers. Now you can see who.%s\n\n", yellow, reset)

	// Meta line
	fmt.Fprintf(os.Stdout, "  %sHost:%s %-20s %sPlatform:%s %-10s",
		grey, reset, hostname,
		grey, reset, platform,
	)
	fmt.Println()

	// Privacy score bar
	bar := buildBar(r.PrivacyScore, 30)
	sc := scoreColour(r.PrivacyScore)
	fmt.Fprintf(os.Stdout, "\n  %s┌─ Privacy Score ──────────────────────────────────────────┐%s\n", grey, reset)
	fmt.Fprintf(os.Stdout, "  %s│%s %s%s%s [%d%%] %s%-9s%s                              %s│%s\n",
		grey, reset,
		sc, bar, reset,
		r.PrivacyScore,
		sc+bold, scoreLabel(r.PrivacyScore), reset,
		grey, reset,
	)
	fmt.Fprintf(os.Stdout, "  %s└──────────────────────────────────────────────────────────┘%s\n\n", grey, reset)

	// Summary counts
	fmt.Fprintf(os.Stdout, "  Connections: %s%d%s   ", white+bold, r.TotalConns, reset)
	fmt.Fprintf(os.Stdout, "%s⚠ Trackers: %d%s   ", red, r.Trackers, reset)
	fmt.Fprintf(os.Stdout, "%s⚡ Telemetry: %d%s   ", yellow, r.Telemetry, reset)
	fmt.Fprintf(os.Stdout, "%s🔴 Suspicious: %d%s   ", red+bold, r.Suspicious, reset)
	fmt.Fprintf(os.Stdout, "%s☁ Cloud: %d%s   ", blue, r.Cloud, reset)
	fmt.Fprintf(os.Stdout, "%s✓ Normal: %d%s\n\n", green, r.Normal, reset)

	if len(conns) == 0 {
		fmt.Fprintf(os.Stdout, "  %sNo active connections found.%s\n", grey, reset)
		return
	}

	// Sort: suspicious first, then trackers, then telemetry, then rest
	sorted := make([]models.Connection, len(conns))
	copy(sorted, conns)
	sort.Slice(sorted, func(i, j int) bool {
		return categoryOrder(sorted[i].Category) < categoryOrder(sorted[j].Category)
	})

	// Table header
	fmt.Fprintf(os.Stdout, "  %s%-3s %-18s %-18s %-22s %-12s %s%s\n",
		bold+white, "", "PROCESS", "REMOTE IP", "COMPANY", "CATEGORY", "CONNS", reset)
	fmt.Fprintf(os.Stdout, "  %s%s%s\n", grey, strings.Repeat("─", 92), reset)

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

		display := c.Hostname
		if display == "" {
			display = c.RemoteIP
		}
		if len(display) > 17 {
			display = display[:14] + "..."
		}

		process := c.Process
		if len(process) > 17 {
			process = process[:14] + "..."
		}

		ip := c.RemoteIP
		if len(ip) > 17 {
			ip = ip[:14] + "..."
		}

		if len(company) > 21 {
			company = company[:18] + "..."
		}

		catStr := string(c.Category)

		fmt.Fprintf(os.Stdout, "  %s%s%s %-18s %-18s %-22s %-12s %s%d%s\n",
			col, icon, reset,
			process,
			ip,
			company,
			catStr,
			col, c.Count, reset,
		)

		// Show hostname under the IP if it differs
		if c.Hostname != "" && c.Hostname != c.RemoteIP {
			truncHost := c.Hostname
			if len(truncHost) > 39 {
				truncHost = truncHost[:36] + "..."
			}
			fmt.Fprintf(os.Stdout, "  %s    %-18s %s%s\n", grey, "", truncHost, reset)
		}
	}

	fmt.Fprintf(os.Stdout, "  %s%s%s\n\n", grey, strings.Repeat("─", 92), reset)

	// Legend
	fmt.Fprintf(os.Stdout, "  %sLegend:%s  %s⚠ TRACKER%s  %s⚡ TELEMETRY%s  %s🔴 SUSPICIOUS — no reverse DNS, unknown host%s  %s☁ CLOUD%s  %s✓ NORMAL%s\n\n",
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

func buildBar(score, width int) string {
	filled := (score * width) / 100
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func padVersion(v string) string {
	// pad to 5 chars
	for len(v) < 5 {
		v += " "
	}
	return v
}
