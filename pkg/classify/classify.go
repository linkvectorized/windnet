package classify

import (
	"strings"

	"github.com/linkvectorized/windnet/pkg/models"
)

// Classify determines the company and category for a resolved hostname.
// hostname should be the full reverse-DNS result (e.g. "lb-192-168.google.com").
// If hostname is empty the IP had no reverse DNS — mark SUSPICIOUS.
func Classify(hostname string) (company string, category models.Category) {
	if hostname == "" {
		return "Unknown", models.CategorySuspicious
	}

	root := rootDomain(hostname)

	// Check tracker list first (most important to flag)
	if trackerDomains[root] || trackerDomains[hostname] {
		company = companyFor(root)
		if company == "" {
			company = root
		}
		return company, models.CategoryTracker
	}

	// Check telemetry
	if telemetryDomains[hostname] || telemetryDomains[root] {
		company = companyFor(root)
		if company == "" {
			company = root
		}
		return company, models.CategoryTelemetry
	}

	// Look up company
	company = companyFor(root)

	// Check cloud providers
	if cloudProviders[root] {
		if company == "" {
			company = root
		}
		return company, models.CategoryCloud
	}

	if company != "" {
		return company, models.CategoryNormal
	}

	// Has a hostname but no known company
	return root, models.CategoryUnknown
}

// rootDomain extracts the registrable domain from a hostname.
// "lb-192.prod.google.com" → "google.com"
func rootDomain(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".")
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// companyFor returns the company name for a root domain.
func companyFor(root string) string {
	if c, ok := domainCompany[root]; ok {
		return c
	}
	return ""
}
