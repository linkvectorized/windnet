package models

import "time"

type Category string

const (
	CategoryTracker    Category = "TRACKER"
	CategoryTelemetry  Category = "TELEMETRY"
	CategoryCloud      Category = "CLOUD"
	CategoryNormal     Category = "NORMAL"
	CategorySuspicious Category = "SUSPICIOUS"
	CategoryUnknown    Category = "UNKNOWN"
)

type Connection struct {
	Process    string
	PID        int
	Protocol   string   // "TCP" or "UDP"
	RemoteIP   string
	RemotePort int
	Hostname   string   // reverse DNS result
	RootDomain string   // e.g. "google.com" from "lb.google.com"
	Company    string   // e.g. "Google LLC"
	Category   Category
	Count      int // number of connections to this IP from this process
}

type Report struct {
	Connections  []Connection
	ScanTime     time.Time
	Hostname     string
	Platform     string
	TotalConns   int
	Trackers     int
	Telemetry    int
	Suspicious   int
	Cloud        int
	Normal       int
	Unknown int
}
