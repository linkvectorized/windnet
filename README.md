# windnet

```
 ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ██╗███████╗████████╗
 ██║    ██║██║████╗  ██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
 ██║ █╗ ██║██║██╔██╗ ██║██║  ██║██╔██╗ ██║█████╗     ██║
 ██║███╗██║██║██║╚██╗██║██║  ██║██║╚██╗██║██╔══╝     ██║
 ╚███╔███╔╝██║██║ ╚████║██████╔╝██║ ╚████║███████╗   ██║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

> Your machine talks to strangers. Now you can see who.

Real-time network connection auditor. See every outbound TCP connection your machine makes — which company owns the IP, whether it's a tracker, telemetry beacon, or cloud service, and a live privacy score. No API keys, no cloud, no data leaves your machine.

macOS supported. Linux coming soon.

---

## Quick start

```bash
# Install pre-built binary (no Go required)
curl -fsSL https://raw.githubusercontent.com/linkvectorized/windnet/master/install.sh | bash

# One-shot scan
windnet

# Live mode — refreshes every 5 seconds
windnet -live

# Live mode — custom refresh rate
windnet -live -interval 10
```

Or build from source (requires Go 1.21+):

```bash
git clone https://github.com/linkvectorized/windnet
cd windnet
go build -o windnet ./cmd/windnet/
./windnet
```

---

## What it detects

| Category    | Colour  | Icon | Description                                         |
|-------------|---------|------|-----------------------------------------------------|
| SUSPICIOUS  | Red     | 🔴   | No reverse DNS — unknown host, treat with suspicion |
| TRACKER     | Red     | ⚠    | Ad networks, analytics, fingerprinting              |
| TELEMETRY   | Yellow  | ⚡   | OS and app phone-home / diagnostics                 |
| CLOUD       | Blue    | ☁    | Legitimate cloud/CDN infrastructure                 |
| NORMAL      | Green   | ✓    | Known, benign services                              |
| UNKNOWN     | Grey    | ?    | Has reverse DNS but company not in database         |

---

## Privacy Score

Starts at 100. Deductions per active connection:

- **Tracker**: −8
- **Telemetry**: −4
- **Suspicious** (no reverse DNS): −15
- **Unknown**: −2

Score labels: `EXCELLENT` (90+) · `GOOD` (75+) · `FAIR` (60+) · `POOR` (45+) · `CRITICAL` (<45)

---

## Flags

```
-live             Continuously refresh connections
-interval N       Refresh interval in seconds (default: 5, requires -live)
-version          Print version and exit
```

---

## How it works

1. Runs `lsof -iTCP -sTCP:ESTABLISHED` to snapshot all active TCP connections
2. Deduplicates by process + remote IP and counts connections per pair
3. Performs reverse DNS lookup per unique IP (2s timeout, in-memory cache)
4. Classifies each resolved hostname against embedded tracker, telemetry, and company databases
5. IPs with no reverse DNS are marked **SUSPICIOUS**
6. Renders a color-coded table with a privacy score

Everything is embedded — no external API calls, no network requests beyond what your machine was already making.

---

## Building from source

```bash
go build -o windnet ./cmd/windnet/
```

Cross-compile for Linux:

```bash
GOOS=linux GOARCH=amd64 go build -o windnet-linux-amd64 ./cmd/windnet/
GOOS=linux GOARCH=arm64 go build -o windnet-linux-arm64 ./cmd/windnet/
```

---

## License

MIT
