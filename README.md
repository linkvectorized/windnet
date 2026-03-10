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

Network connection auditor. See every outbound TCP and UDP connection your machine makes — which organisation owns the IP, whether it's a tracker, telemetry beacon, or cloud service. No API keys, no cloud, no data leaves your machine beyond the enrichment lookups described below.

macOS supported. Linux coming soon.

---

## Quick start

```bash
# Install pre-built binary (no Go required)
curl -fsSL https://raw.githubusercontent.com/linkvectorized/windnet/master/install.sh | bash

# Run
windnet
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

| Category   | Colour | Icon | Description                                         |
|------------|--------|------|-----------------------------------------------------|
| SUSPICIOUS | Red    | ●    | No reverse DNS — unknown host, treat with suspicion |
| TRACKER    | Red    | ⚠    | Ad networks, analytics, fingerprinting              |
| TELEMETRY  | Yellow | ⚡   | OS and app phone-home / diagnostics                 |
| CLOUD      | Blue   | ☁    | Legitimate cloud/CDN infrastructure                 |
| NORMAL     | Green  | ✓    | Known, benign services                              |
| UNKNOWN    | Grey   | ?    | Has reverse DNS but company not in database         |

---

## How it works

1. Runs `lsof` concurrently for TCP (established) and UDP connections
2. Deduplicates by protocol + process + remote IP, counting connections per group
3. Performs reverse DNS lookup per unique IP (2s timeout, in-memory cache)
4. Classifies each resolved hostname against embedded tracker, telemetry, and company databases
5. IPs with no reverse DNS are marked **SUSPICIOUS**
6. For **UNKNOWN** and **SUSPICIOUS** connections, queries [Team Cymru's IP-to-ASN DNS service](https://team-cymru.com/community-services/ip-asn-mapping/) to resolve the owning organisation from BGP routing data — all lookups run concurrently
7. Renders a colour-coded table showing process, remote IP, company, category, protocol, and connection count

---

## Enrichment and network calls

windnet makes two categories of outbound DNS queries beyond normal resolution:

- **Reverse DNS** (`in-addr.arpa` / `ip6.arpa`) — standard PTR lookups per unique IP
- **ASN lookups** (Team Cymru) — two TXT queries per unrecognised IP: `<reversed-ip>.origin.asn.cymru.com` and `AS<num>.asn.cymru.com`

No data is sent to any HTTP endpoint. All lookups are standard DNS queries. Results are cached in-process for the lifetime of the scan.

---

## Flags

```
-version    Print version and exit
```

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
