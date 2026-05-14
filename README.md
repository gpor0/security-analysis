# portscan.py

A TCP port scanner for authorized security assessments. Single-file Python, no external dependencies, scans hostnames or IPs across configurable port profiles and produces structured text or JSON reports with banner-grabbing, TLS posture analysis, and HTTP fingerprinting on open ports.

> **Authorization is mandatory.** Only scan systems you own or have explicit written permission to test. The script refuses to run without the `--confirm` flag as a deliberate guardrail. Even on systems you own, coordinate with whoever runs the network — port scans trigger IDS/WAF rules and can get your source IP auto-blocked.

---

## Quick start

```bash
# Single host, common services
python portscan.py -t example.com --confirm

# Multiple hosts, Kubernetes ports, JSON output
python portscan.py -t 10.0.0.5 cluster-node-1 -p k8s --json scan.json --confirm

# Targets from file, everything we know about, save both formats
python portscan.py -f targets.txt -p common+k8s+monitoring \
  --text report.txt --json report.json --confirm
```

---

## Requirements

- Python 3.10 or newer (uses `ssl.TLSVersion`, `dict | None` type hints, `match` syntax).
- Standard library only — no `pip install` step.
- Outbound TCP allowed to your target ports.
- `openssl` binary is **not** required at runtime (only by the test fixtures); the script uses Python's `ssl` module.

Tested on Linux and macOS. Should work on Windows but Windows defenders may interfere with rapid connect attempts; lower `--workers` if scans are unreliable.

---

## What it does, in order

For each target, for each port:

1. **DNS resolution** — A-record lookup (skipped for literal IPs) plus reverse-DNS for context. Failed resolution is surfaced and the host is skipped.
2. **TCP connect** — `connect_ex()` against the port. Result classified as `open` (handshake completed), `closed` (RST received), `filtered` (timeout, usually firewall), or `error` (other OS-level failure).
3. **TLS handshake** — for ports in the TLS list (443, 6443, 8443, 10250, 2379, etc.), wrap the socket with the `ssl` module. Two-stage probe: secure handshake first, falling back to a deliberately permissive handshake if the secure one fails. Captures protocol version, cipher, certificate subject/issuer/validity/SANs.
4. **TLS classification** — flags deprecated protocol versions (anything below TLS 1.2, per RFC 8996) and weak ciphers (RC4, DES, 3DES, NULL, EXPORT, anonymous DH, MD5).
5. **Protocol-specific banner grab** — for ports with known text protocols (SSH, FTP, SMTP, MySQL, Redis, etc.), reads the server's initial response. Some ports get a probe payload first (HTTP HEAD, Redis PING).
6. **HTTP GET probe** — for non-TLS ports not in the skip list, opens a fresh connection and sends `GET /`. For TLS ports, runs the GET over the already-wrapped TLS socket if the handshake was modern. Parses status line, key fingerprinting headers, HTML title, and body preview.
7. **Result aggregation** — all of the above is stored in a `PortResult` dataclass and rendered into text and/or JSON.

Concurrency: one `ThreadPoolExecutor` per host, with `--workers` threads (default 100) scanning ports in parallel. Hosts are scanned sequentially.

---

## Flags reference

### Target specification

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `-t` / `--targets` | one or more hostnames or IPs | none | Targets passed directly on the command line. Mix of DNS names and IPs is fine. |
| `-f` / `--file` | path to text file | none | One target per line. Blank lines and lines starting with `#` are ignored. Can be combined with `-t`; targets are deduplicated. |

At least one of `-t` or `-f` must be supplied.

### Port selection

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `-p` / `--ports` | profile name, numeric spec, or combination | `common` | Defines which ports to scan. See "Port profiles" below for the full list of accepted forms. |

### Scan tuning

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `--timeout` | seconds (float) | `1.5` | Per-connection timeout. Lower values speed up scans but increase false-negative rate (filtered ports look closed). Raise to `3.0`+ on slow or high-latency targets. |
| `--workers` | integer | `100` | Concurrent connections per host. The OS file-descriptor limit is the real ceiling — bump `ulimit -n` if you go above 500. Cloud-hosted targets may rate-limit at this layer; 50–100 is a safe middle ground for external scans. |

### Probe control

| Flag | Default | Purpose |
|------|---------|---------|
| `--no-banner` | off | Disables banner grabbing, TLS info, and HTTP probing entirely. Reduces scan to pure connect-only (`open`/`closed`/`filtered`). Fastest mode; use when you only need an inventory of reachable ports. |
| `--no-http` | off | Disables only the HTTP GET probe; banner grabs and TLS info still run. Use when you want service inventory and TLS posture but don't want HTTP requests in target access logs. |
| `--user-agent STRING` | distinctive auto-generated tag | Sets the `User-Agent` header on all HTTP probes. Default value is `PortScan-PenTest/1.0 (authorized-assessment; src=<your-hostname>)` so you can grep your own probes out of target access logs. Override per engagement (see "User-Agent" below). |

### Output control

| Flag | Argument | Default | Purpose |
|------|----------|---------|---------|
| `--show-closed` | (off) | open only | Include closed and filtered ports in the text report. By default the report only shows open ports to keep output skimmable; turn this on if you need to confirm a port is firewalled rather than just absent. |
| `--text` | path | none | Write the text report to this file in addition to printing it to stdout. |
| `--json` | path | none | Write the full structured JSON report to this file. JSON includes every field — closed ports, raw banner bytes, TLS cert details, HTTP headers — regardless of `--show-closed`. |
| `--html` | path | none | Write a self-contained HTML report. Embedded CSS and JS, no external dependencies — safe to email or upload as a single file. Includes summary stat cards, a top-of-report TLS findings callout, expand/collapse-all controls, and a "show only hosts with findings" filter. Supports both light and dark OS themes via `prefers-color-scheme`. |

### Safety

| Flag | Default | Purpose |
|------|---------|---------|
| `--confirm` | off | Required to actually run a scan. Without it, the script prints the planned target list and exits with code 1. This is a deliberate friction point — make sure you have authorization before adding it. |

---

## Port profiles

The `-p` argument accepts a flexible spec composed of profile names and numeric port references, joined with `,` or `+`. Profiles are case-insensitive.

### Named profiles

| Profile | Aliases | Port count | Purpose |
|---------|---------|------------|---------|
| `common` | `top`, `top100` | 119 | General-purpose top ports across operating systems, network infrastructure, and the most widely-deployed services. Reasonable default for unknown targets. |
| `kubernetes` | `k8s` | 106 | Control plane (etcd, kube-apiserver, scheduler, controller-manager), worker components (kubelet, kube-proxy), container runtimes (Docker daemon), CNI plugins (Calico, Cilium, Flannel), service mesh (Istio/Envoy, Linkerd), ingress controllers, in-cluster registries, observability defaults, message brokers, databases run as StatefulSets, and CI/CD running in clusters. |
| `observability` | `monitoring`, `obs` | 108 | Prometheus ecosystem (server + ~25 standard exporters in the 9100–9913 range), time-series DBs (Graphite, InfluxDB, VictoriaMetrics, OpenTSDB, statsd), logging stacks (ELK/OpenSearch, Loki+Tempo, Splunk, Graylog, Fluentd, Vector), tracing (Jaeger, Zipkin, OpenTelemetry OTLP), APM agents (Datadog, Elastic APM), classic monitoring (Zabbix, Puppet, SaltStack, JMX), and the dashboard/UI ports for all of these (Grafana, Kibana, Netdata, Sentry). Also includes the often-leaked Go pprof endpoint on 6060. |
| `all` | — | 65535 | Every TCP port. Slow and noisy — expect 5–15 minutes per host even at 200 workers. Most useful when you suspect services on non-standard ports. |

### Numeric forms

| Form | Example | Notes |
|------|---------|-------|
| Single port | `22` | One port. |
| Comma list | `22,80,443` | Discrete ports. Whitespace ignored. |
| Range | `1-1024` | Inclusive on both ends. Both bounds must be in 1–65535. |
| Mixed | `22,80-90,443,8000-8100` | Any combination. |

### Combining profiles and numerics

Use `,` or `+` (they're interchangeable) to combine:

```bash
# k8s + observability stacks together
-p k8s+monitoring

# common + your custom application ports
-p common,7777,9876,11434

# everything we know about, plus a specific range
-p common+k8s+obs,30000-32767

# Just the kubernetes profile plus the default ingress NodePort range
-p kubernetes,30000-32767
```

Duplicates across profiles and numeric specs are automatically deduplicated.

---

## Output formats

### Text report (stdout, `--text`)

Structured around three nested sections.

**Header block** — generation timestamp and host count.

**TLS findings summary** — appears immediately after the header if any deprecated-TLS or weak-cipher findings were detected. Format: `host:port → finding`. This is intentionally placed up top because in scans of 50+ hosts the per-host detail is too long to skim for security issues.

**Per-host blocks** — one per target, with:
- Resolved IP, reverse DNS, scan start/end timestamps.
- Open-port count.
- Port table with columns: `PORT`, `STATE`, `SERVICE` (from `/etc/services`), `DETAIL`.

The `DETAIL` column's content depends on what was discovered:
- For protocols with a clear banner: the raw banner text (truncated to 80 chars).
- For TLS ports: protocol version + certificate subject. Prefixed with `[!!]` if the port is on deprecated TLS, `[!]` if the cipher is weak.
- For ports with errors: the error message.

**Continuation lines** (indented under each port row) appear when there's structured information that doesn't fit on the main row:
- `>>> TLS FINDING:` lines explain deprecated-TLS or weak-cipher findings in plain English, with the cipher in use.
- `HTTP:` lines show the parsed HTTP response — status line, `Server`, `X-Powered-By`, `Location`, `WWW-Authenticate`, `Content-Type`, page title, and a body preview.

### JSON report (`--json`)

The JSON output mirrors the dataclass structure exactly. Top-level is an array of host objects. Each host has:

```json
{
  "target": "example.com",
  "resolved_ip": "93.184.216.34",
  "reverse_dns": "example.com",
  "resolution_error": "",
  "scan_started": "2026-05-12T10:00:00+00:00",
  "scan_finished": "2026-05-12T10:00:14+00:00",
  "ports": [
    {
      "port": 443,
      "state": "open",
      "service": "https",
      "banner": "",
      "tls_info": {
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "subject": "CN=example.com",
        "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1 ...",
        "not_before": "Jan  1 00:00:00 2026 GMT",
        "not_after": "Feb  1 23:59:59 2027 GMT",
        "san": ["DNS:example.com", "DNS:www.example.com"],
        "severity_tags": ["TLS_1_3"]
      },
      "http_info": {
        "status_line": "HTTP/1.1 200 OK",
        "headers": {
          "server": "nginx/1.24.0",
          "content-type": "text/html; charset=utf-8"
        },
        "title": "Example Domain",
        "body_preview": "<!doctype html><html>..."
      },
      "error": ""
    }
  ]
}
```

Notable fields:
- `state` ∈ `{"open", "closed", "filtered", "error"}`.
- `tls_info.severity_tags` ∈ subsets of `{"DEPRECATED_TLS", "WEAK_CIPHER", "TLS_1_2", "TLS_1_3"}`.
- `tls_info.findings` is a list of human-readable strings, only present when issues are detected.
- `tls_info.modern_handshake_error` is present only when the secure handshake failed and a fallback succeeded — indicates the server requires deprecated TLS.
- `http_info.non_http_response` appears when a port accepts the GET but replies with something that isn't HTTP (e.g. a Redis error). The first 120 bytes are captured.
- All ports — including closed and filtered — are present in the JSON regardless of `--show-closed`. That flag only affects the text report.

JSON is suitable for:
- Diffing between scan runs to detect drift (`diff <(jq -S . old.json) <(jq -S . new.json)`).
- Ingestion into ELK, Splunk, or a custom database.
- Triggering automation (e.g. "fail CI if any host has a port outside an allowlist").

### HTML report (`--html`)

A single self-contained file with embedded CSS and JS — no external resources, safe to email or attach to a ticket. Designed for handing to stakeholders who need to skim findings without running `jq` queries.

Top of the report:
- Title bar with generation timestamp, port profile used, and the User-Agent the scan ran with.
- Four stat cards: total hosts, total open ports, deprecated-TLS finding count (red if non-zero), weak-cipher count (orange if non-zero).
- TLS findings callout block — only rendered if findings exist; lists every `host:port → finding` in a prominent red-bordered box.

Per-host sections:
- Each host is a collapsible `<details>` block. Hosts with findings are auto-expanded; clean hosts are collapsed by default if the report has more than 5 hosts.
- Summary line shows host, IP, reverse DNS, an "open" badge with port count, and a "Findings" badge in red if any TLS issues were detected.
- Inside each host is a sortable port table with columns Port / State / Service / Details. Rows are color-coded: red background for deprecated-TLS rows, orange for weak-cipher rows, plain for everything else.
- The Details column embeds banner output, TLS info (with severity-tag pills like `[DEPRECATED TLS]`), certificate fields, and parsed HTTP response fields (status line, server header, title, body preview).

Interactive controls in the toolbar:
- **Expand all** / **Collapse all** buttons for jumping through large reports.
- **Show only hosts with findings** checkbox that filters the host list to just the problematic ones.

The report respects `prefers-color-scheme: dark`, so analysts on dark-mode systems get a properly themed report automatically.

**Security note**: all values from scanned targets (banners, certificate subjects, HTTP titles, server headers) are HTML-escaped before being written to the report. A malicious or misconfigured target cannot inject script into your report by setting a hostile `Server` header or certificate CN.

Use cases:
- Sharing findings with developers or management who don't want to read JSON.
- Attaching as evidence to a pentest report or audit ticket.
- Quick visual review of large scans where the text report would be too dense to skim.

---

## User-Agent

The HTTP probe sets a `User-Agent` header so you can attribute your own traffic in target logs and subtract it from "real" traffic during a review.

**Default value** is built at runtime:

```
PortScan-PenTest/1.0 (authorized-assessment; src=<your-hostname>)
```

The `src=<hostname>` token comes from `socket.gethostname()` so scans from different boxes are distinguishable.

**Override** with `--user-agent` for engagement-specific tags:

```bash
python portscan.py -t target.example.com -p common \
  --user-agent "PenTest-acme-2026Q2-jira-12345 contact=alice@security.example.com" \
  --confirm
```

Useful patterns:

- Include the engagement identifier (client + quarter, or a ticket number).
- Include a contact handle so a blue-team analyst who notices the scan has someone to call.
- Avoid spaces in the leading token if you want it to grep cleanly: `PenTest-acme-2026Q2_alice/contact-info`.

**Filtering your probes from logs:**

```bash
# Exclude probes from real-traffic analysis
grep -v "PenTest-acme-2026Q2" /var/log/nginx/access.log

# Confirm coverage — show only what your scan hit
grep "PenTest-acme-2026Q2" /var/log/nginx/access.log

# Splunk/ELK
NOT user_agent="PenTest-acme-2026Q2*"
```

**Caveat for external targets behind WAFs:** Cloudflare, AWS WAF, and Akamai maintain reputation lists of scanner-like UAs and may rate-limit or block. For internal testing, the obvious default is fine. For external assets, either coordinate an allowlist for your UA with the WAF team beforehand, or use a less obvious tag (`InternalAudit-2026Q2` still works while being less likely to trip reputation rules).

---

## TLS posture analysis

The scanner does a two-stage TLS probe to detect deprecated protocol versions.

**Stage 1**: handshake with `ssl.create_default_context()` — secure defaults, minimum TLS 1.2. If this succeeds, the negotiated version is recorded as-is.

**Stage 2** (only if stage 1 failed): handshake with `minimum_version = SSLv3` and `set_ciphers("ALL:@SECLEVEL=0")`. If this succeeds, the server **only** speaks deprecated TLS — recorded with `severity_tags: ["DEPRECATED_TLS"]` and the stage-1 error preserved as `modern_handshake_error` for diagnosis.

### Classification

| Tag | Triggers when... |
|-----|------------------|
| `DEPRECATED_TLS` | Negotiated protocol is SSLv2, SSLv3, TLSv1.0, or TLSv1.1 (RFC 8996). |
| `WEAK_CIPHER` | Cipher name contains any of: `NULL`, `EXPORT`, `RC4`, `RC2`, `DES-CBC`, `3DES`, `MD5`, `ANON`, `ADH`, `AECDH`, `IDEA`, `SEED`. |
| `TLS_1_2` | Negotiated TLS 1.2. Not a finding; informational tag for filtering. |
| `TLS_1_3` | Negotiated TLS 1.3. Informational. |

### Limitations

The cipher-classification is a substring match — it catches well-known weak primitives but won't flag every subtlety a dedicated TLS auditor would (CRIME, BREACH, LUCKY13, Sweet32, certificate transparency, OCSP stapling, key sizes below 2048-bit RSA, etc.). For deep TLS posture review, run `testssl.sh` or `sslyze` against any port this scanner flags. Treat the scanner's findings as a *trigger* for deeper investigation, not the final word.

If both handshake stages fail with errors, that's surfaced as `error` + `legacy_error` in `tls_info`. This usually means the local OpenSSL build has stripped support for the protocol entirely (most modern distros refuse SSLv3 and below at compile time). Verify with `openssl s_client -ssl3 -connect host:port` from a more permissive environment.

---

## HTTP probing

After a port is confirmed open, the scanner sends `GET / HTTP/1.1` and parses the response.

### Which ports are probed

Probed: any open port that isn't on the protocol-specific skip list. The skip list contains ~30 ports where the protocol is known not to be HTTP (SSH 22, SMTP 25, DNS 53, POP3/IMAP 110/143, LDAP 389, SMB 445, MySQL 3306, RDP 3389, Postgres 5432, VNC 5900, Redis 6379, MongoDB 27017, etc.) plus a few cluster-data-plane ports (BGP 179, VXLAN 4789/8472). Probing these would either fail outright or risk confusing the protocol state machine.

### What's parsed

Captured into `http_info`:

- `status_line` — the first response line, e.g. `HTTP/1.1 200 OK`.
- `headers` — a subset of fingerprinting-relevant headers (`server`, `x-powered-by`, `location`, `www-authenticate`, `content-type`, `x-jenkins`, `x-prometheus-api-version`, `x-kubernetes-pf-flowschema-uid`, plus a few others).
- `title` — extracted from `<title>` if the response is HTML.
- `body_preview` — first 200 bytes of body content with whitespace collapsed. Useful for JSON APIs (k8s apiserver returns a `Status` object explaining why your request was refused; Prometheus's root path returns a redirect snippet).
- `non_http_response` — first 120 bytes if the port accepted the GET but the response doesn't start with `HTTP/`.
- `error` — connection or parse failure message.

### TLS-port behavior

For TLS ports, the HTTPS GET runs over the wrapped TLS socket immediately after the handshake. It's **only** attempted if the modern handshake succeeded; on deprecated-TLS servers, the GET is skipped with a note in `http_info.error` ("HTTPS probe skipped — server uses deprecated TLS"), because the weakness is already captured in `tls_info` and re-establishing the legacy handshake to fetch HTTP would add complexity without new information.

### Common findings in real-world output

| Service | Tell-tale signature |
|---------|---------------------|
| Grafana | `Server: Grafana` + `302 Found` + `Location: /login` |
| Prometheus | `302 Found` + `Location: /graph` (no Server header) |
| Kibana | HTML title `Kibana` |
| Jenkins | `WWW-Authenticate: Basic realm="Jenkins"` + `X-Jenkins: <version>` |
| Kubernetes apiserver | JSON body containing `"kind":"Status"` + `forbidden:` message |
| Go pprof | `200 OK` + body containing `/debug/pprof/` links |
| Exposed Docker daemon (2375) | Skipped from HTTP probe; banner-grab catches it |
| nginx default | `Server: nginx/<version>` + HTML title `Welcome to nginx!` |
| Apache default | `Server: Apache/<version>` + content-type `text/html` |

---

## Common workflows

### Inventory of open ports across a host range

```bash
# Fast connect-scan, no banners
echo "10.0.0.{1..254}" | xargs -n1 > targets.txt
python portscan.py -f targets.txt -p common --no-banner --workers 200 --confirm
```

### Kubernetes cluster posture review

```bash
# All cluster nodes, full k8s + observability profile, JSON for archival
python portscan.py -f cluster-nodes.txt -p k8s+monitoring \
  --user-agent "k8s-audit-2026Q2" \
  --json cluster-scan-$(date +%F).json \
  --text cluster-scan-$(date +%F).txt \
  --confirm
```

### Report for stakeholders (HTML)

```bash
# Scan, produce a shareable HTML report with summary stats and findings callouts
python portscan.py -f targets.txt -p common+k8s+monitoring \
  --html audit-2026Q2.html --confirm

# Open in browser to review, or email/attach to a ticket
```

### Drift detection between scans

```bash
# Run weekly, diff against last week
python portscan.py -f targets.txt -p common+k8s --json this-week.json --confirm
jq -S 'sort_by(.target) | map({target, ports: .ports | map(select(.state == "open")) | map({port, service})})' \
  this-week.json > this-week-summary.json
diff last-week-summary.json this-week-summary.json
```

### External-facing TLS audit

```bash
# Just the TLS posture, no HTTP noise in target logs
python portscan.py -f external-hosts.txt -p 443,8443,6443,8883,993,995,465 \
  --no-http --confirm
```

### Triaging a finding from a CI scanner

```bash
# Single host, single port, maximum detail in JSON
python portscan.py -t suspect.internal.example.com -p 6443 \
  --timeout 5.0 --json triage.json --confirm
jq '.[0].ports[0]' triage.json
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully. |
| `1` | `--confirm` was not supplied; the script printed planned targets and exited. |
| `2` | Argument validation failed (no targets, invalid port spec, missing file). Error message on stderr. |

Note: a non-zero exit does **not** indicate that open ports were found. Use `jq` on the JSON output to script alerts on findings:

```bash
python portscan.py -f targets.txt -p common --json scan.json --confirm
# Fail if any deprecated-TLS finding
jq -e '[.[] | .ports[] | .tls_info // empty | .severity_tags // [] | contains(["DEPRECATED_TLS"])] | any' \
  scan.json && echo "TLS findings detected!" && exit 1
```

---

## Performance and tuning

Rough timing per host on a fast network:

| Profile | Open ports | `--workers 100` | `--workers 200` |
|---------|------------|------------------|------------------|
| `common` (119 ports) | most closed | ~5 s | ~3 s |
| `k8s+monitoring` (~210 ports) | mostly closed | ~8 s | ~5 s |
| `1-1024` | typical server | ~12 s | ~7 s |
| `all` (65535) | typical server | ~6 min | ~3.5 min |

Bottlenecks in practice:

- **Filtered ports drive scan time** because each one waits for the full `--timeout`. On a host with most ports closed (RST response), scans finish near-instantly. On a host where most ports are filtered, scans take `(port_count / workers) * timeout` seconds at minimum.
- **TLS handshakes on open ports** add ~100–500 ms each depending on round-trip time. The two-stage probe doubles this on deprecated-TLS servers.
- **HTTP GETs** add another ~50–200 ms per open port. Use `--no-http` if scan speed matters more than fingerprinting.

To tune:

- Lower `--timeout` (e.g. `0.5`) on local-network targets where RTT is < 5 ms. Increases false-negatives on heavily-loaded targets.
- Raise `--workers` to 300+ — but make sure `ulimit -n` is at least `workers * 2`. On macOS the default limit is 256; on most Linux distros it's 1024.
- Use `--no-banner` for pure connect-scan when you only need a port inventory.

---

## Operational caveats

**Logs.** Every probe is a real TCP connection. Banner grabs send protocol-specific payloads. HTTP probes send actual GET requests that hit application code. All of this will appear in target access logs, IDS/IPS dashboards, and SIEM event streams. Coordinate with the blue team before scanning anything that's monitored.

**Rate limiting and WAFs.** Production targets often have per-source-IP rate limits. A 200-worker scan from a single source IP looks indistinguishable from an attack. If you're scanning external assets, either run from an allowlisted source or stagger scans with shell loops + `sleep`.

**Stealth.** This scanner is the opposite of stealthy. Full TCP handshakes on every probe, protocol-specific banners, identifiable User-Agent. That's the right trade-off for authorized testing where attribution and reproducibility matter. For stealth scans (SYN, FIN, idle), use `nmap` with appropriate privileges — Python's standard library can't do half-open scans without raw sockets and root.

**False classification on filtered ports.** A `closed` result means the kernel got an RST packet; `filtered` means the connect timed out. Stateful firewalls usually generate `filtered` for blocked ports, but some return RSTs that look like `closed`. Don't over-interpret the difference without correlating with the firewall config.

**TLS probes are not exhaustive.** This script flags deprecated protocol versions and substring-matched weak ciphers. It does **not** test for individual cipher suite acceptance, certificate chain validity, OCSP stapling, HSTS headers, key sizes, or known attacks like Heartbleed/CRIME/BREACH/POODLE. For thorough TLS review, run `testssl.sh` or `sslyze` against flagged ports.

**The script is not stealthy and not pretending to be.** Use only with authorization.

---

## License and intended use

This tool is intended for authorized security assessments — your own infrastructure, or third-party systems with documented written permission. Unauthorized port scanning may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), Article 615ter of the Italian Penal Code, §202c StGB (Germany), the Cybersecurity Law of the PRC, and equivalent statutes in most other jurisdictions. The `--confirm` flag is a deliberate reminder of this requirement.
