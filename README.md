# Lookout

> **Status: In Development / Testing Phase**
> This tool is actively being developed and is not yet considered stable.
> Features may change, break, or be incomplete. If you'd like to test it,
> feedback is very welcome — see [Contributing](#contributing) below.

**Automated OSINT & Threat Intelligence for domains, IPs, hashes, and URLs.**

Lookout is a command-line tool that lets you investigate suspicious indicators with a single command. It queries multiple threat intelligence sources in parallel and gives you a clear risk assessment — no need to manually check each service one by one.

Built for investigators and analysts who need fast, reliable results without deep technical expertise.

## What does it do?

You give Lookout a domain, IP address, file hash, or URL. Lookout automatically:

1. **Detects** what type of indicator it is
2. **Queries** up to 9 threat intelligence sources in parallel
3. **Scores** the risk based on weighted results from all sources
4. **Reports** the findings in a clear overview (table, JSON, or Markdown)

### Example

```
$ lookout investigate suspicious-domain.com

Detected type: domain

DOMAIN: suspicious-domain.com [MEDIUM (42)]

Source      Status      Risk            Details
virustotal  OK          medium (38)     8/93 malicious, 5 suspicious
urlscan     OK          clean (0)       IP: 203.0.113.50
rdap        OK          -               Registrar: Example Registrar Inc.
crtsh       OK          -               12 subdomains
threatfox   OK          clean (0)       -

Queried 5 sources in 2.34s (0 cached)
```

## Supported Threat Intelligence Sources

| Source | Type | What it checks | API key needed? |
|--------|------|----------------|-----------------|
| **VirusTotal** | Premium | Domains, IPs, URLs, file hashes (60+ antivirus engines) | Yes (free tier available) |
| **AbuseIPDB** | Premium | IP reputation and abuse reports | Yes (free tier available) |
| **Shodan** | Premium | Open ports, services, vulnerabilities on IPs | Yes (free tier available) |
| **URLScan.io** | Premium | Live website scanning, screenshots, technologies | Yes (free tier available) |
| **AlienVault OTX** | Premium | Community threat intelligence pulses | Yes (free) |
| **RDAP** | Free | WHOIS/domain registration data (registrar, dates, nameservers) | No |
| **crt.sh** | Free | Certificate Transparency logs (subdomains, certificates) | No |
| **ThreatFox** | Free | Known IOCs from abuse.ch (malware, C2 servers) | No |
| **URLhaus** | Free | Malicious URL database from abuse.ch | No |

## Supported Indicator Types

| Type | Example | Sources used |
|------|---------|-------------|
| Domain | `example.com` | VirusTotal, URLScan, RDAP, crt.sh, ThreatFox |
| IPv4 | `1.2.3.4` | VirusTotal, AbuseIPDB, Shodan, RDAP, ThreatFox |
| IPv6 | `2001:db8::1` | VirusTotal, AbuseIPDB, Shodan, RDAP, ThreatFox |
| URL | `https://evil.com/payload` | VirusTotal, URLScan, URLhaus, ThreatFox |
| MD5 hash | `d41d8cd98f00b204e9800998ecf8427e` | VirusTotal, ThreatFox |
| SHA1 hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | VirusTotal, ThreatFox |
| SHA256 hash | `e3b0c44298fc1c14...` | VirusTotal, ThreatFox |
| Email | `actor@evil.com` | VirusTotal |

## Risk Scoring

Lookout calculates a risk score from 0 to 100 based on weighted results:

| Score | Level | Meaning |
|-------|-------|---------|
| 0-9 | **CLEAN** | No threats detected |
| 10-29 | **LOW** | Minor flags, probably safe |
| 30-59 | **MEDIUM** | Suspicious activity detected |
| 60-84 | **HIGH** | Multiple sources flag this as malicious |
| 85-100 | **CRITICAL** | Strong consensus: this is malicious |

## Quick Start

See the [Installation & Usage Guide (HOWTO.md)](HOWTO.md) for detailed step-by-step instructions.

```bash
# 1. Clone the repository
git clone https://github.com/tools4eu/lookout.git
cd Lookout

# 2. Install
pip install -e .

# 3. Configure API keys
cp .env.example .env
# Edit .env with your API keys (see HOWTO.md for where to get them)

# 4. Run your first investigation
lookout investigate example.com
```

## Output Formats

```bash
# Table (default) - human-readable overview
lookout investigate example.com

# JSON - for further processing or scripting
lookout investigate example.com --format json

# Markdown - for reports and documentation
lookout investigate example.com --format markdown

# Save to file
lookout investigate example.com --format json --output report.json
```

## OPSEC — Know What Each Command Does

**Read this before using Lookout.** Not all commands are equally safe to run. Some are fully passive (invisible to the target), others are not.

### Passive commands (target CANNOT see you)

| Command | What happens | Your IP visible to target? |
|---------|-------------|---------------------------|
| `lookout investigate` | Queries third-party APIs (VirusTotal, Shodan, etc.) | **No** — traffic goes to API providers, never to the target |
| `lookout detect` | Local detection only, no network traffic | **No** |

### Semi-passive commands (low risk)

| Command | What happens | Your IP visible to target? |
|---------|-------------|---------------------------|
| `lookout enumerate` | Sends DNS queries via your DNS resolver | **Indirect** — the target's nameserver sees your DNS resolver's IP, not yours directly |

### Active commands (target CAN see you)

| Command | What happens | Your IP visible to target? |
|---------|-------------|---------------------------|
| `lookout dirscan` | Makes direct HTTP requests to the target | **YES** — your IP is in their server logs, WAF alerts, and anti-bot systems |

**To protect yourself when using `dirscan`:**
```bash
# Route through a SOCKS5 proxy (e.g. Tor)
lookout dirscan target.com --proxy socks5://127.0.0.1:9050

# Route through an HTTP proxy
lookout dirscan target.com --proxy http://your-proxy:8080
```

Both `enumerate` and `dirscan` will show an OPSEC warning and ask for confirmation before proceeding. Use `--yes` to skip the warning only if you understand the risks.

See the [HOWTO](HOWTO.md#11-opsec--privacy) for more details.

## Project Structure

```
Lookout/
├── .env.example              # API keys template (fill in your own)
├── config/
│   └── config.yaml           # Rate limits, caching, enabled sources
├── src/osint/
│   ├── cli/app.py            # Command-line interface
│   ├── clients/              # API clients (one per source)
│   ├── core/                 # Config, constants, exceptions
│   ├── detection/            # Auto-detection of indicator types
│   ├── models/               # Data models for results
│   ├── orchestration/        # Investigation orchestrator
│   ├── cache/                # SQLite caching layer
│   ├── reports/              # Report generation (Markdown/JSON)
│   └── utils/                # Rate limiter
├── tests/                    # Unit tests
└── data/                     # Runtime data (cache database)
```

## Contributing

Lookout is in active development. Feedback, bug reports, feature requests, and contributions are welcome.

**How to contribute:**

- **Bug reports & feature requests**: Open an [Issue](https://github.com/tools4eu/lookout/issues) on GitHub
- **Questions & ideas**: Use [GitHub Discussions](https://github.com/tools4eu/lookout/discussions) (if enabled) or open an Issue
- **Code contributions**: Fork the repo, make your changes, and submit a Pull Request
- **Wordlist contributions**: If you have subdomain or path patterns from your own investigations that you'd like to share, open a PR or Issue

When reporting bugs, please include:
- Your OS and Python version
- The command you ran
- The error message or unexpected behavior

## License

MIT
