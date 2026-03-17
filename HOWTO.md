# Lookout - Installation & Usage Guide

This guide walks you through everything from installation to your first investigation. No deep technical knowledge required.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Getting Your API Keys](#3-getting-your-api-keys)
4. [Configuration](#4-configuration)
5. [Your First Investigation](#5-your-first-investigation)
6. [Understanding the Output](#6-understanding-the-output)
7. [All Commands](#7-all-commands)
8. [Saving Reports](#8-saving-reports)
9. [Cache Management](#9-cache-management)
10. [Troubleshooting](#10-troubleshooting)
11. [OPSEC & Privacy](#11-opsec--privacy)
12. [Proxy Setup Guide](#12-proxy-setup-guide)

---

## 1. Prerequisites

You need two things installed on your computer:

### Python (version 3.10 or newer)

Check if Python is installed by opening a terminal and running:

```bash
python --version
```

You should see something like `Python 3.12.4`. If not, download Python from [python.org/downloads](https://www.python.org/downloads/).

> **Windows users**: During installation, make sure to check the box **"Add Python to PATH"**.

### Git

Check if Git is installed:

```bash
git --version
```

If not, download Git from [git-scm.com](https://git-scm.com/downloads).

---

## 2. Installation

### Step 1: Download Lookout

Open a terminal (Command Prompt, PowerShell, or Terminal) and run:

```bash
git clone https://github.com/tools4eu/lookout.git
cd Lookout
```

### Step 2: (Recommended) Create a Virtual Environment

A virtual environment keeps Lookout's dependencies separate from your other Python projects.

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

When the virtual environment is active, you'll see `(.venv)` at the beginning of your terminal prompt.

### Step 3: Install Lookout

```bash
pip install -e .
```

This installs Lookout and all its dependencies. The `-e` flag means "editable" — if the tool is updated, your installation stays in sync.

### Step 4: Verify installation

```bash
lookout version
```

You should see: `OSINT Tool v0.1.0`

---

## 3. Getting Your API Keys

Lookout works best with API keys, but it can also run without them — it will simply use the free sources (RDAP, crt.sh, ThreatFox, URLhaus).

Here's how to get a (free) API key for each service:

### VirusTotal (strongly recommended)

1. Go to [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Go to your profile (click your avatar, top-right)
4. Click **API Key**
5. Copy the key

> Free tier: 4 lookups per minute, 500 per day. This is enough for normal use.

### AbuseIPDB (recommended for IP investigations)

1. Go to [abuseipdb.com](https://www.abuseipdb.com/register)
2. Create a free account
3. Go to **Account** > **API**
4. Copy the key

> Free tier: 1000 lookups per day.

### Shodan (recommended for IP investigations)

1. Go to [account.shodan.io](https://account.shodan.io/register)
2. Create a free account
3. Go to **Account** > **Overview**
4. Copy the API Key

> Free tier: limited to 1 request per second, basic host information.

### URLScan.io (recommended for domain/URL investigations)

1. Go to [urlscan.io](https://urlscan.io/user/signup)
2. Create a free account
3. Go to **Settings** > **API**
4. Create an API key

> Free tier: 100 scans per day.

### AlienVault OTX (optional)

1. Go to [otx.alienvault.com](https://otx.alienvault.com/api)
2. Create a free account
3. Go to **Settings**
4. Copy the OTX API Key

### Other services (optional, currently under development)

- **WhoisXML API**: [whoisxmlapi.com](https://whois.whoisxmlapi.com/signup) — enhanced WHOIS data
- **Hatching Triage**: [tria.ge](https://tria.ge/signup) — malware sandbox analysis

---

## 4. Configuration

### Step 1: Create your .env file

```bash
cp .env.example .env
```

### Step 2: Add your API keys

Open the `.env` file with any text editor (Notepad, VS Code, nano, etc.) and fill in your keys:

```
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
```

Replace `your_key_here` with the actual key. Leave a line empty if you don't have a key for that service — Lookout will skip that source automatically.

> **Important**: Never share your `.env` file or commit it to Git. It is excluded from the repository via `.gitignore`.

### Step 3: Verify your configuration

```bash
lookout config show
```

This shows which API keys are configured and which sources are enabled:

```
API Keys
API          Configured    Enabled
virustotal   Yes           Yes
urlscan      Yes           Yes
abuseipdb    Yes           Yes
shodan       Yes           Yes
alienvault   No            No
rdap (free)  N/A           Yes
crtsh (free) N/A           Yes
...
```

### Advanced: config.yaml

The file `config/config.yaml` lets you fine-tune:

- **Rate limits** per API (how fast Lookout queries each service)
- **Cache duration** (how long results are stored locally)
- **Risk scoring weights** (which source matters most)
- **Enabling/disabling** specific sources

In most cases, the defaults work fine. Only change this if you know what you're doing.

---

## 5. Your First Investigation

### Investigate a domain

```bash
lookout investigate example.com
```

### Investigate an IP address

```bash
lookout investigate 8.8.8.8
```

### Investigate a file hash

If you have a suspicious file and want to check its hash:

```bash
lookout investigate e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Investigate a URL

```bash
lookout investigate https://suspicious-site.com/login
```

### Just detect the indicator type

If you're not sure what type of indicator you have:

```bash
lookout detect 8.8.8.8
# Output: Detected: ipv4

lookout detect example.com
# Output: Detected: domain

lookout detect d41d8cd98f00b204e9800998ecf8427e
# Output: Detected: md5
```

---

## 6. Understanding the Output

Here's what a typical result looks like:

```
DOMAIN: suspicious-domain.com [MEDIUM (42)]

Source      Status      Risk            Details
virustotal  OK          medium (38)     8/93 malicious, 5 suspicious
urlscan     OK          clean (0)       IP: 203.0.113.50
rdap        OK          -               Registrar: Example Registrar Inc.
crtsh       OK          -               12 subdomains
threatfox   OK          clean (0)       -

Queried 5 sources in 2.34s (0 cached)
```

### Header line

- **DOMAIN**: The type of indicator (DOMAIN, IPV4, URL, SHA256, etc.)
- **suspicious-domain.com**: The value you investigated
- **[MEDIUM (42)]**: Overall risk level and score (0-100)

### Results table

| Column | Meaning |
|--------|---------|
| **Source** | Which service was queried |
| **Status** | `OK` = success, `OK [cached]` = from cache, `Error` = query failed |
| **Risk** | Risk level and score from this specific source |
| **Details** | Key findings from this source |

### Risk levels explained

| Level | What it means | What to do |
|-------|--------------|------------|
| **CLEAN** (0-9) | No threats found | Probably safe |
| **LOW** (10-29) | Minor flags | Review the details, usually not urgent |
| **MEDIUM** (30-59) | Suspicious | Investigate further, could be malicious |
| **HIGH** (60-84) | Multiple sources flag it | Likely malicious, take action |
| **CRITICAL** (85-100) | Strong consensus | Confirmed malicious, act immediately |

### Verbose mode

For more details, add `--verbose` or `-v`:

```bash
lookout investigate example.com --verbose
```

This shows all available fields from each source (registrar, ASN, nameservers, etc.).

---

## 7. All Commands

### Main commands

| Command | Description |
|---------|-------------|
| `lookout investigate <value>` | Investigate a domain, IP, hash, or URL |
| `lookout detect <value>` | Detect the indicator type without investigating |
| `lookout version` | Show version information |

### Investigation options

| Option | Short | Description |
|--------|-------|-------------|
| `--format json` | `-f json` | Output as JSON |
| `--format markdown` | `-f markdown` | Output as Markdown |
| `--output file.json` | `-o file.json` | Save output to a file |
| `--no-cache` | | Force fresh lookups (bypass cache) |
| `--verbose` | `-v` | Show detailed output |

### Cache management

| Command | Description |
|---------|-------------|
| `lookout cache stats` | Show cache statistics (entries, size) |
| `lookout cache clean` | Remove expired cache entries |
| `lookout cache clear --yes` | Delete all cached data |

### Configuration

| Command | Description |
|---------|-------------|
| `lookout config show` | Show current configuration and API key status |
| `lookout config reload` | Reload configuration from files |

---

## 8. Saving Reports

### Save as JSON (for further processing)

```bash
lookout investigate example.com --format json --output report.json
```

### Save as Markdown (for documentation)

```bash
lookout investigate example.com --format markdown --output report.md
```

### Multiple investigations

You can run multiple investigations one after another:

```bash
lookout investigate domain1.com --format json --output domain1.json
lookout investigate domain2.com --format json --output domain2.json
lookout investigate 1.2.3.4 --format json --output ip_report.json
```

---

## 9. Cache Management

Lookout caches results locally in a SQLite database (`data/cache.db`). This avoids hitting API rate limits when you investigate the same indicator multiple times.

### Default cache durations

| Source | Duration | Why |
|--------|----------|-----|
| VirusTotal | 24 hours | Detection data changes frequently |
| AbuseIPDB | 24 hours | New reports come in regularly |
| Shodan | 7 days | Infrastructure changes slowly |
| RDAP/WHOIS | 7 days | Registration data is stable |
| crt.sh | 7 days | Certificates don't change often |

### Force fresh results

If you want the latest data and skip the cache:

```bash
lookout investigate example.com --no-cache
```

### Clean up the cache

```bash
# Remove only expired entries
lookout cache clean

# Remove everything
lookout cache clear --yes
```

---

## 10. Troubleshooting

### "command not found: lookout"

The tool is not installed or not in your PATH.

- Make sure you ran `pip install -e .` in the Lookout directory
- If using a virtual environment, make sure it's activated (you see `(.venv)` in your prompt)
- Try running with `python -m osint` instead of `lookout`

### "Error: Could not detect indicator type"

Lookout doesn't recognize the input. Check that:

- Domains have a TLD: `example.com` (not just `example`)
- URLs start with `http://` or `https://`
- Hashes are complete (32, 40, or 64 hex characters)
- IP addresses are valid (no spaces, correct format)

### "API request failed: 401"

Your API key is missing or invalid for that service.

- Run `lookout config show` to check which keys are configured
- Double-check the key in your `.env` file (no extra spaces, correct key)

### "API request failed: 429"

You've hit the rate limit for a service.

- Wait a minute and try again
- VirusTotal free tier allows only 4 requests per minute
- Use `--no-cache` sparingly to avoid unnecessary API calls

### "Rate limit exceeded"

Same as above. Lookout has built-in rate limiting, but if you run many investigations quickly, you may still hit limits. Just wait and retry.

### Results show "[cached]"

This means the result was loaded from local cache instead of querying the API. This is normal behavior and saves API quota. Use `--no-cache` if you need fresh data.

### No results from a source

- The source may not support that indicator type (e.g., AbuseIPDB only works with IP addresses)
- The source may be disabled in `config/config.yaml`
- Run `lookout config show` to see which sources are active

### Python version errors

Make sure you have Python 3.10 or newer:

```bash
python --version
```

If you have an older version, download the latest from [python.org](https://www.python.org/downloads/).

---

## 11. OPSEC & Privacy

**This section is important. Read it before running any command against a live target.**

Lookout has different commands with different levels of visibility. Some commands are completely invisible to the target, others are not. Understanding the difference is critical.

### What "passive" means

A **passive** command only talks to third-party services (like VirusTotal or Shodan). It never sends any traffic to the target itself. The target has no way of knowing you looked them up.

An **active** command sends traffic **directly to the target**. Your IP address (or your proxy's IP) will appear in their logs.

### Command-by-command breakdown

#### `lookout investigate` — PASSIVE (safe)

```
You  --->  VirusTotal API  (your IP visible to VT, not to target)
You  --->  Shodan API      (your IP visible to Shodan, not to target)
You  --->  AbuseIPDB API   (your IP visible to AbuseIPDB, not to target)
You  --->  crt.sh          (public database, not the target)
...
Target sees: NOTHING
```

Your IP is only visible to the API providers (VirusTotal, Shodan, etc.), **never to the target**. This is safe to run against any indicator.

#### `lookout detect` — PASSIVE (safe)

Runs entirely locally. No network traffic at all.

#### `lookout enumerate` — SEMI-PASSIVE (low risk)

```
You  --->  Your DNS resolver (8.8.8.8, ISP, etc.)
                |
                v
           Target's authoritative nameserver
```

DNS queries go through your DNS resolver. The target's nameserver sees **your DNS resolver's IP** (e.g., Google's 8.8.8.8 or your ISP), **not your direct IP**.

**Risk**: If the target monitors DNS query logs (e.g., Cloudflare analytics), they may notice a burst of subdomain lookups. In practice, this is rarely monitored and your IP is hidden behind the resolver.

The crt.sh part of enumeration is fully passive (queries a public database).

Lookout will show a **yellow warning** and ask for confirmation before running.

#### `lookout dirscan` — ACTIVE (your IP is exposed!)

```
You  --->  Target webserver    <--- YOUR IP IS IN THEIR LOGS
```

This command makes **direct HTTP connections** to the target. Your IP address will be visible in:
- The target's web server access logs
- Their WAF (Web Application Firewall) alerts
- Anti-bot systems (Cloudflare, Akamai, etc.)
- Potentially: real-time alerts to the operator

Lookout will show a **red warning** and ask for explicit confirmation before running.

### How to protect yourself with dirscan

#### Option 1: Use a proxy

```bash
# SOCKS5 proxy (e.g., Tor running locally)
lookout dirscan target.com --proxy socks5://127.0.0.1:9050

# HTTP proxy
lookout dirscan target.com --proxy http://your-proxy:8080

# SOCKS5 with authentication
lookout dirscan target.com --proxy socks5://user:pass@proxy:1080
```

With a proxy, the target sees the **proxy's IP**, not yours.

#### Option 2: Use a VPN

If you're on a VPN, your VPN's IP will appear in logs instead of your real IP. This works automatically — no `--proxy` flag needed.

#### Option 3: Don't use dirscan

If you only need to know what's on a domain, `lookout investigate` and `lookout enumerate` often provide enough information without any active scanning. Use `dirscan` only when you specifically need to probe for exposed paths.

### Summary

| Command | Type | Target sees your IP? | Confirmation required? |
|---------|------|---------------------|----------------------|
| `investigate` | Passive | No | No |
| `detect` | Passive | No | No |
| `enumerate` | Semi-passive | DNS resolver IP only | Yes (yellow warning) |
| `dirscan` | **Active** | **YES** | Yes (red warning) |
| `dirscan --proxy` | Active (proxied) | Proxy IP only | Yes (yellow warning) |

---

## 12. Proxy Setup Guide

### Why use a proxy?

- `lookout dirscan` makes **direct HTTP connections** to the target — your IP address is visible in their logs
- A proxy hides your real IP behind the proxy's IP
- API commands (`investigate`, `detect`) do **NOT** need a proxy — they only talk to third-party APIs (VirusTotal, Shodan, etc.), never to the target

### Important: VPN vs Proxy — different tools for different commands

This is a critical distinction that many people get wrong:

- A **VPN** changes **all your traffic**, including API calls to VirusTotal, Shodan, AbuseIPDB, etc.
- Some threat intel APIs **block known VPN and Tor IP ranges** — they see VPN exit nodes as suspicious
- This means: a VPN can **break your `investigate` command** (API calls get rejected) while helping `dirscan`
- **Best practice**: use a **proxy** (not a VPN) for `dirscan`, and keep your normal internet connection for `investigate`
- The `--proxy` flag in Lookout **only affects `dirscan`**, not API calls — this is by design

In short:

| Approach | Effect on `investigate` | Effect on `dirscan` |
|----------|------------------------|---------------------|
| No VPN, no proxy | Works fine | Your IP is exposed |
| VPN on | May break (APIs block VPN IPs) | Your IP is hidden |
| `--proxy` flag | No effect (works fine) | Your IP is hidden |

The `--proxy` flag gives you the best of both worlds: hidden IP for scanning, normal IP for API lookups.

### Option 1: SSH SOCKS5 proxy (recommended)

If you have access to a Linux VM (e.g., Kali) or a VPS, you can create a SOCKS5 proxy through an SSH tunnel. This is the most reliable and flexible option.

**From a Linux/macOS terminal:**

```bash
# Open an SSH tunnel (runs in the background):
ssh -D 9050 -f -N user@your-proxy-server

# Then use it with lookout:
lookout dirscan target.com --proxy socks5://127.0.0.1:9050
```

**For PuTTY users (Windows):**

1. Open PuTTY
2. Go to **Connection > SSH > Tunnels**
3. Source port: `9050`
4. Select **Dynamic** and **Auto**
5. Click **Add** — you should see `D9050` in the list
6. Go back to **Session**, enter your server details, and connect
7. Keep the PuTTY window open while using the proxy

Then use it with Lookout:

```bash
lookout dirscan target.com --proxy socks5://127.0.0.1:9050
```

### Option 2: Tor

Tor provides anonymous routing through multiple relays. It's easy to set up but can be slower and some websites block Tor exit nodes.

```bash
# On Linux (Debian/Ubuntu):
sudo apt install tor && sudo systemctl start tor

# On macOS (with Homebrew):
brew install tor && tor

# On Windows: download Tor Browser from https://www.torproject.org
# Tor Browser includes a built-in SOCKS proxy on port 9150
```

Use with Lookout:

```bash
# Standalone Tor (Linux/macOS):
lookout dirscan target.com --proxy socks5://127.0.0.1:9050

# Tor Browser (Windows):
lookout dirscan target.com --proxy socks5://127.0.0.1:9150
```

> **Warning**: Tor exit nodes are often blocked by websites. You may get more 403/blocked responses compared to an SSH proxy or a clean VPS.

### Option 3: HTTP proxy

If you have access to an HTTP proxy server:

```bash
lookout dirscan target.com --proxy http://proxy-server:8080
```

### Supported proxy types

| Protocol | Format | Notes |
|----------|--------|-------|
| `socks4://` | `socks4://host:port` | Basic SOCKS, no authentication |
| `socks5://` | `socks5://host:port` | Recommended, supports authentication |
| `http://` | `http://host:port` | Standard HTTP proxy |
| `https://` | `https://host:port` | HTTP proxy over TLS |

All types support optional authentication: `protocol://user:pass@host:port`

### Quick reference

| Command | Needs proxy? | Why |
|---------|-------------|-----|
| `investigate` | No | Talks to APIs, not the target |
| `detect` | No | Runs locally, no network traffic |
| `enumerate` | No (low risk) | DNS queries go via your resolver |
| `dirscan` | **Recommended** | Direct HTTP connections to target |
| `dirscan --proxy` | Proxy used | Target sees the proxy IP, not yours |

---

## Need Help?

- Check the [README](README.md) for a quick overview
- Open an issue on [GitHub](https://github.com/tools4eu/lookout/issues)
