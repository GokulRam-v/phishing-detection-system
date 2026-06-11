# Phishing Detection System

A command-line URL scanner and browser-based threat analysis UI that checks URLs against **11 independent detection modules** and produces a colour-coded risk verdict.

---

## Features

### Static / Heuristic Checks *(no network required)*

| Module | File | What it detects | Max score |
|---|---|---|---|
| IP-Based URL | `ip_check.py` | Raw IPv4 / IPv6 address used as host instead of a domain | +3 |
| HTTPS Verify | `https_check.py` | Insecure scheme (`http`), unencrypted (`ftp`), or dangerous (`javascript:`, `data:`) | +1 – +4 |
| URL Length | `length_check.py` | URLs > 100 chars (suspicious) or > 150 chars (high risk) | +1 – +2 |
| Shortener DB | `shortener_check.py` | 40+ known URL-shortening services that hide the real destination | +2 |
| Blacklist Lookup | `blacklist_check.py` | Domain or any parent domain present in `data/blacklist.txt` | +5 |
| Domain Pattern | `domain_check.py` | Homoglyphs (`paypa1.com`), brand-in-subdomain (`paypal.evil.com`), punycode/IDN, excessive hyphens, deeply nested subdomains | +1 – +3 |
| Suspicious TLD | `tld_check.py` | High-abuse TLDs (`.tk`, `.ml`, `.xyz`, `.ru`, etc.) | +1 – +2 |
| Path / Query | `path_check.py` | Phishing keywords in the URL path (`login`, `verify`, `password`, etc.), excessive URL encoding, double slashes | +1 – +2 |
| URL Manipulation | `special_chars_check.py` | `@`-sign misdirection, embedded credentials, null-byte injection, double encoding, consecutive dots | +2 – +4 |

### Live Network Checks *(require internet access)*

| Module | File | What it detects | Max score |
|---|---|---|---|
| Live Reachability | `reachability_check.py` | Site offline, redirect to different domain, SSL errors, HTTP 4xx/5xx responses | +1 – +3 |
| Source Code Analysis | `source_analysis_check.py` | Forms posting to external domains, password fields, meta-refresh redirects, obfuscated JS, iframes, device permission APIs, hidden input harvesting, brand impersonation in title/favicon | +1 – +10 |

---

## Scoring Thresholds

| Score | Verdict |
|---|---|
| 0 – 2 | ✅ **SAFE** |
| 3 – 6 | ⚠️ **SUSPICIOUS** |
| 7 + | 🚨 **DANGEROUS** |

> Thresholds are tuned to avoid false positives on legitimate sites (e.g. `https://about.google/` scores 0).

---

## Requirements

- Python **3.10** or higher
- pip packages listed in `requirements.txt`

---

## Installation

```bash
# 1. Clone / download the project
cd phishing-detection-system

# 2. (Recommended) create a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Mode 1 — API server only (launch the browser UI)

```bash
python main.py
```

Then open `UI/UGI.html` in any browser. The top bar shows **API: ONLINE** when the server is ready.

### Mode 2 — CLI scan + API server

```bash
python main.py --url https://example.com
```

Runs all 11 checks in the terminal **and** keeps the API server running so the UI stays available.

### Mode 3 — CLI scan only (no server)

```bash
python main.py --no-server --url https://example.com
```

### Custom port

```bash
python main.py --port 8080
```

> If using a custom port, update the `API` constant at the top of `UI/UGI.html` to match.

### CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--url URL` | *(none)* | URL to analyse. If omitted, runs in server-only mode. |
| `--no-server` | off | Skip starting the Flask API server. |
| `--port PORT` | `5000` | Port for the API server. |

---

## CLI Output Example

```
  ╔══════════════════════════════════════╗
  ║   PHISH-HUNT  Threat Analysis v3.0  ║
  ╚══════════════════════════════════════╝

  [SERVER] API running at http://localhost:5000
  [SERVER] Open UI/UGI.html in your browser to use the interface.

  Analysing: http://192.168.1.1/login/verify?account=update
  ──────────────────────────────────────────────────────────────────────
  [!] IP-based URL detected (192.168.1.1)                        +3  SUSPICIOUS
  [!] No HTTPS — connection is not encrypted (http)              +1  SUSPICIOUS
  [✓] URL length is normal (44 characters)                       +0  OK
  [✓] No URL shortener detected                                  +0  OK
  [✓] Domain not found in blacklist                              +0  OK
  [✓] No suspicious domain patterns detected                     +0  OK
  [✓] TLD looks normal                                           +0  OK
  [!] Suspicious path/query: multiple phishing keywords          +2  SUSPICIOUS
  [✓] No URL manipulation tricks detected                        +0  OK
  ──────────────────────────────────────────────────────────────────────

  ── Live Reachability ──────────────────────────────────────────────
  [ONLINE]  Site is reachable (HTTP 200)

  ── Source Code Analysis ───────────────────────────────────────────
  Page title  : Login - Secure Account
  Page purpose: credential harvesting / fake login page
  [!] Password input field(s) detected (1 found)
  [!] Form submits data to external domain: evil-collector.com

  ──────────────────────────────────────────────────────────────────────

  Total risk score : 9
  Final Verdict    : 🚨  DANGEROUS
```

---

## Browser UI

The hacker-themed single-page app (`UI/UGI.html`) requires the Flask API to be running.

- **Page 1** — animated terminal-style input with Matrix rain background
- Scanning overlay — shows live progress through each check module
- **Page 2** — full results with verdict banner, animated risk score bar, individual check cards, and a dedicated **Source Code Analysis** panel showing:
  - Page title and HTTP status
  - Inferred page purpose / behaviour
  - Per-finding severity (`[!!]` critical / `[!]` suspicious / `[i]` info)
  - Browser permission APIs detected (camera, microphone, geolocation, clipboard)

---

## Project Structure

```
phishing-detection-system/
├── main.py                        # Unified CLI entry point + embedded Flask API server
├── server.py                      # Standalone Flask API (alternative to main.py)
├── requirements.txt
├── README.md
│
├── checks/
│   ├── __init__.py
│   ├── ip_check.py                # Raw IP address detection
│   ├── https_check.py             # Scheme safety (https / http / ftp / javascript:)
│   ├── length_check.py            # URL length thresholds
│   ├── shortener_check.py         # Known URL shortener database (40+ services)
│   ├── blacklist_check.py         # Local domain blacklist with subdomain matching
│   ├── domain_check.py            # Homoglyphs, brand-in-subdomain, punycode, IDN
│   ├── tld_check.py               # High-abuse TLD detection
│   ├── path_check.py              # Phishing keywords in URL path/query
│   ├── special_chars_check.py     # @-sign, null-byte, double-encoding tricks
│   ├── reachability_check.py      # Live HTTP check + redirect chain analysis
│   └── source_analysis_check.py  # HTML/JS source code deep inspection
│
├── data/
│   └── blacklist.txt              # One domain per line; # = comment
│
├── UI/
│   └── UGI.html                   # Self-contained browser UI (HTML + CSS + JS)
│
└── tests/
    ├── __init__.py
    ├── test_blacklist_check.py
    ├── test_ip_check.py
    └── test_length_check.py
```

---

## Updating the Blacklist

Add one domain per line to `data/blacklist.txt`. Lines starting with `#` are comments. Subdomain matching is automatic — adding `evil.com` will also flag `login.evil.com`.

```
# Custom threat entries
malicious-domain.com
phishing-bank-login.net
fake-paypal-secure.org
```

---

## Running Tests

```bash
# pytest
python -m pytest tests/ -v

# or unittest
python -m unittest discover tests/
```

---

## API Reference

The Flask server exposes two endpoints:

### `GET /api/health`
Returns `{"status": "ok"}` when the server is running.

### `POST /api/scan`
**Request body:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "score": 0,
  "verdict": "SAFE",
  "checks": [
    {
      "key": "ip",
      "label": "IP-Based URL",
      "triggered": false,
      "detail": "No IP-based URL detected",
      "score": 0
    },
    {
      "key": "source",
      "label": "Source Code Analysis",
      "triggered": false,
      "detail": "Page source appears clean",
      "score": 0,
      "findings": [],
      "permissions": [],
      "page_purpose": "general informational page",
      "page_title": "Example Domain",
      "status_code": 200,
      "reachable": true
    }
  ]
}
```

---

## False-Positive Handling

The scoring system is calibrated to avoid false positives on legitimate sites:

- Brand-owned TLDs (`.google`, `.apple`, `.microsoft`) are excluded from domain spoofing checks
- Scripts from 30+ trusted CDNs (`googleapis.com`, `gstatic.com`, `cloudflare.com`, etc.) are ignored in source analysis
- JavaScript obfuscation requires **3+ distinct patterns** before triggering
- Hidden input fields require **6+** before flagging (CSRF tokens are common on legitimate sites)
- DANGEROUS threshold is **7+** points, giving legitimate sites with minor signals room to stay SAFE
