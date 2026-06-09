# Phishing Detection System

A lightweight command-line tool that analyses URLs for common phishing indicators and outputs a colour-coded risk verdict.

---

## Features

| Check | What it looks for |
|---|---|
| IP-based URL | Raw IPv4/IPv6 address used instead of a domain name |
| HTTPS check | Whether the URL uses HTTP instead of HTTPS |
| URL length | URLs longer than 75 characters |
| URL shortener | Known shortening services (bit.ly, tinyurl, etc.) |
| Blacklist | Domain present in the local `data/blacklist.txt` |
| Suspicious domain | Homoglyphs, brand keywords in subdomains, excessive hyphens |

---

## Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

---

## Installation

```bash
# 1. Clone / download the project
cd phishing-detection-system

# 2. (Optional) create a virtual environment
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

```bash
python main.py --url <URL>
```

### Examples

```
$ python main.py --url http://192.168.1.1/login

Analysing: http://192.168.1.1/login
------------------------------------------------------------
  [!] IP-based URL detected (192.168.1.1)              → SUSPICIOUS
  [!] No HTTPS detected (scheme: 'http')               → SUSPICIOUS
  [✓] URL length is normal (26 characters)             → OK
  [✓] No URL shortener detected                        → OK
  [✓] Domain not found in blacklist                    → OK
  [✓] No suspicious domain patterns detected           → OK
------------------------------------------------------------

  Total risk score : 4
  Final Verdict    : SUSPICIOUS
```

```
$ python main.py --url https://known-phishing-site.com/login

  Total risk score : 6
  Final Verdict    : DANGEROUS
```

```
$ python main.py --url not_a_url

  [ERROR] 'not_a_url' is not a valid URL. Please include the scheme (http:// or https://).
```

---

## Scoring

| Score | Verdict |
|---|---|
| 0 – 1 | ✅ SAFE |
| 2 – 4 | ⚠️ SUSPICIOUS |
| 5 + | 🚨 DANGEROUS |

Individual check scores:

| Check | Score |
|---|---|
| IP-based URL | +3 |
| No HTTPS | +1 |
| Long URL | +1 |
| URL shortener | +2 |
| Blacklisted domain | +5 |
| Suspicious domain | +1 or +2 |

---

## Updating the Blacklist

Add one domain per line to `data/blacklist.txt`. Lines starting with `#` are treated as comments.

```
# My custom entries
malicious-domain.com
another-phishing-site.net
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# or with unittest
python -m unittest discover tests/
```

---

## Project Structure

```
phishing-detection-system/
├── main.py                  # CLI entry point
├── requirements.txt
├── README.md
├── checks/
│   ├── __init__.py
│   ├── ip_check.py
│   ├── length_check.py
│   ├── https_check.py
│   ├── shortener_check.py
│   ├── blacklist_check.py
│   └── domain_check.py
├── data/
│   └── blacklist.txt
└── tests/
    ├── test_ip_check.py
    ├── test_length_check.py
    └── test_blacklist_check.py
```

---

## Future Enhancements

- Machine learning model trained on phishing URL datasets
- Browser extension wrapper
- Integration with Google Safe Browsing / VirusTotal APIs
- REST API endpoint
- Whitelist support
- Scan history logging
