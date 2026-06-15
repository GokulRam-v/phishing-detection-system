# PRD – Phishing Detection System

## 1. Project Overview

The Phishing Detection System is a command-line interface (CLI) tool built in Python. It accepts a URL as input and analyzes it for common phishing indicators such as suspicious domains, IP-based URLs, URL length, redirects, and blacklist matches. The tool outputs a risk assessment indicating whether the URL is likely legitimate or a phishing attempt.

---

## 2. Problem Statement

Phishing attacks are one of the most common cybersecurity threats, tricking users into visiting fake websites that steal personal credentials and sensitive data. Most users cannot visually identify a phishing URL. There is a need for a simple, fast, and accessible tool that can automatically analyze URLs and flag potentially dangerous ones before users visit them.

---

## 3. Objectives

- Detect phishing URLs using rule-based analysis.
- Provide a clear, easy-to-understand risk verdict for each URL.
- Be lightweight, fast, and usable without any graphical interface.
- Serve as a foundation for more advanced ML-based detection in the future.

---

## 4. Features

| Feature | Description |
|---|---|
| URL Input | Accept a URL via command-line argument |
| Suspicious Domain Detection | Flag misspelled or lookalike domains (e.g., paypa1.com) |
| IP-Based URL Detection | Flag URLs that use raw IP addresses instead of domain names |
| URL Length Check | Flag abnormally long URLs (typically > 75 characters) |
| Redirect Detection | Detect excessive redirects in the URL path |
| URL Shortener Detection | Identify known URL shortening services (bit.ly, tinyurl, etc.) |
| Blacklist Check | Check the URL against a local list of known phishing domains |
| Risk Score Output | Display a final verdict: Safe, Suspicious, or Dangerous |

---

## 5. User Flow

1. User opens the terminal.
2. User runs: `python main.py --url <URL>`
3. The tool parses and analyzes the URL.
4. Each check is run and a score is calculated.
5. The tool prints each check result and a final verdict.

Example:
```
$ python main.py --url http://192.168.1.1/login

[!] IP-based URL detected         → SUSPICIOUS
[!] No HTTPS detected             → SUSPICIOUS
[✓] URL length is normal          → OK
[✓] No URL shortener detected     → OK
[!] Domain found in blacklist     → DANGEROUS

Final Verdict: DANGEROUS
```

---

## 6. Functional Requirements

- FR1: The system must accept a URL as a CLI argument.
- FR2: The system must validate whether the input is a properly formatted URL.
- FR3: The system must check if the URL uses an IP address instead of a domain name.
- FR4: The system must check if the URL length exceeds 75 characters.
- FR5: The system must detect the presence of URL shortening services.
- FR6: The system must compare the domain against a local blacklist file.
- FR7: The system must check for HTTPS vs HTTP usage.
- FR8: The system must output a final verdict: Safe, Suspicious, or Dangerous.
- FR9: The system must handle invalid or unreachable URLs gracefully with error messages.

---

## 7. Non-Functional Requirements

- NFR1: The tool must return results within 3 seconds for most URLs.
- NFR2: The tool must run on Python 3.8 or above.
- NFR3: The codebase must be modular — each detection check in its own function/module.
- NFR4: The tool must work offline (blacklist stored locally).
- NFR5: Output must be readable and color-coded in the terminal (using colorama).

---

## 8. Technical Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| CLI Parsing | argparse |
| URL Parsing | urllib.parse |
| HTTP Requests | requests |
| Terminal Colors | colorama |
| Blacklist Storage | Local .txt or .json file |
| Testing | unittest or pytest |

---

## 9. Folder Structure

```
phishing-detection-system/
│
├── main.py                  # Entry point – CLI interface
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation
├── PRD.md                   # This document
│
├── checks/
│   ├── __init__.py
│   ├── ip_check.py          # Detects IP-based URLs
│   ├── length_check.py      # Checks URL length
│   ├── https_check.py       # Checks for HTTP vs HTTPS
│   ├── shortener_check.py   # Detects URL shorteners
│   ├── blacklist_check.py   # Checks against local blacklist
│   └── domain_check.py      # Detects suspicious/lookalike domains
│
├── data/
│   └── blacklist.txt        # List of known phishing domains
│
└── tests/
    ├── test_ip_check.py
    ├── test_length_check.py
    └── test_blacklist_check.py
```

---

## 10. Testing Requirements

| Test Case | Input | Expected Output |
|---|---|---|
| Legitimate URL | https://google.com | Safe |
| IP-based URL | http://192.168.1.1/login | Dangerous |
| Fake domain | https://paypa1-login.com | Suspicious/Dangerous |
| URL shortener | https://bit.ly/xyz123 | Suspicious |
| Very long URL | https://example.com/a*100 chars | Suspicious |
| Invalid URL | not_a_url | Error: Invalid URL |
| HTTP only | http://example.com | Suspicious |
| Blacklisted domain | https://known-phishing-site.com | Dangerous |

---

## 11. Future Enhancements

- **Machine Learning Integration** – Train a model on phishing URL datasets for higher accuracy.
- **Browser Extension** – Wrap the tool as a Chrome/Firefox extension.
- **Real-Time Threat Intelligence** – Connect to APIs like Google Safe Browsing or VirusTotal.
- **API Support** – Expose the detection logic as a REST API endpoint.
- **Whitelist Support** – Allow users to add trusted domains.
- **Logging** – Save scan history to a local log file.

---

## 12. Deliverables

- [ ] PRD.md
- [ ] Source Code (main.py + checks/)
- [ ] Test Cases (tests/)
- [ ] requirements.txt
- [ ] README.md
- [ ] GitHub Repository
- [ ] Working CLI Application
