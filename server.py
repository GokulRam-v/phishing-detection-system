"""
server.py – Lightweight Flask API for the Phishing Detection UI.

Endpoints:
  POST /api/scan        → run all checks + source analysis, return JSON
  GET  /api/health      → liveness probe

Run:
  python server.py

The UI (UGI.html) calls http://localhost:5000/api/scan
"""

import json
import sys
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS

from checks.ip_check          import check_ip_url
from checks.length_check      import check_url_length
from checks.https_check       import check_https
from checks.shortener_check   import check_url_shortener
from checks.blacklist_check   import check_blacklist
from checks.domain_check      import check_suspicious_domain
from checks.path_check        import check_path_keywords
from checks.tld_check         import check_suspicious_tld
from checks.special_chars_check import check_special_chars
from checks.reachability_check  import check_reachability
from checks.source_analysis_check import check_source_analysis

app = Flask(__name__)
CORS(app)   # allow the HTML file (file://) to call the API

THRESHOLD_SUSPICIOUS = 2
THRESHOLD_DANGEROUS  = 5


def _validate_url(url: str) -> bool:
    try:
        r = urlparse(url)
        return bool(r.scheme and r.netloc)
    except Exception:
        return False


def _verdict(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "DANGEROUS"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "SAFE"


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not _validate_url(url):
        return jsonify({"error": "Invalid URL — include http:// or https://"}), 400

    # ── Static / heuristic checks ─────────────────────────────────────────
    static = [
        ("ip",           "IP-Based URL",        check_ip_url(url)),
        ("https",        "HTTPS Verify",         check_https(url)),
        ("length",       "URL Length",           check_url_length(url)),
        ("shortener",    "Shortener DB",         check_url_shortener(url)),
        ("blacklist",    "Blacklist Lookup",     check_blacklist(url)),
        ("domain",       "Domain Pattern",       check_suspicious_domain(url)),
        ("tld",          "Suspicious TLD",       check_suspicious_tld(url)),
        ("path",         "Path / Query",         check_path_keywords(url)),
        ("special_chars","URL Manipulation",     check_special_chars(url)),
    ]

    checks_out = []
    total = 0
    for key, label, result in static:
        total += result["score"]
        checks_out.append({
            "key":       key,
            "label":     label,
            "triggered": result["triggered"],
            "detail":    result["detail"],
            "score":     result["score"],
        })

    # ── Reachability ──────────────────────────────────────────────────────
    reach = check_reachability(url)
    total += reach["score"]
    checks_out.append({
        "key":       "reachability",
        "label":     "Live Reachability",
        "triggered": reach["triggered"],
        "detail":    reach["detail"],
        "score":     reach["score"],
        "extra":     reach.get("extra", {}),
    })

    # ── Source analysis ───────────────────────────────────────────────────
    src = check_source_analysis(url)
    total += src["score"]
    checks_out.append({
        "key":         "source",
        "label":       "Source Code Analysis",
        "triggered":   src["triggered"],
        "detail":      src["detail"],
        "score":       src["score"],
        "findings":    src.get("findings", []),
        "permissions": src.get("permissions", []),
        "page_purpose": src.get("page_purpose", ""),
        "page_title":   src.get("page_title", ""),
        "status_code":  src.get("status_code"),
        "reachable":    src.get("reachable", False),
    })

    return jsonify({
        "url":     url,
        "score":   total,
        "verdict": _verdict(total),
        "checks":  checks_out,
    })


if __name__ == "__main__":
    print("\n  [PHISH-HUNT API] Starting on http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
