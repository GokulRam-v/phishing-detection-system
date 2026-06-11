"""
main.py – Unified entry point for the Phishing Detection System.

Behaviour
─────────
  python main.py               → starts the API server only (UI mode)
  python main.py --url <URL>   → starts the API server + runs CLI scan
  python main.py --no-server --url <URL>  → CLI scan only, no server

The Flask API server always starts in a background daemon thread so it
never blocks the CLI output.  Open UI/UGI.html in a browser while the
server is running.

Scoring thresholds
──────────────────
  0 – 2  → SAFE
  3 – 6  → SUSPICIOUS
  7 +    → DANGEROUS
"""

import argparse
import sys
import threading
import time
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

from checks.ip_check             import check_ip_url
from checks.length_check         import check_url_length
from checks.https_check          import check_https
from checks.shortener_check      import check_url_shortener
from checks.blacklist_check      import check_blacklist
from checks.domain_check         import check_suspicious_domain
from checks.path_check           import check_path_keywords
from checks.tld_check            import check_suspicious_tld
from checks.special_chars_check  import check_special_chars
from checks.reachability_check   import check_reachability
from checks.source_analysis_check import check_source_analysis

colorama_init(autoreset=True)

# ── Thresholds ────────────────────────────────────────────────────────────────
THRESHOLD_SUSPICIOUS = 3
THRESHOLD_DANGEROUS  = 7

# ── Server config ─────────────────────────────────────────────────────────────
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000


# ═════════════════════════════════════════════════════════════════════════════
# Flask API server — started in a background daemon thread
# ═════════════════════════════════════════════════════════════════════════════

def _start_server(port: int = SERVER_PORT) -> None:
    """Import and start the Flask app in a daemon thread (non-blocking)."""
    try:
        from flask import Flask, request, jsonify
        from flask_cors import CORS

        app = Flask(__name__)
        CORS(app)

        def _verdict(score: int) -> str:
            if score >= THRESHOLD_DANGEROUS:  return "DANGEROUS"
            if score >= THRESHOLD_SUSPICIOUS: return "SUSPICIOUS"
            return "SAFE"

        def _validate(url: str) -> bool:
            try:
                r = urlparse(url)
                return bool(r.scheme and r.netloc)
            except Exception:
                return False

        @app.route("/api/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"})

        @app.route("/api/scan", methods=["POST"])
        def scan():
            data = request.get_json(silent=True) or {}
            url  = (data.get("url") or "").strip()
            if not url:
                return jsonify({"error": "No URL provided"}), 400
            if not _validate(url):
                return jsonify({"error": "Invalid URL — include http:// or https://"}), 400

            static = [
                ("ip",           "IP-Based URL",       check_ip_url(url)),
                ("https",        "HTTPS Verify",        check_https(url)),
                ("length",       "URL Length",          check_url_length(url)),
                ("shortener",    "Shortener DB",        check_url_shortener(url)),
                ("blacklist",    "Blacklist Lookup",    check_blacklist(url)),
                ("domain",       "Domain Pattern",      check_suspicious_domain(url)),
                ("tld",          "Suspicious TLD",      check_suspicious_tld(url)),
                ("path",         "Path / Query",        check_path_keywords(url)),
                ("special_chars","URL Manipulation",    check_special_chars(url)),
            ]

            checks_out = []
            total = 0
            for key, label, result in static:
                total += result["score"]
                checks_out.append({
                    "key": key, "label": label,
                    "triggered": result["triggered"],
                    "detail": result["detail"],
                    "score": result["score"],
                })

            reach = check_reachability(url)
            total += reach["score"]
            checks_out.append({
                "key": "reachability", "label": "Live Reachability",
                "triggered": reach["triggered"],
                "detail": reach["detail"],
                "score": reach["score"],
                "extra": reach.get("extra", {}),
            })

            src = check_source_analysis(url)
            total += src["score"]
            checks_out.append({
                "key": "source", "label": "Source Code Analysis",
                "triggered":    src["triggered"],
                "detail":       src["detail"],
                "score":        src["score"],
                "findings":     src.get("findings", []),
                "permissions":  src.get("permissions", []),
                "page_purpose": src.get("page_purpose", ""),
                "page_title":   src.get("page_title", ""),
                "status_code":  src.get("status_code"),
                "reachable":    src.get("reachable", False),
            })

            return jsonify({"url": url, "score": total,
                            "verdict": _verdict(total), "checks": checks_out})

        # Suppress Flask's default startup banner — we print our own
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        app.run(host=SERVER_HOST, port=port, debug=False, use_reloader=False)

    except ImportError:
        print(
            Fore.YELLOW
            + "\n  [SERVER] Flask not installed — API server not started."
            + "\n  [SERVER] Run:  pip install flask flask-cors\n"
            + Style.RESET_ALL
        )
    except OSError as exc:
        # Port already in use — server probably already running
        if "10048" in str(exc) or "Address already in use" in str(exc):
            print(
                Fore.YELLOW
                + f"\n  [SERVER] Port {port} already in use — "
                + "server may already be running.\n"
                + Style.RESET_ALL
            )
        else:
            print(Fore.RED + f"\n  [SERVER] Could not start: {exc}\n" + Style.RESET_ALL)


def start_server_background(port: int = SERVER_PORT) -> None:
    """Launch the Flask server in a background daemon thread."""
    t = threading.Thread(target=_start_server, args=(port,), daemon=True, name="flask-api")
    t.start()
    # Give it a moment to bind the port before printing the ready banner
    time.sleep(0.8)
    print(
        Fore.GREEN
        + f"  [SERVER] API running at http://localhost:{port}"
        + Style.RESET_ALL
    )
    print(
        Fore.GREEN
        + "  [SERVER] Open UI/UGI.html in your browser to use the interface.\n"
        + Style.RESET_ALL
    )


# ═════════════════════════════════════════════════════════════════════════════
# CLI helpers
# ═════════════════════════════════════════════════════════════════════════════

def _validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def _label(triggered: bool) -> str:
    return Fore.YELLOW + "[!]" + Style.RESET_ALL if triggered \
        else Fore.GREEN  + "[✓]" + Style.RESET_ALL


def _verdict_color(verdict: str) -> str:
    return {"SAFE": Fore.GREEN, "SUSPICIOUS": Fore.YELLOW,
            "DANGEROUS": Fore.RED}.get(verdict, Fore.WHITE)


def _score_to_verdict(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:  return "DANGEROUS"
    if score >= THRESHOLD_SUSPICIOUS: return "SUSPICIOUS"
    return "SAFE"


def _status_text(score: int, triggered: bool) -> str:
    if not triggered:         return Fore.GREEN  + "OK"        + Style.RESET_ALL
    if score >= THRESHOLD_DANGEROUS: return Fore.RED    + "DANGEROUS"  + Style.RESET_ALL
    if score > 0:             return Fore.YELLOW + "SUSPICIOUS" + Style.RESET_ALL
    return                           Fore.GREEN  + "OK"        + Style.RESET_ALL


def _print_reachability(result: dict) -> None:
    extra     = result.get("extra", {})
    reachable = extra.get("reachable")
    status    = extra.get("status_code")
    final_url = extra.get("final_url")

    print()
    print(Fore.CYAN + "  ── Live Reachability ──────────────────────────────────────────────" + Style.RESET_ALL)

    if reachable is None:
        print(f"  {Fore.WHITE}[~]{Style.RESET_ALL} {result.get('detail','')}")
        return

    icon  = Fore.GREEN + "  [ONLINE] " if reachable else Fore.RED + "  [OFFLINE]"
    color = Fore.GREEN if reachable else Fore.RED
    print(f"{icon}{Style.RESET_ALL} {color}{result.get('detail','')}{Style.RESET_ALL}")
    if final_url: print(f"             Final URL  : {final_url}")
    if status:    print(f"             HTTP Status: {status}")


# ═════════════════════════════════════════════════════════════════════════════
# Main CLI scan
# ═════════════════════════════════════════════════════════════════════════════

def run_checks(url: str) -> None:
    """Run every check against *url* and print a full report to stdout."""
    print()
    print(Fore.CYAN + f"  Analysing: {url}" + Style.RESET_ALL)
    print("  " + "─" * 70)

    static_checks = [
        ("IP-based URL",       check_ip_url(url)),
        ("Scheme / HTTPS",     check_https(url)),
        ("URL length",         check_url_length(url)),
        ("URL shortener",      check_url_shortener(url)),
        ("Blacklist",          check_blacklist(url)),
        ("Suspicious domain",  check_suspicious_domain(url)),
        ("Suspicious TLD",     check_suspicious_tld(url)),
        ("Path / query",       check_path_keywords(url)),
        ("URL manipulation",   check_special_chars(url)),
    ]

    total_score = 0
    for name, result in static_checks:
        total_score += result["score"]
        display = result["detail"] if len(result["detail"]) <= 60 \
            else result["detail"][:57] + "..."
        print(
            f"  {_label(result['triggered'])} "
            f"{display:<60} +{result['score']}  "
            f"{_status_text(result['score'], result['triggered'])}"
        )

    print("  " + "─" * 70)

    # Reachability
    print(f"\n  {Fore.WHITE}Checking live reachability...{Style.RESET_ALL}", end="\r")
    reach = check_reachability(url)
    total_score += reach["score"]
    _print_reachability(reach)

    # Source analysis
    print(f"\n  {Fore.WHITE}Running source code analysis...{Style.RESET_ALL}", end="\r")
    src = check_source_analysis(url)
    total_score += src["score"]

    print()
    print(Fore.CYAN + "  ── Source Code Analysis ───────────────────────────────────────────" + Style.RESET_ALL)
    if src["reachable"]:
        print(f"  Page title  : {src['page_title'] or '(none)'}")
        print(f"  Page purpose: {src['page_purpose']}")
        if src["findings"]:
            for f in src["findings"]:
                print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {f}")
        else:
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} No suspicious patterns found in page source")
        if src["permissions"]:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} Permission APIs detected: {', '.join(src['permissions'])}")
    else:
        print(f"  {Fore.WHITE}[~]{Style.RESET_ALL} {src['detail']}")

    # Final verdict
    verdict = _score_to_verdict(total_score)
    color   = _verdict_color(verdict)
    icons   = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "DANGEROUS": "🚨"}

    print()
    print("  " + "─" * 70)
    print(
        f"\n  Total risk score : {total_score}"
        f"\n  {color}Final Verdict    : {icons.get(verdict,'')}  {verdict}{Style.RESET_ALL}\n"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description=(
            "Phishing Detection System — CLI scanner + API server.\n"
            "Run without --url to start the API server only (for the UI).\n"
            "Run with    --url to scan a URL and also start the API server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        metavar="URL",
        default=None,
        help="URL to analyse (optional). If omitted, only the API server starts.",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Skip starting the API server (CLI scan only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=SERVER_PORT,
        metavar="PORT",
        help=f"Port for the API server (default: {SERVER_PORT}).",
    )

    args = parser.parse_args()

    print()
    print(Fore.GREEN + Style.BRIGHT +
          "  ╔══════════════════════════════════════╗" + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT +
          "  ║   PHISH-HUNT  Threat Analysis v3.0  ║" + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT +
          "  ╚══════════════════════════════════════╝" + Style.RESET_ALL)

    # ── Start the API server in background (unless --no-server) ──────────────
    if not args.no_server:
        start_server_background()

    # ── CLI scan (if --url was given) ─────────────────────────────────────────
    if args.url:
        url = args.url.strip()
        if not _validate_url(url):
            print(
                Fore.RED
                + f"\n  [ERROR] '{url}' is not a valid URL. "
                + "Please include the scheme (http:// or https://).\n"
                + Style.RESET_ALL
            )
            sys.exit(1)
        run_checks(url)

    else:
        # No URL — server-only mode: keep the process alive
        print(
            Fore.CYAN
            + "  No --url given. Running in server-only mode.\n"
            + "  Press Ctrl+C to stop.\n"
            + Style.RESET_ALL
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n  [SERVER] Shutting down. Goodbye.\n" + Style.RESET_ALL)
            sys.exit(0)


if __name__ == "__main__":
    main()
