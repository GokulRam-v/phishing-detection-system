"""
main.py – CLI entry point for the Phishing Detection System.

Usage:
    python main.py --url <URL>

Example:
    python main.py --url http://192.168.1.1/login

Scoring thresholds:
  0 – 1  → SAFE
  2 – 4  → SUSPICIOUS
  5 +    → DANGEROUS
"""

import argparse
import sys
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

from checks.ip_check import check_ip_url
from checks.length_check import check_url_length
from checks.https_check import check_https
from checks.shortener_check import check_url_shortener
from checks.blacklist_check import check_blacklist
from checks.domain_check import check_suspicious_domain
from checks.path_check import check_path_keywords
from checks.tld_check import check_suspicious_tld
from checks.special_chars_check import check_special_chars
from checks.reachability_check import check_reachability

# Initialise colorama (handles Windows ANSI codes automatically)
colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------
THRESHOLD_SUSPICIOUS = 2   # score ≥ 2 → Suspicious
THRESHOLD_DANGEROUS  = 5   # score ≥ 5 → Dangerous


def _validate_url(url: str) -> bool:
    """Return True only if the URL has both a scheme and a network location."""
    try:
        result = urlparse(url)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def _label_for_check(triggered: bool) -> str:
    """Return a coloured status label for a single check row."""
    if triggered:
        return Fore.YELLOW + "[!]" + Style.RESET_ALL
    return Fore.GREEN + "[✓]" + Style.RESET_ALL


def _verdict_color(verdict: str) -> str:
    colors = {
        "SAFE":       Fore.GREEN,
        "SUSPICIOUS": Fore.YELLOW,
        "DANGEROUS":  Fore.RED,
    }
    return colors.get(verdict, Fore.WHITE)


def _score_to_verdict(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "DANGEROUS"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "SAFE"


def _status_text_for(score: int, triggered: bool) -> str:
    """Return a coloured status string for a single check result."""
    if not triggered:
        return Fore.GREEN + "OK" + Style.RESET_ALL
    if score >= THRESHOLD_DANGEROUS:
        return Fore.RED + "DANGEROUS" + Style.RESET_ALL
    if score > 0:
        return Fore.YELLOW + "SUSPICIOUS" + Style.RESET_ALL
    return Fore.GREEN + "OK" + Style.RESET_ALL


def _print_reachability(result: dict) -> None:
    """Print the live reachability block separately (below the check table)."""
    extra     = result.get("extra", {})
    reachable = extra.get("reachable")
    status    = extra.get("status_code")
    final_url = extra.get("final_url")
    detail    = result.get("detail", "")

    print()
    print(Fore.CYAN + "  ── Live Reachability ─────────────────────────────────────────────" + Style.RESET_ALL)

    if reachable is None:
        print(f"  {Fore.WHITE}[~]{Style.RESET_ALL} {detail}")
        return

    if reachable:
        icon  = Fore.GREEN + "  [ONLINE] " + Style.RESET_ALL
        color = Fore.GREEN
    else:
        icon  = Fore.RED + "  [OFFLINE]" + Style.RESET_ALL
        color = Fore.RED

    print(f"{icon} {color}{detail}{Style.RESET_ALL}")

    if final_url:
        print(f"  {'':10} Final URL  : {final_url}")
    if status:
        print(f"  {'':10} HTTP Status: {status}")


def run_checks(url: str) -> None:
    """Execute all checks against *url* and print the results."""
    print()
    print(Fore.CYAN + f"  Analysing: {url}" + Style.RESET_ALL)
    print("  " + "─" * 70)

    # Static / heuristic checks (fast, no network)
    static_checks = [
        ("IP-based URL",      check_ip_url(url)),
        ("Scheme / HTTPS",    check_https(url)),
        ("URL length",        check_url_length(url)),
        ("URL shortener",     check_url_shortener(url)),
        ("Blacklist",         check_blacklist(url)),
        ("Suspicious domain", check_suspicious_domain(url)),
        ("Suspicious TLD",    check_suspicious_tld(url)),
        ("Path / query",      check_path_keywords(url)),
        ("URL manipulation",  check_special_chars(url)),
    ]

    total_score = 0

    for name, result in static_checks:
        triggered = result["triggered"]
        detail    = result["detail"]
        score     = result["score"]
        total_score += score

        label       = _label_for_check(triggered)
        status_text = _status_text_for(score, triggered)
        display     = detail if len(detail) <= 60 else detail[:57] + "..."

        print(f"  {label} {display:<60} +{score}  {status_text}")

    print("  " + "─" * 70)

    # Live reachability check (network call — shown separately)
    print(f"\n  {Fore.WHITE}Checking live reachability...{Style.RESET_ALL}", end="\r")
    reach_result = check_reachability(url)
    total_score += reach_result["score"]

    # Final verdict
    verdict = _score_to_verdict(total_score)
    color   = _verdict_color(verdict)
    icons   = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "DANGEROUS": "🚨"}

    print("  " + "─" * 70)
    print(
        f"\n  Total risk score : {total_score}"
        f"\n  {color}Final Verdict    : {icons.get(verdict, '')}  {verdict}{Style.RESET_ALL}"
    )

    # Print the reachability detail block last
    _print_reachability(reach_result)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Analyse a URL for common phishing indicators.",
    )
    parser.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="The URL to analyse (e.g. https://example.com)",
    )

    args = parser.parse_args()
    url  = args.url.strip()

    if not _validate_url(url):
        print(
            Fore.RED
            + f"\n  [ERROR] '{url}' is not a valid URL. "
            + "Please include the scheme (http:// or https://).\n"
            + Style.RESET_ALL
        )
        sys.exit(1)

    run_checks(url)


if __name__ == "__main__":
    main()
