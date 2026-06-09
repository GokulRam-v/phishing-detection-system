"""
main.py – CLI entry point for the Phishing Detection System.

Usage:
    python main.py --url <URL>

Example:
    python main.py --url http://192.168.1.1/login
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

# Initialise colorama (handles Windows ANSI codes automatically)
colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Scoring thresholds
# ---------------------------------------------------------------------------
THRESHOLD_SUSPICIOUS = 2   # score ≥ 2 → Suspicious
THRESHOLD_DANGEROUS = 5    # score ≥ 5 → Dangerous


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
        "SAFE": Fore.GREEN,
        "SUSPICIOUS": Fore.YELLOW,
        "DANGEROUS": Fore.RED,
    }
    return colors.get(verdict, Fore.WHITE)


def _score_to_verdict(score: int) -> str:
    if score >= THRESHOLD_DANGEROUS:
        return "DANGEROUS"
    if score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "SAFE"


def run_checks(url: str) -> None:
    """Execute all checks against *url* and print the results."""
    print()
    print(Fore.CYAN + f"Analysing: {url}" + Style.RESET_ALL)
    print("-" * 60)

    checks = [
        ("IP-based URL",        check_ip_url(url)),
        ("HTTPS check",         check_https(url)),
        ("URL length",          check_url_length(url)),
        ("URL shortener",       check_url_shortener(url)),
        ("Blacklist",           check_blacklist(url)),
        ("Suspicious domain",   check_suspicious_domain(url)),
    ]

    total_score = 0

    for name, result in checks:
        triggered = result["triggered"]
        detail    = result["detail"]
        score     = result["score"]
        total_score += score

        label = _label_for_check(triggered)

        if triggered:
            status_text = Fore.YELLOW + "SUSPICIOUS" if score < THRESHOLD_DANGEROUS else Fore.RED + "DANGEROUS"
            if score >= THRESHOLD_DANGEROUS:
                status_text = Fore.RED + "DANGEROUS"
            elif score > 0:
                status_text = Fore.YELLOW + "SUSPICIOUS"
            else:
                status_text = Fore.GREEN + "OK"
        else:
            status_text = Fore.GREEN + "OK"

        print(f"  {label} {detail:<55} → {status_text}{Style.RESET_ALL}")

    print("-" * 60)

    verdict = _score_to_verdict(total_score)
    color   = _verdict_color(verdict)
    print(
        f"\n  Total risk score : {total_score}"
        f"\n  {color}Final Verdict    : {verdict}{Style.RESET_ALL}\n"
    )


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
