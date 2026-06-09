"""
ip_check.py – Detects whether the URL uses a raw IP address as the host.
Using an IP instead of a domain name is a common phishing indicator.
"""

import re
from urllib.parse import urlparse

# Matches IPv4 addresses (e.g. 192.168.1.1)
IPV4_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# Matches IPv6 addresses wrapped in brackets (e.g. [::1])
IPV6_PATTERN = re.compile(r"^\[.*\]$")


def check_ip_url(url: str) -> dict:
    """
    Check if the URL host is a raw IP address.

    Returns:
        dict with keys:
            - triggered (bool): True if an IP-based URL is detected.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0 or 3).
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if IPV4_PATTERN.match(host) or IPV6_PATTERN.match(host):
            return {
                "triggered": True,
                "detail": f"IP-based URL detected ({host})",
                "score": 3,
            }
    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "No IP-based URL detected",
        "score": 0,
    }
