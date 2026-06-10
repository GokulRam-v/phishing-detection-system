"""
reachability_check.py – Verifies whether the URL is actually reachable on the internet.

Behaviour:
  - Sends a HEAD request (falls back to GET) with a short timeout.
  - Follows redirects and reports the final destination URL.
  - Flags redirect chains that land on a completely different domain (common in
    phishing — shortened or cloaked links that bounce to a malicious page).
  - A site being unreachable is itself a mild risk signal (dead/parked domains
    are often used for short-lived phishing campaigns).

Score contributions:
  +0  — site is reachable, final domain matches original
  +1  — site is unreachable (connection error / timeout / DNS failure)
  +2  — site redirects to a completely different domain
  +3  — HTTP 4xx/5xx from the server (broken / parked page)
"""

import socket
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

# Maximum seconds to wait for a response
_TIMEOUT = 6

# Maximum redirects to follow
_MAX_REDIRECTS = 10


def _root_domain(hostname: str) -> str:
    """Return the last two labels of a hostname (e.g. 'evil.com' from 'login.evil.com')."""
    parts = (hostname or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def check_reachability(url: str) -> dict:
    """
    Try to reach the URL and report availability + redirect behaviour.

    Returns:
        dict with keys:
            - triggered (bool)
            - detail (str)
            - score (int): 0–3
            - extra (dict): { 'status_code', 'final_url', 'reachable' }
    """
    if not _REQUESTS_AVAILABLE:
        return {
            "triggered": False,
            "detail": "Reachability check skipped (requests library not installed)",
            "score": 0,
            "extra": {"reachable": None, "status_code": None, "final_url": None},
        }

    try:
        original_host = _root_domain((urlparse(url).hostname or "").lower())

        session = requests.Session()
        session.max_redirects = _MAX_REDIRECTS

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        }

        # Try HEAD first (faster); fall back to GET if the server rejects it
        try:
            resp = session.head(url, timeout=_TIMEOUT, allow_redirects=True,
                                headers=headers, verify=False)
            if resp.status_code == 405:
                resp = session.get(url, timeout=_TIMEOUT, allow_redirects=True,
                                   headers=headers, verify=False, stream=True)
        except requests.exceptions.TooManyRedirects:
            return {
                "triggered": True,
                "detail": "Too many redirects — possible redirect loop",
                "score": 2,
                "extra": {"reachable": False, "status_code": None, "final_url": None},
            }

        final_url  = resp.url
        status     = resp.status_code
        final_host = _root_domain((urlparse(final_url).hostname or "").lower())

        # ------------------------------------------------------------------ #
        # Redirect to a different root domain
        # ------------------------------------------------------------------ #
        if final_host and original_host and final_host != original_host:
            return {
                "triggered": True,
                "detail": (
                    f"Redirects to a different domain: "
                    f"{original_host} → {final_host} (status {status})"
                ),
                "score": 2,
                "extra": {
                    "reachable": True,
                    "status_code": status,
                    "final_url": final_url,
                },
            }

        # ------------------------------------------------------------------ #
        # Server error or parked/broken page
        # ------------------------------------------------------------------ #
        if status >= 400:
            return {
                "triggered": True,
                "detail": f"Server returned HTTP {status} — page may be broken or parked",
                "score": 1,
                "extra": {
                    "reachable": True,
                    "status_code": status,
                    "final_url": final_url,
                },
            }

        # ------------------------------------------------------------------ #
        # Site is up and serving normally
        # ------------------------------------------------------------------ #
        return {
            "triggered": False,
            "detail": f"Site is reachable (HTTP {status})",
            "score": 0,
            "extra": {
                "reachable": True,
                "status_code": status,
                "final_url": final_url,
            },
        }

    # ---------------------------------------------------------------------- #
    # Network-level failures
    # ---------------------------------------------------------------------- #
    except requests.exceptions.SSLError:
        return {
            "triggered": True,
            "detail": "SSL certificate error — site may be using a fake/expired certificate",
            "score": 2,
            "extra": {"reachable": False, "status_code": None, "final_url": None},
        }
    except requests.exceptions.ConnectionError:
        return {
            "triggered": True,
            "detail": "Connection failed — domain may not exist or is down",
            "score": 1,
            "extra": {"reachable": False, "status_code": None, "final_url": None},
        }
    except requests.exceptions.Timeout:
        return {
            "triggered": True,
            "detail": f"Request timed out after {_TIMEOUT}s — site is unreachable",
            "score": 1,
            "extra": {"reachable": False, "status_code": None, "final_url": None},
        }
    except Exception as exc:
        return {
            "triggered": True,
            "detail": f"Reachability check failed: {type(exc).__name__}",
            "score": 1,
            "extra": {"reachable": False, "status_code": None, "final_url": None},
        }
