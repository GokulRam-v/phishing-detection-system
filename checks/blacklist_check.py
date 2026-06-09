"""
blacklist_check.py – Compares the URL's domain against a local blacklist file.
The blacklist is stored at data/blacklist.txt, one domain per line.
Lines starting with '#' are treated as comments and ignored.
"""

import os
from urllib.parse import urlparse

# Resolve the blacklist path relative to this file's location
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BLACKLIST_PATH = os.path.join(_HERE, "..", "data", "blacklist.txt")


def _load_blacklist(path: str) -> set:
    """Load domain entries from the blacklist file into a set (lowercase)."""
    domains = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        pass  # Missing blacklist is non-fatal; we just return an empty set
    return domains


def check_blacklist(url: str, blacklist_path: str = DEFAULT_BLACKLIST_PATH) -> dict:
    """
    Check whether the URL's domain appears in the local blacklist.

    Args:
        url: The URL to check.
        blacklist_path: Optional path to an alternative blacklist file.

    Returns:
        dict with keys:
            - triggered (bool): True if the domain is blacklisted.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0 or 5).
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        blacklist = _load_blacklist(blacklist_path)

        if host in blacklist:
            return {
                "triggered": True,
                "detail": f"Domain found in blacklist ({host})",
                "score": 5,
            }
    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "Domain not found in blacklist",
        "score": 0,
    }
