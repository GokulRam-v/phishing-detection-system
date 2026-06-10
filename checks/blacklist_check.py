"""
blacklist_check.py – Compares the URL's domain against a local blacklist file.
The blacklist is stored at data/blacklist.txt, one domain per line.
Lines starting with '#' are treated as comments and ignored.

Improvements over v1:
  - Blacklist is cached in a module-level set (loaded once, not on every call).
  - Subdomain matching: 'sub.evil.com' matches a blacklisted 'evil.com'.
"""

import os
from urllib.parse import urlparse

# Resolve the blacklist path relative to this file's location
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BLACKLIST_PATH = os.path.join(_HERE, "..", "data", "blacklist.txt")

# Module-level cache: { blacklist_path -> frozenset of domains }
_CACHE: dict[str, frozenset] = {}


def _load_blacklist(path: str) -> frozenset:
    """
    Load domain entries from the blacklist file into a frozenset (lowercase).
    Results are cached per path so the file is only read once.
    """
    if path in _CACHE:
        return _CACHE[path]

    domains: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    except FileNotFoundError:
        pass  # Missing blacklist is non-fatal

    result = frozenset(domains)
    _CACHE[path] = result
    return result


def check_blacklist(url: str, blacklist_path: str = DEFAULT_BLACKLIST_PATH) -> dict:
    """
    Check whether the URL's domain (or any parent domain) appears in the blacklist.

    Subdomain matching is supported: if 'evil.com' is blacklisted, then
    'login.evil.com' will also be flagged.

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

        if not host:
            return {"triggered": False, "detail": "Domain not found in blacklist", "score": 0}

        blacklist = _load_blacklist(blacklist_path)

        # Check the host itself, then progressively strip subdomains
        # e.g. for "login.steal.evil.com" we check:
        #   login.steal.evil.com → steal.evil.com → evil.com
        parts = host.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in blacklist:
                return {
                    "triggered": True,
                    "detail": f"Domain found in blacklist ({candidate})",
                    "score": 5,
                }

    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "Domain not found in blacklist",
        "score": 0,
    }
