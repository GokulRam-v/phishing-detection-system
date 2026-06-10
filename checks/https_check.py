"""
https_check.py – Checks whether the URL uses a safe scheme.

Risk levels:
  - javascript: / data: / vbscript:  → score 4  (dangerous executable schemes)
  - ftp:                              → score 2  (unencrypted file transfer)
  - http:                             → score 1  (plain HTTP, no encryption)
  - https:                            → score 0  (safe)
"""

from urllib.parse import urlparse

# Schemes that can execute code or carry malicious payloads directly
_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript"}

# Schemes that transmit data in plaintext (lower risk than the above)
_UNENCRYPTED_SCHEMES = {"ftp", "ftps"}


def check_https(url: str) -> dict:
    """
    Check whether the URL uses a safe encrypted scheme.

    Returns:
        dict with keys:
            - triggered (bool): True if the URL does NOT use HTTPS.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0, 1, 2, or 4).
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme in _DANGEROUS_SCHEMES:
            return {
                "triggered": True,
                "detail": f"Dangerous scheme detected ('{scheme}:')",
                "score": 4,
            }

        if scheme in _UNENCRYPTED_SCHEMES:
            return {
                "triggered": True,
                "detail": f"Unencrypted scheme detected ('{scheme}:')",
                "score": 2,
            }

        if scheme == "http":
            return {
                "triggered": True,
                "detail": "No HTTPS — connection is not encrypted (http)",
                "score": 1,
            }

        if scheme == "https":
            return {
                "triggered": False,
                "detail": "HTTPS is being used",
                "score": 0,
            }

        # Unknown / empty scheme
        return {
            "triggered": True,
            "detail": f"Unknown or missing scheme ('{scheme}')",
            "score": 1,
        }

    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "HTTPS is being used",
        "score": 0,
    }
