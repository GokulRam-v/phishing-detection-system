"""
https_check.py – Checks whether the URL uses HTTPS.
Legitimate sites almost universally use HTTPS. Plain HTTP is a risk signal,
though not conclusive on its own.
"""

from urllib.parse import urlparse


def check_https(url: str) -> dict:
    """
    Check whether the URL scheme is HTTPS.

    Returns:
        dict with keys:
            - triggered (bool): True if the URL does NOT use HTTPS.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0 or 1).
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme != "https":
            return {
                "triggered": True,
                "detail": f"No HTTPS detected (scheme: '{scheme}')",
                "score": 1,
            }
    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "HTTPS is being used",
        "score": 0,
    }
