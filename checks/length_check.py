"""
length_check.py – Flags URLs that are abnormally long.
Phishing URLs are often padded with extra path segments or query parameters
to confuse users and bypass simple filters.

Thresholds (raised from 75 to reduce false positives on legitimate e-commerce URLs):
  - > 100 chars  → SUSPICIOUS (+1)
  - > 150 chars  → stronger signal (+2)
"""

LENGTH_THRESHOLD = 100       # URLs longer than this are suspicious
LENGTH_THRESHOLD_HIGH = 150  # URLs longer than this are more strongly flagged


def check_url_length(url: str) -> dict:
    """
    Check whether the URL exceeds the configured length threshold.

    Returns:
        dict with keys:
            - triggered (bool): True if the URL is suspiciously long.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0, 1, or 2).
    """
    length = len(url)

    if length > LENGTH_THRESHOLD_HIGH:
        return {
            "triggered": True,
            "detail": f"URL is very long ({length} characters, threshold: {LENGTH_THRESHOLD_HIGH})",
            "score": 2,
        }

    if length > LENGTH_THRESHOLD:
        return {
            "triggered": True,
            "detail": f"URL is abnormally long ({length} characters, threshold: {LENGTH_THRESHOLD})",
            "score": 1,
        }

    return {
        "triggered": False,
        "detail": f"URL length is normal ({length} characters)",
        "score": 0,
    }
