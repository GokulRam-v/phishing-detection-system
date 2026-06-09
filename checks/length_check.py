"""
length_check.py – Flags URLs that are abnormally long.
Phishing URLs are often padded with extra path segments or query parameters
to confuse users and bypass simple filters.
"""

# Threshold from the PRD
LENGTH_THRESHOLD = 75


def check_url_length(url: str) -> dict:
    """
    Check whether the URL exceeds the configured length threshold.

    Returns:
        dict with keys:
            - triggered (bool): True if the URL is suspiciously long.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0 or 1).
    """
    length = len(url)

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
