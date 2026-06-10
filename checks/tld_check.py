"""
tld_check.py – Flags domains using TLDs (top-level domains) that are
disproportionately used for phishing and spam.

Free or very cheap TLDs like .tk, .ml, .ga, .cf, .gq are heavily abused
because they can be registered at zero cost with minimal identity verification.
"""

from urllib.parse import urlparse

# TLDs with a disproportionately high abuse rate
# Sources: Spamhaus TLD reputation data, SURBL, PhishTank analysis
_SUSPICIOUS_TLDS = {
    # Freenom free TLDs — massively abused
    ".tk", ".ml", ".ga", ".cf", ".gq",
    # High-abuse generic TLDs
    ".xyz", ".top", ".click", ".work", ".loan",
    ".date", ".stream", ".download", ".accountant",
    ".racing", ".party", ".review", ".win",
    ".bid", ".trade", ".science", ".faith",
    ".men", ".cricket", ".webcam",
    # Country codes commonly used for abuse
    ".ru", ".cn", ".pw",
}

# TLDs that carry a mild (not severe) risk signal — newer gTLDs sometimes abused
_MILD_SUSPICIOUS_TLDS = {
    ".info", ".biz", ".mobi", ".online", ".site",
    ".space", ".website", ".tech",
}


def check_suspicious_tld(url: str) -> dict:
    """
    Check whether the URL's TLD is in a known high-abuse list.

    Returns:
        dict with keys:
            - triggered (bool)
            - detail (str)
            - score (int): 0, 1, or 2
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname or "." not in hostname:
            return {"triggered": False, "detail": "TLD looks normal", "score": 0}

        # Extract the TLD (last label)
        tld = "." + hostname.rsplit(".", 1)[-1]

        if tld in _SUSPICIOUS_TLDS:
            return {
                "triggered": True,
                "detail": f"High-abuse TLD detected ('{tld}')",
                "score": 2,
            }

        if tld in _MILD_SUSPICIOUS_TLDS:
            return {
                "triggered": True,
                "detail": f"Commonly abused TLD detected ('{tld}')",
                "score": 1,
            }

    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "TLD looks normal",
        "score": 0,
    }
