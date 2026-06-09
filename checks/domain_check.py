"""
domain_check.py – Detects suspicious or lookalike domains.

Checks for:
  1. Homoglyph / typosquatting substitutions  (e.g. paypa1.com, g00gle.com)
  2. Brand keywords embedded inside a longer subdomain/path  (e.g. paypal.evil.com)
  3. Excessive hyphens in the domain  (e.g. secure-login-paypal-account.com)
  4. Multiple dots in the hostname  (e.g. login.paypal.com.phishing.net)
"""

import re
from urllib.parse import urlparse

# High-value brand names that are frequently spoofed
TARGETED_BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple",
    "amazon", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "steam", "bankofamerica", "chase", "wellsfargo",
    "citibank", "hsbc", "ebay", "yahoo", "icloud",
]

# Characters commonly substituted for letters in homoglyph attacks
_HOMOGLYPH_PATTERN = re.compile(r"[0-9]")  # digits standing in for letters


def _extract_registered_domain(hostname: str) -> str:
    """
    Very lightweight 'registered domain' extractor.
    Returns the last two labels of the hostname (e.g. 'paypal.com' from
    'login.secure.paypal.com') so we can avoid false positives on legitimate
    subdomains.
    """
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def check_suspicious_domain(url: str) -> dict:
    """
    Analyse the URL's hostname for lookalike / suspicious patterns.

    Returns:
        dict with keys:
            - triggered (bool)
            - detail (str)
            - score (int): 0, 1, or 2
    """
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return {"triggered": False, "detail": "No hostname to analyse", "score": 0}

        registered = _extract_registered_domain(hostname)

        # 1. Brand keyword in a subdomain (not just the registered domain)
        #    e.g. "paypal.evil.com" → hostname != "paypal.com"
        for brand in TARGETED_BRANDS:
            if brand in hostname and brand not in registered:
                reasons.append(f"brand keyword '{brand}' found in subdomain/path")
                score = max(score, 2)

        # 2. Homoglyph digits mixed into the registered domain
        #    e.g. "paypa1.com", "g00gle.com"
        domain_without_tld = registered.split(".")[0]
        for brand in TARGETED_BRANDS:
            # Replace digits with plausible letters and check similarity
            normalised = re.sub(r"1", "l", re.sub(r"0", "o", domain_without_tld))
            if normalised == brand and domain_without_tld != brand:
                reasons.append(
                    f"homoglyph substitution detected ('{domain_without_tld}' ≈ '{brand}')"
                )
                score = max(score, 2)

        # 3. Excessive hyphens (≥ 3) in the hostname
        if hostname.count("-") >= 3:
            reasons.append(f"excessive hyphens in hostname ({hostname.count('-')} hyphens)")
            score = max(score, 1)

        # 4. Many subdomain levels (more than 3 dots total)
        if hostname.count(".") >= 4:
            reasons.append(
                f"deeply nested subdomains ({hostname.count('.')} dots in hostname)"
            )
            score = max(score, 1)

    except Exception:
        pass

    if reasons:
        return {
            "triggered": True,
            "detail": "Suspicious domain pattern: " + "; ".join(reasons),
            "score": score,
        }

    return {
        "triggered": False,
        "detail": "No suspicious domain patterns detected",
        "score": 0,
    }
