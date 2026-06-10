"""
domain_check.py – Detects suspicious or lookalike domains.

Checks for:
  1. Homoglyph / typosquatting substitutions  (e.g. paypa1.com, g00gle.com, m1cr0s0ft.com)
  2. Brand keyword embedded in the registered domain with extra words
     (e.g. paypal-secure.com, google-login.net)
  3. Brand keyword in a subdomain  (e.g. paypal.evil.com)
  4. Excessive hyphens in the domain  (e.g. secure-login-paypal-account.com)
  5. Deeply nested subdomains  (e.g. login.paypal.com.phishing.net)
  6. Unicode / punycode (IDN) hostnames  (e.g. xn--pypa1-xra.com)
  7. Mixed-script hostnames containing non-ASCII characters
"""

import re
import unicodedata
from urllib.parse import urlparse

# High-value brand names that are frequently spoofed
TARGETED_BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple",
    "amazon", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "steam", "bankofamerica", "chase", "wellsfargo",
    "citibank", "hsbc", "ebay", "yahoo", "icloud", "outlook",
    "office365", "onedrive", "adobe", "docusign", "dhl", "fedex",
    "ups", "usps", "irs", "coinbase", "binance",
]

# Comprehensive homoglyph / leet-speak substitution map
_HOMOGLYPH_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
})


def _normalise_homoglyphs(text: str) -> str:
    """Replace common leet/homoglyph characters with their ASCII equivalents."""
    # First translate digits/symbols
    result = text.translate(_HOMOGLYPH_MAP)
    # Then convert Unicode lookalikes to their closest ASCII via NFKD decomposition
    result = unicodedata.normalize("NFKD", result)
    result = "".join(c for c in result if unicodedata.category(c) != "Mn")
    return result


def _extract_registered_domain(hostname: str) -> str:
    """
    Lightweight registered-domain extractor.
    Handles common two-part TLDs (co.uk, com.au, etc.) by checking the last
    three labels when the second-to-last is a known delegated SLD.
    """
    MULTI_PART_TLDS = {
        "co.uk", "co.in", "co.nz", "co.za", "co.jp", "co.kr",
        "com.au", "com.br", "com.mx", "org.uk", "net.au",
        "ac.uk", "gov.uk", "sch.uk",
    }
    parts = hostname.split(".")
    if len(parts) >= 3:
        candidate = ".".join(parts[-2:])
        if candidate in MULTI_PART_TLDS:
            return ".".join(parts[-3:])
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
            - score (int): 0, 1, 2, or 3
    """
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return {"triggered": False, "detail": "No hostname to analyse", "score": 0}

        registered = _extract_registered_domain(hostname)
        domain_without_tld = registered.split(".")[0]

        # ------------------------------------------------------------------ #
        # 1. Homoglyph / leet-speak substitution in the registered domain
        #    e.g. "paypa1.com", "g00gle.com", "m1cr0s0ft.com"
        # ------------------------------------------------------------------ #
        normalised = _normalise_homoglyphs(domain_without_tld)
        for brand in TARGETED_BRANDS:
            if normalised == brand and domain_without_tld != brand:
                reasons.append(
                    f"homoglyph substitution detected ('{domain_without_tld}' ≈ '{brand}')"
                )
                score = max(score, 3)

        # ------------------------------------------------------------------ #
        # 2. Brand keyword mixed into the registered domain with extra words
        #    e.g. "paypal-secure.com", "google-login.net", "apple-id-update.com"
        #    Strategy: strip hyphens/digits from the domain and check for brand
        # ------------------------------------------------------------------ #
        domain_stripped = re.sub(r"[-_0-9]", "", domain_without_tld)
        for brand in TARGETED_BRANDS:
            # The brand must be a substring of the stripped domain, AND
            # the domain must not be the brand itself (to avoid false positives
            # on the real site being in a subdomain — handled separately)
            if brand in domain_stripped and domain_stripped != brand:
                # Avoid double-reporting with check 1
                if not any(brand in r for r in reasons):
                    reasons.append(
                        f"brand keyword '{brand}' embedded in domain ('{domain_without_tld}')"
                    )
                    score = max(score, 2)

        # ------------------------------------------------------------------ #
        # 3. Brand keyword in a subdomain but NOT the registered domain
        #    e.g. "paypal.evil.com" — paypal is in the subdomain, not in evil.com
        # ------------------------------------------------------------------ #
        for brand in TARGETED_BRANDS:
            if brand in hostname and brand not in registered:
                if not any(brand in r for r in reasons):
                    reasons.append(f"brand keyword '{brand}' found in subdomain")
                    score = max(score, 2)

        # ------------------------------------------------------------------ #
        # 4. Excessive hyphens (≥ 3) — e.g. secure-login-verify-account.com
        # ------------------------------------------------------------------ #
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            reasons.append(f"excessive hyphens in hostname ({hyphen_count} hyphens)")
            score = max(score, 1)

        # ------------------------------------------------------------------ #
        # 5. Deeply nested subdomains (≥ 3 dots)
        #    e.g. login.paypal.com.phishing.net  (3 dots = 4 labels)
        # ------------------------------------------------------------------ #
        dot_count = hostname.count(".")
        if dot_count >= 3:
            reasons.append(
                f"deeply nested subdomains ({dot_count} dots in hostname)"
            )
            score = max(score, 1)

        # ------------------------------------------------------------------ #
        # 6. Punycode / IDN hostname  (xn-- prefix indicates encoded Unicode)
        # ------------------------------------------------------------------ #
        if "xn--" in hostname:
            reasons.append(f"punycode/IDN hostname detected ('{hostname}')")
            score = max(score, 3)

        # ------------------------------------------------------------------ #
        # 7. Non-ASCII characters in hostname (Unicode homoglyph attack)
        # ------------------------------------------------------------------ #
        if any(ord(c) > 127 for c in hostname):
            reasons.append("non-ASCII characters in hostname (possible Unicode spoofing)")
            score = max(score, 3)

    except Exception:
        pass

    if reasons:
        return {
            "triggered": True,
            "detail": "Suspicious domain: " + "; ".join(reasons),
            "score": score,
        }

    return {
        "triggered": False,
        "detail": "No suspicious domain patterns detected",
        "score": 0,
    }
