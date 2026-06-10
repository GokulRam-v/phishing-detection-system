"""
path_check.py – Scans the URL path and query string for phishing-related keywords.

Phishing pages commonly use words like 'login', 'verify', 'secure', 'account',
'password', 'update', 'banking', or 'confirm' in the URL to appear legitimate.
This check also looks for encoded characters that are used to obfuscate malicious URLs.
"""

import re
from urllib.parse import urlparse, unquote

# Keywords strongly associated with phishing pages
_PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate", "validation",
    "account", "accounts",
    "secure", "security",
    "update", "confirm", "confirmation",
    "password", "passwd", "credential",
    "banking", "bank",
    "recover", "recovery",
    "suspend", "suspended",
    "authenticate", "authentication",
    "wallet", "crypto", "invoice",
    "alert", "urgent", "important",
    "webscr",            # PayPal phishing classic
    "ebayisapi",         # eBay phishing classic
}

# Multiple consecutive encoded characters indicate obfuscation
_EXCESSIVE_ENCODING_RE = re.compile(r"(%[0-9a-fA-F]{2}){4,}")


def check_path_keywords(url: str) -> dict:
    """
    Scan the path and query string of the URL for suspicious keywords
    and obfuscation techniques.

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
        # Decode percent-encoding so we catch obfuscated keywords
        path_and_query = unquote(
            (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
        ).lower()

        # 1. Check for phishing keywords
        found_keywords = [kw for kw in _PHISHING_KEYWORDS if kw in path_and_query]
        if len(found_keywords) >= 2:
            reasons.append(
                f"multiple phishing keywords in path: {', '.join(sorted(found_keywords)[:4])}"
            )
            score = max(score, 2)
        elif found_keywords:
            reasons.append(f"phishing keyword in path: '{found_keywords[0]}'")
            score = max(score, 1)

        # 2. Excessive percent-encoding (obfuscation)
        raw_path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
        if _EXCESSIVE_ENCODING_RE.search(raw_path):
            reasons.append("excessive URL encoding detected (possible obfuscation)")
            score = max(score, 2)

        # 3. Double slashes in path (common in redirector attacks)
        if "//" in parsed.path:
            reasons.append("double slashes in URL path (possible open redirect)")
            score = max(score, 1)

    except Exception:
        pass

    if reasons:
        return {
            "triggered": True,
            "detail": "Suspicious path/query: " + "; ".join(reasons),
            "score": score,
        }

    return {
        "triggered": False,
        "detail": "No suspicious keywords or patterns in URL path",
        "score": 0,
    }
