"""
special_chars_check.py – Detects URL tricks that misdirect users or hide the
real destination.

Checks for:
  1. @-sign misdirection  — https://google.com@evil.com  (navigates to evil.com)
  2. Embedded credentials — https://user:pass@domain.com
  3. javascript: / data: in the netloc / path (already partially handled by https_check,
     but can appear in unusual positions)
  4. Null-byte injection  — %00 in the URL
  5. Repeated dots / unusual characters in the hostname
"""

from urllib.parse import urlparse


def check_special_chars(url: str) -> dict:
    """
    Detect URL-manipulation tricks used in phishing attacks.

    Returns:
        dict with keys:
            - triggered (bool)
            - detail (str)
            - score (int): 0, 2, 3, or 4
    """
    reasons = []
    score = 0

    try:
        # --- Raw URL level checks ---

        # 1. Null-byte injection
        if "%00" in url or "\x00" in url:
            reasons.append("null-byte injection detected (%00)")
            score = max(score, 4)

        # 2. javascript: or data: anywhere in the raw URL (not just scheme position)
        url_lower = url.lower()
        for bad_scheme in ("javascript:", "data:", "vbscript:"):
            if bad_scheme in url_lower:
                reasons.append(f"dangerous scheme token '{bad_scheme}' found in URL")
                score = max(score, 4)

        # --- Parsed URL checks ---
        parsed = urlparse(url)

        # 3. @-sign in the netloc: https://trusted.com@evil.com/path
        #    urlparse correctly identifies evil.com as the host, but the raw
        #    netloc contains 'trusted.com@evil.com', which confuses users.
        netloc = parsed.netloc or ""
        if "@" in netloc:
            reasons.append(
                "@-sign in URL authority — displayed domain may differ from real destination"
            )
            score = max(score, 3)

        # 4. Embedded credentials (username and/or password in the URL)
        if parsed.username or parsed.password:
            reasons.append(
                "embedded credentials in URL (user:pass@ pattern)"
            )
            score = max(score, 3)

        # 5. Double-encoded characters (%25xx — encoding of a percent sign)
        if "%25" in url:
            reasons.append("double URL-encoding detected (%25xx — possible filter evasion)")
            score = max(score, 2)

        # 6. Consecutive dots in the hostname (e.g. evil..com)
        hostname = (parsed.hostname or "").lower()
        if ".." in hostname:
            reasons.append("consecutive dots in hostname")
            score = max(score, 2)

    except Exception:
        pass

    if reasons:
        return {
            "triggered": True,
            "detail": "URL manipulation detected: " + "; ".join(reasons),
            "score": score,
        }

    return {
        "triggered": False,
        "detail": "No URL manipulation tricks detected",
        "score": 0,
    }
