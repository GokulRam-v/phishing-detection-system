"""
shortener_check.py – Detects known URL-shortening services.
Shortened URLs obscure the real destination, which is a tactic used by phishers
to prevent users from seeing the actual domain before clicking.
"""

from urllib.parse import urlparse

# Common URL shorteners — expanded list
KNOWN_SHORTENERS = {
    # Classic
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "rebrand.ly", "short.io", "is.gd", "v.gd",
    "bl.ink", "tiny.cc", "shrtco.de", "cutt.ly", "shorturl.at",
    "rb.gy", "clck.ru", "qr.ae",
    # Additional popular / emerging services
    "t.ly", "s.id", "urlz.fr", "chilp.it", "mcaf.ee",
    "snip.ly", "po.st", "lnkd.in", "fb.me", "amzn.to",
    "youtu.be", "ift.tt", "dlvr.it", "soo.gd", "x.co",
    "lc.cx", "shorten.im", "1url.com", "shrink.im",
    "vzturl.com", "yourls.org",
}


def check_url_shortener(url: str) -> dict:
    """
    Check whether the URL's domain belongs to a known shortening service.

    Returns:
        dict with keys:
            - triggered (bool): True if a URL shortener is detected.
            - detail (str): Human-readable description of the result.
            - score (int): Risk score contribution (0 or 2).
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if host in KNOWN_SHORTENERS:
            return {
                "triggered": True,
                "detail": f"URL shortener detected ({host}) — real destination hidden",
                "score": 2,
            }
    except Exception:
        pass

    return {
        "triggered": False,
        "detail": "No URL shortener detected",
        "score": 0,
    }
