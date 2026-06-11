"""
source_analysis_check.py – Fetches the URL's HTML source and inspects it for:

  1. Form actions pointing to external/suspicious domains  (score +3)
  2. Password input fields present on the page            (score +2)
  3. Suspicious <meta> redirects                          (score +2)
  4. Obfuscated JavaScript (eval/atob/unescape patterns)  (score +2)
  5. Iframe embedding of external pages                   (score +2)
  6. External script sources from untrusted domains       (score +1)
  7. Data-harvesting permission requests in JS            (score +1)
     (geolocation, camera, microphone, clipboard)
  8. Hidden input fields (credential harvesting)          (score +1)
  9. Favicon mismatch (page pretends to be a brand)       (score +1)
 10. Page title containing brand impersonation keywords   (score +1)

Also returns a human-readable summary of what the page appears to be doing.
"""

import re
from urllib.parse import urlparse, urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# ── constants ────────────────────────────────────────────────────────────────

_TIMEOUT = 8
_MAX_BYTES = 512_000          # read at most 500 KB

_BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "steam",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc",
    "ebay", "yahoo", "icloud",
]

# Trusted CDN / affiliate domains — scripts from these do NOT count as
# "external suspicious" even if they differ from the page's own domain.
_TRUSTED_CDN_DOMAINS = {
    "googleapis.com", "gstatic.com", "google.com", "googletagmanager.com",
    "googleanalytics.com", "googlesyndication.com", "doubleclick.net",
    "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net",
    "unpkg.com", "bootstrapcdn.com", "jquery.com",
    "facebook.net", "fbcdn.net", "twitter.com", "twimg.com",
    "amazon.com", "amazonaws.com", "akamaihd.net", "fastly.net",
    "microsoft.com", "msecnd.net", "live.com",
    "apple.com", "icloud.com",
    "youtube.com", "ytimg.com",
    "wp.com", "wordpress.com",
    "cloudfront.net", "azureedge.net",
}

_JS_OBFUSCATION = re.compile(
    r'\b(eval\s*\(|atob\s*\(|unescape\s*\(|String\.fromCharCode\s*\(|'
    r'document\.write\s*\(.*\\x|\\u00)',
    re.IGNORECASE,
)

_PERMISSION_API = re.compile(
    r'(navigator\.(geolocation|mediaDevices|clipboard)|'
    r'getUserMedia|requestPermission)',
    re.IGNORECASE,
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


# ── tiny HTML helpers (no external parser needed) ───────────────────────────

def _tag_attrs(html: str, tag: str) -> list[dict]:
    """Return a list of attribute dicts for every occurrence of <tag ...>."""
    pattern = re.compile(
        r'<' + re.escape(tag) + r'(\s[^>]*?)?>',
        re.IGNORECASE | re.DOTALL,
    )
    attr_re = re.compile(r'([\w\-]+)\s*=\s*(?:"([^"]*?)"|\'([^\']*?)\'|([^\s>]+))',
                         re.IGNORECASE)
    results = []
    for m in pattern.finditer(html):
        attrs_str = m.group(1) or ""
        attrs = {a.group(1).lower(): (a.group(2) or a.group(3) or a.group(4) or "")
                 for a in attr_re.finditer(attrs_str)}
        results.append(attrs)
    return results

def _meta_content(html: str) -> list[str]:
    """Return content values of all <meta http-equiv='refresh'> tags."""
    found = []
    for attrs in _tag_attrs(html, "meta"):
        if attrs.get("http-equiv", "").lower() == "refresh":
            found.append(attrs.get("content", ""))
    return found

def _root_domain(hostname: str) -> str:
    """
    Return a normalised 'root domain' string used for cross-domain comparisons.
    Handles cases like:
      - about.google       → google
      - mail.google.com    → google.com
      - login.evil.co.uk   → evil.co.uk
    The goal is to extract the brand/owner name so we can tell whether two
    hostnames belong to the same organisation.
    """
    parts = (hostname or "").lower().split(".")
    if len(parts) == 0:
        return hostname
    # Single label (e.g. "localhost") — return as-is
    if len(parts) == 1:
        return parts[0]
    # Known two-part TLDs
    _MULTI = {"co.uk","co.in","co.nz","co.za","com.au","com.br","org.uk","net.au","ac.uk","gov.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI:
        return ".".join(parts[-3:])
    # Brand-TLD registries like .google, .apple, .microsoft
    # These are single-label TLDs owned by the brand — treat the TLD itself
    # as the brand identifier.
    _BRAND_TLDS = {"google","apple","microsoft","amazon","youtube","gmail",
                   "facebook","instagram","linkedin","twitter","yahoo"}
    if parts[-1] in _BRAND_TLDS:
        return parts[-1]   # just "google", "apple", etc.
    return ".".join(parts[-2:])

def _page_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""

def _inline_scripts(html: str) -> str:
    """Concatenate all inline <script> content."""
    return " ".join(
        m.group(1)
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', html,
                             re.IGNORECASE | re.DOTALL)
    )


# ── main check ───────────────────────────────────────────────────────────────

def check_source_analysis(url: str) -> dict:
    """
    Fetch the page at *url* and perform source-level analysis.

    Returns:
        dict with keys:
            - triggered (bool)
            - detail (str)           – one-line summary (for the check table)
            - score (int)
            - findings (list[str])   – individual flagged items
            - permissions (list[str])– permission-related APIs detected
            - page_purpose (str)     – best-guess description of page intent
            - page_title (str)
            - status_code (int|None)
            - reachable (bool)
    """
    if not _REQUESTS_OK:
        return _skip("requests library not installed")

    # ── fetch ────────────────────────────────────────────────────────────────
    try:
        resp = requests.get(
            url, timeout=_TIMEOUT, headers=_HEADERS,
            verify=False, stream=True, allow_redirects=True,
        )
        # Read up to _MAX_BYTES
        raw = b""
        for chunk in resp.iter_content(chunk_size=16384):
            raw += chunk
            if len(raw) >= _MAX_BYTES:
                break
        html = raw.decode("utf-8", errors="replace")
        status_code = resp.status_code
    except Exception as exc:
        return _skip(f"Could not fetch page: {type(exc).__name__}: {exc}")

    original_domain = _root_domain((urlparse(url).hostname or "").lower())

    findings     = []
    permissions  = []
    score        = 0

    title        = _page_title(html)
    scripts      = _inline_scripts(html)

    # ── 1. Forms with external action ────────────────────────────────────────
    for form in _tag_attrs(html, "form"):
        action = form.get("action", "")
        if action.startswith("http"):
            action_domain = _root_domain((urlparse(action).hostname or "").lower())
            if action_domain and action_domain != original_domain:
                findings.append(
                    f"Form submits data to external domain: {action_domain}"
                )
                score += 3

    # ── 2. Password inputs ────────────────────────────────────────────────────
    pw_fields = [
        inp for inp in _tag_attrs(html, "input")
        if inp.get("type", "").lower() == "password"
    ]
    if pw_fields:
        findings.append(
            f"Password input field(s) detected ({len(pw_fields)} found)"
        )
        score += 2

    # ── 3. Meta refresh redirect ──────────────────────────────────────────────
    for content in _meta_content(html):
        if "url=" in content.lower():
            redirect_url = re.search(r'url\s*=\s*(.+)', content, re.IGNORECASE)
            dest = redirect_url.group(1).strip().strip("'\"") if redirect_url else "unknown"
            findings.append(f"Meta-refresh redirect detected → {dest[:60]}")
            score += 2

    # ── 4. Obfuscated JavaScript ──────────────────────────────────────────────
    # Require at least 3 distinct obfuscation patterns to avoid false positives
    # on legitimate minified/analytics code.
    obf_matches = _JS_OBFUSCATION.findall(scripts)
    unique_obf = {m[0] if isinstance(m, tuple) else m for m in obf_matches}
    if len(unique_obf) >= 3:
        findings.append(
            f"Obfuscated JavaScript detected ({len(obf_matches)} pattern(s): "
            + ", ".join(sorted(unique_obf)[:3]) + ")"
        )
        score += 2

    # ── 5. Iframes embedding external pages ───────────────────────────────────
    for iframe in _tag_attrs(html, "iframe"):
        src = iframe.get("src", "")
        if src.startswith("http"):
            iframe_domain = _root_domain((urlparse(src).hostname or "").lower())
            if iframe_domain and iframe_domain != original_domain:
                findings.append(f"Iframe embedding external page: {iframe_domain}")
                score += 2

    # ── 6. External script sources ────────────────────────────────────────────
    # Skip scripts from well-known trusted CDN / affiliate domains.
    external_scripts = []
    for script in _tag_attrs(html, "script"):
        src = script.get("src", "")
        if src.startswith("http"):
            sc_domain = _root_domain((urlparse(src).hostname or "").lower())
            if sc_domain and sc_domain != original_domain and sc_domain not in _TRUSTED_CDN_DOMAINS:
                external_scripts.append(sc_domain)

    if external_scripts:
        uniq = list(dict.fromkeys(external_scripts))[:5]
        findings.append(f"External scripts from unknown domains: {', '.join(uniq)}")
        score += min(len(uniq), 1)

    # ── 7. Permission / data-harvesting APIs ─────────────────────────────────
    perm_hits = _PERMISSION_API.findall(scripts + html)
    if perm_hits:
        detected = sorted({h[0] if isinstance(h, tuple) else h for h in perm_hits})
        permissions = detected
        findings.append(
            f"Sensitive browser APIs detected: {', '.join(detected[:4])}"
        )
        score += 1

    # ── 8. Hidden input fields ────────────────────────────────────────────────
    # Raise bar to 6 — many legitimate sites (Google, etc.) use several hidden
    # fields for CSRF tokens and analytics without being malicious.
    hidden = [
        inp for inp in _tag_attrs(html, "input")
        if inp.get("type", "").lower() == "hidden"
    ]
    if len(hidden) >= 6:
        findings.append(
            f"{len(hidden)} hidden input field(s) detected (possible data harvesting)"
        )
        score += 1

    # ── 9. Brand impersonation in title ───────────────────────────────────────
    # Only flag if the brand is in the title AND the page domain has NO relation
    # to that brand at all (i.e., original_domain doesn't contain the brand name).
    title_lower = title.lower()
    for brand in _BRANDS:
        if brand in title_lower and brand not in original_domain:
            findings.append(
                f"Page title '{title[:50]}' references brand '{brand}' "
                f"not matching domain '{original_domain}'"
            )
            score += 1
            break

    # ── 10. Favicon domain mismatch ───────────────────────────────────────────
    for link in _tag_attrs(html, "link"):
        rel = link.get("rel", "").lower()
        if "icon" in rel:
            href = link.get("href", "")
            if href.startswith("http"):
                fav_domain = _root_domain((urlparse(href).hostname or "").lower())
                if fav_domain and fav_domain != original_domain:
                    findings.append(
                        f"Favicon loaded from different domain: {fav_domain}"
                    )
                    score += 1
            break

    # ── Guess page purpose ────────────────────────────────────────────────────
    page_purpose = _infer_purpose(html, title, findings)

    # ── Build summary ─────────────────────────────────────────────────────────
    if findings:
        detail = f"{len(findings)} issue(s) found in page source"
    else:
        detail = "Page source appears clean — no suspicious patterns detected"

    return {
        "triggered": bool(findings),
        "detail":     detail,
        "score":      min(score, 10),   # cap contribution at 10
        "findings":   findings,
        "permissions": permissions,
        "page_purpose": page_purpose,
        "page_title":   title,
        "status_code":  status_code,
        "reachable":    True,
    }


def _infer_purpose(html: str, title: str, findings: list) -> str:
    """Return a plain-English guess at what the page is doing."""
    html_lower = html.lower()
    title_lower = title.lower()
    hints = []

    if any("password" in f.lower() or "login" in title_lower
           or "signin" in title_lower for f in findings):
        hints.append("credential harvesting / fake login page")

    if any("form submits" in f.lower() for f in findings):
        hints.append("data exfiltration via form submission")

    if any("meta-refresh" in f.lower() for f in findings):
        hints.append("automatic redirect / cloaking")

    if any("obfuscated" in f.lower() for f in findings):
        hints.append("malicious obfuscated script execution")

    if any("iframe" in f.lower() for f in findings):
        hints.append("iframe-based content injection")

    if any("geolocation" in f.lower() or "camera" in f.lower()
           or "microphone" in f.lower() for f in findings):
        hints.append("requesting sensitive device permissions")

    if any("clipboard" in f.lower() for f in findings):
        hints.append("clipboard access / data theft")

    # Generic content clues
    if "download" in html_lower and "install" in html_lower:
        hints.append("software download / potential malware distribution")

    if not hints:
        if any(w in title_lower for w in ("shop","store","cart","buy","checkout")):
            hints.append("e-commerce / shopping page")
        elif any(w in title_lower for w in ("news","article","blog","post")):
            hints.append("content / news page")
        else:
            hints.append("general informational page")

    return " | ".join(hints)


def _skip(reason: str) -> dict:
    return {
        "triggered":   False,
        "detail":      f"Source analysis skipped: {reason}",
        "score":       0,
        "findings":    [],
        "permissions": [],
        "page_purpose": "unknown",
        "page_title":   "",
        "status_code":  None,
        "reachable":    False,
    }
