"""
Phishing / malicious-URL scanner.

Two layers, same philosophy as the APK pipeline:
  1. Heuristic analysis (offline, instant) - structural red flags in the URL itself.
  2. VirusTotal URL reputation (online, reuses the same VT API key already used
     for APK hash lookups) - checks the URL against dozens of aggregated
     phishing/malware blocklists.

This module only ever FLAGS a URL. It never deletes, blocks, or modifies
anything automatically - see the "flag, don't auto-act" design note in
scan_url()'s docstring. Any deletion/removal action is left entirely to the
user, by design, to avoid false-positive data loss.
"""

import re
import time
import base64
import socket
import ipaddress
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

# ---- Heuristic reference data ----

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work",
    "click", "link", "loan", "win", "review", "country", "kim", "party",
}

URGENCY_KEYWORDS = [
    "verify", "suspend", "urgent", "confirm", "update", "secure", "unlock",
    "limited", "expire", "restricted", "reactivate", "billing", "invoice",
]

# A short list of frequently-impersonated brands for typosquat detection.
# (Not exhaustive - intended as a demonstrable heuristic, not a full brand database.)
WELL_KNOWN_DOMAINS = [
    "google.com", "paypal.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "netflix.com", "whatsapp.com", "sbi.co.in",
    "icicibank.com", "hdfcbank.com", "irctc.co.in", "paytm.com", "flipkart.com",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at",
}


def _levenshtein(a: str, b: str) -> int:
    """Small edit-distance helper for typosquat detection (no extra dependency)."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def heuristic_scan(url: str) -> dict:
    """
    Offline structural analysis of a URL. Returns a dict:
      {"score": 0-100, "reasons": [...], "flags": {...}}
    Higher score = more phishing-like structure. This is a heuristic signal,
    not a verdict on its own - it is combined with VirusTotal reputation
    (if available) in scan_url().
    """
    reasons = []
    score = 0

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"score": 100, "reasons": ["URL could not be parsed - treat as suspicious."], "flags": {}}

    host = (parsed.hostname or "").lower()
    full = url.lower()

    flags = {
        "is_ip_host": False, "has_at_symbol": False, "uses_shortener": False,
        "no_https": False, "suspicious_tld": False, "many_subdomains": False,
        "urgency_keyword": False, "possible_typosquat": False, "punycode": False,
        "long_url": False, "many_hyphens": False,
    }

    if _is_ip_host(host):
        flags["is_ip_host"] = True
        score += 30
        reasons.append(f"Domain is a raw IP address ({host}) rather than a name - a common phishing/C2 pattern.")

    if "@" in url.split("://", 1)[-1]:
        flags["has_at_symbol"] = True
        score += 25
        reasons.append("URL contains an '@' symbol, which can hide the real destination host from the visible link text.")

    if host in URL_SHORTENERS:
        flags["uses_shortener"] = True
        score += 10
        reasons.append(f"Uses a URL shortener ({host}) which hides the real destination.")

    if parsed.scheme != "https":
        flags["no_https"] = True
        score += 10
        reasons.append("Link does not use HTTPS - credentials or data submitted would be unencrypted.")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags["suspicious_tld"] = True
        score += 15
        reasons.append(f"Uses a top-level domain (.{tld}) frequently abused for disposable phishing sites.")

    subdomain_count = max(host.count(".") - 1, 0)
    if subdomain_count >= 3:
        flags["many_subdomains"] = True
        score += 15
        reasons.append(f"Unusually deep subdomain chain ({subdomain_count} levels) - often used to bury the real domain.")

    if any(k in full for k in URGENCY_KEYWORDS):
        hit = next(k for k in URGENCY_KEYWORDS if k in full)
        flags["urgency_keyword"] = True
        score += 10
        reasons.append(f"Contains an urgency/social-engineering keyword ('{hit}') commonly used in phishing lures.")

    if "xn--" in host:
        flags["punycode"] = True
        score += 20
        reasons.append("Domain uses punycode (xn--) encoding, which can disguise look-alike international characters (homograph attack).")

    if len(url) > 90:
        flags["long_url"] = True
        score += 5
        reasons.append("Unusually long URL - can be used to obscure the true destination.")

    if host.count("-") >= 3:
        flags["many_hyphens"] = True
        score += 10
        reasons.append("Domain contains many hyphens, a pattern common in generated phishing domains.")

    # Typosquat check 1: compare the registrable domain against well-known brand domains.
    registrable = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    typosquat_hit = False
    for known in WELL_KNOWN_DOMAINS:
        if registrable == known:
            break
        dist = _levenshtein(registrable, known)
        if 0 < dist <= 2 and len(registrable) >= len(known) - 2:
            typosquat_hit = True
            reasons.append(f"Domain '{registrable}' closely resembles a well-known domain ('{known}') - possible typosquatting.")
            break

    # Typosquat check 2: brand-name tokens hidden inside hyphenated/subdomain
    # components (e.g. "paypa1-secure.tk", "login.paypa1.verify-x.com").
    if not typosquat_hit:
        tokens = re.split(r"[.\-]", host)
        brand_names = {d.split(".")[0] for d in WELL_KNOWN_DOMAINS}
        for token in tokens:
            if len(token) < 4:
                continue
            for brand in brand_names:
                if token == brand:
                    continue
                dist = _levenshtein(token, brand)
                if 0 < dist <= 1 and len(brand) >= 4:
                    typosquat_hit = True
                    reasons.append(f"Found '{token}' in the domain, one character away from the brand name '{brand}' - possible typosquatting.")
                    break
            if typosquat_hit:
                break

    if typosquat_hit:
        flags["possible_typosquat"] = True
        score += 35

    score = min(score, 100)
    if not reasons:
        reasons.append("No structural red flags detected in the URL itself.")

    return {"score": score, "reasons": reasons, "flags": flags, "normalized_url": url}


def virustotal_url_scan(url: str, api_key: str, timeout: int = 20) -> dict:
    """
    Submits a URL to VirusTotal v3 and polls for the analysis result.
    Reuses the same VT API key already used for APK hash lookups.
    Returns {"found": bool, "malicious": int, "suspicious": int, "total_engines": int,
             "permalink": str, "error": str|None}
    """
    if not api_key:
        return {"found": False, "error": "NO_API_KEY"}

    headers = {"x-apikey": api_key}

    try:
        # VT wants the URL identifier as base64 (no padding) of the URL itself.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=timeout
        )

        if resp.status_code == 404:
            # Not previously analyzed - submit it for a fresh scan.
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=timeout,
            )
            if submit.status_code != 200:
                return {"found": False, "error": f"SUBMIT_HTTP_{submit.status_code}"}
            analysis_id = submit.json().get("data", {}).get("id")
            # Poll briefly for the analysis to complete (VT queues new submissions).
            for _ in range(4):
                time.sleep(3)
                poll = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers, timeout=timeout,
                )
                if poll.status_code == 200:
                    status = poll.json().get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        stats = poll.json()["data"]["attributes"]["stats"]
                        return {
                            "found": True,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "total_engines": sum(stats.values()),
                            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                            "error": None,
                        }
            return {"found": False, "error": "ANALYSIS_TIMED_OUT"}

        if resp.status_code == 401:
            return {"found": False, "error": "INVALID_API_KEY"}
        if resp.status_code == 429:
            return {"found": False, "error": "RATE_LIMITED"}
        if resp.status_code != 200:
            return {"found": False, "error": f"HTTP_{resp.status_code}"}

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
            "error": None,
        }

    except requests.exceptions.RequestException as e:
        return {"found": False, "error": f"NETWORK_ERROR: {e}"}


def investigate_url(url: str) -> dict:
    """
    Public entry point for the opt-in 'where does this actually lead' deep-dive.
    Wraps analyze_landing_page() - read-only, no JS execution, SSRF-guarded.
    Called only when the user explicitly clicks "Investigate" in the UI.
    """
    return analyze_landing_page(url)


def scan_url(url: str, vt_api_key: str = None, check_domain: bool = False) -> dict:
    """
    Combined phishing risk assessment for a single URL.

    IMPORTANT DESIGN NOTE (by user request): this function only ever FLAGS a
    URL with a risk score and reasons. It never deletes, blocks, quarantines,
    or otherwise modifies anything automatically. Any resulting action
    (ignore / delete / report) is a decision the user makes themselves in
    the UI - this is a deliberate safety choice to avoid false positives
    silently destroying legitimate messages or links.

    check_domain=True adds a WHOIS domain-age lookup (off by default since
    it can take several seconds and WHOIS may be blocked on some networks).
    """
    url = url.strip()
    heur = heuristic_scan(url)
    vt = virustotal_url_scan(heur["normalized_url"], vt_api_key) if vt_api_key else {"found": False, "error": "NO_API_KEY"}

    # Combine: VT signal (if available) dominates, heuristics add/adjust.
    combined_score = heur["score"]
    reasons = list(heur["reasons"])

    if vt.get("found"):
        vt_ratio = vt["malicious"] / vt["total_engines"] if vt.get("total_engines") else 0
        vt_score = min(vt_ratio * 100 * 1.3, 100)  # weight VT detections heavily
        combined_score = max(combined_score, vt_score)
        if vt["malicious"] > 0:
            reasons.insert(0, f"Flagged malicious/phishing by {vt['malicious']} of {vt['total_engines']} VirusTotal engines.")
        else:
            reasons.append("No VirusTotal engines flagged this URL as malicious.")

    domain_age_result = None
    if check_domain:
        from modules.domain_age import check_domain_age
        host = urlparse(heur["normalized_url"]).hostname or ""
        domain_age_result = check_domain_age(host)
        if domain_age_result.get("available") and domain_age_result.get("reason"):
            reasons.append(domain_age_result["reason"])
            if domain_age_result["age_days"] < 7:
                combined_score = max(combined_score, 60)
            elif domain_age_result["is_newly_registered"]:
                combined_score = max(combined_score, 40)

    combined_score = round(min(combined_score, 100), 1)
    if combined_score >= 70:
        label = "Phishing / Malicious"
    elif combined_score >= 35:
        label = "Suspicious"
    else:
        label = "Likely Safe"

    return {
        "url": url,
        "normalized_url": heur["normalized_url"],
        "score": combined_score,
        "label": label,
        "reasons": reasons,
        "heuristic": heur,
        "virustotal": vt,
        "domain_age": domain_age_result,
    }


def extract_urls_from_text(text: str) -> list:
    """Pulls URLs out of a pasted block of text (e.g. a copy-pasted SMS/email body)."""
    pattern = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
    return list(dict.fromkeys(pattern.findall(text)))  # de-duplicate, preserve order


# ---------------------------------------------------------------------------
# Safe landing-page investigation ("what does this link actually do?")
#
# DESIGN / SAFETY NOTES:
#  - This is READ-ONLY. It never submits forms, clicks anything, downloads
#    files, or executes JavaScript. It fetches the raw HTML and parses it
#    statically with BeautifulSoup, the same way a search-engine crawler would.
#  - It is opt-in per URL (a separate "Investigate" action in the UI), not run
#    automatically on every scan, since it means actually contacting the
#    potentially malicious server from this machine.
#  - SSRF protection: every hop's resolved IP is checked and rejected if it's
#    private/loopback/link-local/reserved, so a malicious redirect can't be
#    used to probe your internal network.
#  - Redirects are followed manually (not via requests' auto-follow) so each
#    hop can be inspected and capped.
# ---------------------------------------------------------------------------

MAX_REDIRECTS = 8
MAX_CONTENT_BYTES = 3_000_000  # 3 MB cap on what we'll download and parse
REQUEST_TIMEOUT = 10
USER_AGENT = "OneClick-Analyzer-SafeCrawler/1.0 (+read-only security scan; no JS executed)"

SUSPICIOUS_JS_PATTERNS = [
    (r"eval\s*\(", "Uses eval() - can execute dynamically constructed code."),
    (r"document\.write\s*\(", "Uses document.write() - sometimes used to inject content post-load to evade static scanners."),
    (r"atob\s*\(", "Uses atob() (base64 decode) - can be used to hide malicious strings/URLs from static scanning."),
    (r"unescape\s*\(", "Uses unescape() - a legacy pattern often paired with obfuscated payloads."),
    (r"String\.fromCharCode\s*\(", "Builds strings via character codes - a common obfuscation technique."),
    (r"window\.location(\.href)?\s*=", "Script forces a redirect via window.location - can silently send visitors elsewhere."),
]

CREDENTIAL_INPUT_TYPES = {"password"}
CREDENTIAL_NAME_HINTS = ["password", "passwd", "pwd", "otp", "cvv", "card", "pin", "ssn", "aadhaar"]


def _is_public_ip(host: str) -> bool:
    """SSRF guard: resolve the hostname and reject private/loopback/reserved IPs."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def trace_redirect_chain(url: str) -> dict:
    """
    Manually follows redirects (HTTP 3xx / meta-refresh) up to MAX_REDIRECTS,
    checking each hop against the SSRF guard before proceeding.
    Returns {"chain": [...], "final_url": str, "blocked": bool, "reason": str|None}
    """
    chain = []
    current = url if re.match(r"^https?://", url, re.IGNORECASE) else "http://" + url
    headers = {"User-Agent": USER_AGENT}

    for _ in range(MAX_REDIRECTS):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https"):
            return {"chain": chain, "final_url": current, "blocked": True, "reason": f"Unsupported scheme '{parsed.scheme}'."}
        if not _is_public_ip(parsed.hostname or ""):
            chain.append({"url": current, "status": None, "note": "BLOCKED - resolves to a private/internal address"})
            return {"chain": chain, "final_url": current, "blocked": True, "reason": "Destination resolves to a private/internal IP address - refusing to fetch (SSRF protection)."}

        try:
            resp = requests.get(
                current, headers=headers, timeout=REQUEST_TIMEOUT,
                allow_redirects=False, stream=True,
            )
        except requests.exceptions.RequestException as e:
            chain.append({"url": current, "status": None, "note": f"Request failed: {e}"})
            return {"chain": chain, "final_url": current, "blocked": False, "reason": f"NETWORK_ERROR: {e}"}

        chain.append({"url": current, "status": resp.status_code, "note": None})

        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            current = urljoin(current, resp.headers["Location"])
            continue

        return {"chain": chain, "final_url": current, "blocked": False, "reason": None, "final_response": resp}

    return {"chain": chain, "final_url": current, "blocked": True, "reason": f"Exceeded {MAX_REDIRECTS} redirects."}


def analyze_landing_page(url: str) -> dict:
    """
    Fetches the final destination page (read-only, no JS execution) and
    statically inspects it for phishing/malicious-behavior indicators:
    credential-harvesting forms, cross-domain form submission, meta-refresh
    tricks, and obfuscated inline scripts.
    """
    trace = trace_redirect_chain(url)
    result = {
        "requested_url": url,
        "redirect_chain": [h["url"] for h in trace["chain"]],
        "hop_count": len(trace["chain"]),
        "final_url": trace["final_url"],
        "blocked": trace["blocked"],
        "block_reason": trace.get("reason"),
        "page_title": None,
        "forms": [],
        "meta_refresh_redirect": None,
        "external_script_domains": [],
        "suspicious_scripts": [],
        "likely_actions": [],
    }

    if trace["blocked"] or "final_response" not in trace:
        if trace["blocked"]:
            result["likely_actions"].append(f"Investigation stopped: {trace.get('reason')}")
        return result

    resp = trace["final_response"]
    content_type = resp.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        result["likely_actions"].append(f"Final resource is not an HTML page (Content-Type: {content_type or 'unknown'}) - likely a direct file/download link.")
        return result

    raw = b""
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            raw += chunk
            if len(raw) >= MAX_CONTENT_BYTES:
                break
    except requests.exceptions.RequestException:
        pass

    try:
        html_text = raw.decode(resp.encoding or "utf-8", errors="replace")
    except (LookupError, TypeError):
        html_text = raw.decode("utf-8", errors="replace")

    page_analysis = _analyze_html(html_text, trace["final_url"])
    result.update(page_analysis)
    return result


def _analyze_html(html_text: str, final_url: str) -> dict:
    """
    Pure static-HTML analysis (no network calls) - separated out so it can be
    unit-tested directly against crafted HTML without needing to fetch a real
    page. Looks for credential-harvesting forms, meta-refresh redirects,
    external script domains, and obfuscated inline scripts.
    """
    out = {
        "page_title": None, "forms": [], "meta_refresh_redirect": None,
        "external_script_domains": [], "suspicious_scripts": [], "likely_actions": [],
    }
    soup = BeautifulSoup(html_text, "html.parser")

    title_tag = soup.find("title")
    out["page_title"] = title_tag.get_text(strip=True) if title_tag else None

    final_host = urlparse(final_url).hostname or ""

    for meta in soup.find_all("meta"):
        if meta.get("http-equiv", "").lower() == "refresh":
            content = meta.get("content", "")
            m = re.search(r"url=(.+)", content, re.IGNORECASE)
            if m:
                out["meta_refresh_redirect"] = urljoin(final_url, m.group(1).strip())
                out["likely_actions"].append(f"Page auto-redirects via <meta refresh> to: {out['meta_refresh_redirect']}")

    for form in soup.find_all("form"):
        action = form.get("action", "") or final_url
        action_abs = urljoin(final_url, action)
        action_host = urlparse(action_abs).hostname or ""
        inputs = form.find_all("input")
        input_summary = []
        has_credential_field = False
        for inp in inputs:
            itype = (inp.get("type") or "text").lower()
            iname = (inp.get("name") or "").lower()
            input_summary.append({"type": itype, "name": iname})
            if itype in CREDENTIAL_INPUT_TYPES or any(h in iname for h in CREDENTIAL_NAME_HINTS):
                has_credential_field = True

        cross_domain = bool(action_host) and action_host != final_host
        out["forms"].append({
            "action": action_abs, "method": (form.get("method") or "GET").upper(),
            "cross_domain_submit": cross_domain, "has_credential_field": has_credential_field,
            "inputs": input_summary,
        })

        if has_credential_field and cross_domain:
            out["likely_actions"].append(
                f"Form collects sensitive data (password/OTP/card-like fields) and submits it to a "
                f"DIFFERENT domain ({action_host}) than the page itself - classic credential-harvesting pattern."
            )
        elif has_credential_field:
            out["likely_actions"].append(
                f"Form collects sensitive data (password/OTP/card-like fields) and submits it to {action_host or 'this same page'}."
            )

    ext_domains = set()
    for script in soup.find_all("script", src=True):
        src_abs = urljoin(final_url, script["src"])
        host = urlparse(src_abs).hostname
        if host and host != final_host:
            ext_domains.add(host)
    out["external_script_domains"] = sorted(ext_domains)
    if len(ext_domains) >= 5:
        out["likely_actions"].append(f"Loads scripts from {len(ext_domains)} different external domains - unusually high for a single page.")

    for script in soup.find_all("script", src=False):
        code = script.get_text() or ""
        for pattern, note in SUSPICIOUS_JS_PATTERNS:
            if re.search(pattern, code):
                if note not in out["suspicious_scripts"]:
                    out["suspicious_scripts"].append(note)

    if not out["likely_actions"] and not out["forms"] and not out["suspicious_scripts"]:
        out["likely_actions"].append("No credential-harvesting forms, redirect tricks, or obfuscated scripts detected in the static HTML.")

    return out
