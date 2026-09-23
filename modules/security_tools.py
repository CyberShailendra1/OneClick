"""
OneClick Security Suite — Extended Security Tools:
  1. HTTP Security Headers Analyzer
  2. SSL/TLS Certificate & Cipher Inspector
  3. Email Spoofing Defense (SPF / DMARC / MX via DNS-over-HTTPS)
  4. Open Port & Network Service Exposure Checker (SSRF-guarded)
  5. Universal File Threat Hash Scanner (PDF, EXE, ZIP, etc. + VirusTotal)
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from modules.hash_scanner import query_virustotal


# ============================================================================
# 1. HTTP Security Headers Analyzer
# ============================================================================

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "title": "HSTS (Strict-Transport-Security)",
        "importance": "High",
        "description": "Enforces HTTPS connections and prevents SSL stripping man-in-the-middle attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "title": "Content-Security-Policy (CSP)",
        "importance": "Critical",
        "description": "Restricts sources of executable scripts, stylesheets, and objects to prevent XSS and data injection.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
    },
    "X-Frame-Options": {
        "title": "X-Frame-Options",
        "importance": "High",
        "description": "Protects against clickjacking attacks by forbidding framing in <iframe> tags.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options",
        "importance": "Medium",
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy",
        "importance": "Medium",
        "description": "Controls how much referrer information is included with requests when navigating away.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "title": "Permissions-Policy",
        "importance": "Low",
        "description": "Controls access to browser features such as camera, microphone, geolocation.",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
}


def check_security_headers(url: str, timeout: int = 10) -> dict:
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "OneClick-Security-Scanner/1.0"})
    except requests.exceptions.SSLError as e:
        return {"error": f"SSL Handshake error: {e}", "url": url}
    except Exception as e:
        return {"error": f"Connection error: {e}", "url": url}

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    findings = []
    missing_count = 0
    present_count = 0

    for header_name, meta in RECOMMENDED_HEADERS.items():
        val = response_headers.get(header_name.lower())
        if val:
            present_count += 1
            findings.append({
                "header": header_name,
                "title": meta["title"],
                "present": True,
                "value": val,
                "importance": meta["importance"],
                "description": meta["description"],
                "recommendation": None,
            })
        else:
            missing_count += 1
            findings.append({
                "header": header_name,
                "title": meta["title"],
                "present": False,
                "value": None,
                "importance": meta["importance"],
                "description": meta["description"],
                "recommendation": meta["recommended"],
            })

    total = len(RECOMMENDED_HEADERS)
    score = int((present_count / total) * 100)

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    else:
        grade = "F"

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "score": score,
        "grade": grade,
        "present_count": present_count,
        "missing_count": missing_count,
        "server": resp.headers.get("Server"),
        "findings": findings,
    }


# ============================================================================
# 2. SSL/TLS Certificate & Encryption Inspector
# ============================================================================

def _clean_hostname(target: str) -> str:
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target
    if "/" in target:
        target = target.split("/")[0]
    if ":" in target:
        target = target.split(":")[0]
    return target


def inspect_ssl_cert(target: str, port: int = 443, timeout: int = 8) -> dict:
    hostname = _clean_hostname(target)
    if not hostname:
        return {"error": "Invalid hostname"}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname,
            "valid": False,
            "error": f"Certificate verification failed: {e.verify_message}",
            "tls_version": None,
        }
    except Exception as e:
        return {"hostname": hostname, "valid": False, "error": str(e)}

    # Parse validity dates
    not_after_str = cert.get("notAfter")
    not_before_str = cert.get("notBefore")
    days_left = None
    if not_after_str:
        # e.g. "May 10 12:00:00 2025 GMT"
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
        except Exception:
            pass

    # Extract Issuer and Subject
    issuer_dict = {}
    for item in cert.get("issuer", ()):
        for k, v in item:
            issuer_dict[k] = v

    subject_dict = {}
    for item in cert.get("subject", ()):
        for k, v in item:
            subject_dict[k] = v

    sans = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]

    return {
        "hostname": hostname,
        "valid": True,
        "days_left": days_left,
        "expires_on": not_after_str,
        "issued_on": not_before_str,
        "issuer": issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown",
        "subject": subject_dict.get("commonName") or hostname,
        "subject_alt_names": sans[:15],
        "tls_version": tls_version,
        "cipher_suite": cipher[0] if cipher else None,
        "serial_number": cert.get("serialNumber"),
    }


# ============================================================================
# 3. Email Spoofing & Phishing Defense (SPF / DMARC via DoH)
# ============================================================================

def _query_doh_txt(domain: str) -> list[str]:
    """Queries DNS TXT records using Google/Cloudflare DNS-over-HTTPS (no local DNS dependency)."""
    endpoints = [
        f"https://dns.google/resolve?name={domain}&type=TXT",
        f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
    ]
    for url in endpoints:
        try:
            r = requests.get(url, headers={"Accept": "application/dns-json"}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                answers = data.get("Answer", [])
                records = []
                for ans in answers:
                    data_str = ans.get("data", "").strip('"')
                    records.append(data_str)
                return records
        except Exception:
            continue
    return []


def _query_doh_mx(domain: str) -> list[str]:
    """Queries DNS MX records using DoH."""
    url = f"https://dns.google/resolve?name={domain}&type=MX"
    try:
        r = requests.get(url, headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer", [])
            return [ans.get("data", "") for ans in answers]
    except Exception:
        pass
    return []


def check_email_security(domain: str) -> dict:
    domain = _clean_hostname(domain)
    txt_records = _query_doh_txt(domain)
    dmarc_records = _query_doh_txt(f"_dmarc.{domain}")
    mx_records = _query_doh_mx(domain)

    # 1. SPF Check
    spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)
    spf_status = "missing"
    spf_strength = "None"
    if spf_record:
        spf_status = "present"
        if "-all" in spf_record:
            spf_strength = "Hard Fail (-all, Strong)"
        elif "~all" in spf_record:
            spf_strength = "Soft Fail (~all, Moderate)"
        elif "+all" in spf_record or "?all" in spf_record:
            spf_strength = "Weak (?all / +all, Insecure)"

    # 2. DMARC Check
    dmarc_record = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)
    dmarc_policy = "none"
    dmarc_status = "missing"
    if dmarc_record:
        dmarc_status = "present"
        match = re.search(r"p=(reject|quarantine|none)", dmarc_record, re.IGNORECASE)
        if match:
            dmarc_policy = match.group(1).lower()

    # Risk Evaluation
    spoofable = False
    vulnerability_notes = []

    if not spf_record:
        spoofable = True
        vulnerability_notes.append("No SPF record found. Anyone can forge emails claiming to be from this domain.")
    elif "+all" in spf_record:
        spoofable = True
        vulnerability_notes.append("SPF allows '+all' — any mail server can send on behalf of this domain.")

    if not dmarc_record:
        spoofable = True
        vulnerability_notes.append("No DMARC policy found. Receiving email providers will not reject spoofed emails.")
    elif dmarc_policy == "none":
        spoofable = True
        vulnerability_notes.append("DMARC policy is set to 'p=none' (monitoring only). Spoofed emails will still land in inboxes.")

    return {
        "domain": domain,
        "spoofable": spoofable,
        "spf": {
            "status": spf_status,
            "record": spf_record,
            "strength": spf_strength,
        },
        "dmarc": {
            "status": dmarc_status,
            "record": dmarc_record,
            "policy": dmarc_policy,
        },
        "has_mx": len(mx_records) > 0,
        "mx_records": mx_records[:5],
        "vulnerabilities": vulnerability_notes,
    }


# ============================================================================
# 4. Open Port & Network Service Exposure Checker (SSRF-Guarded)
# ============================================================================

COMMON_PORTS = [
    (21, "FTP", "File Transfer Protocol (Unencrypted credentials)"),
    (22, "SSH", "Secure Shell Administrative Access"),
    (23, "Telnet", "Telnet (Unencrypted plaintext console - HIGH RISK)"),
    (25, "SMTP", "Simple Mail Transfer"),
    (80, "HTTP", "Web Server"),
    (443, "HTTPS", "Secure Web Server"),
    (3306, "MySQL", "MySQL Database Port (High Risk if public)"),
    (3389, "RDP", "Remote Desktop Protocol (Frequent target of brute-force)"),
    (5432, "PostgreSQL", "PostgreSQL Database Port"),
    (8080, "HTTP-Proxy", "Alternative Web Port / Proxy"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return True


def scan_port_exposure(target: str, timeout: float = 1.0) -> dict:
    hostname = _clean_hostname(target)
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception as e:
        return {"error": f"Failed to resolve host: {e}", "target": target}

    # Strict SSRF Guard
    if _is_private_ip(resolved_ip):
        return {
            "error": "Scanning of private, internal, or loopback IP addresses is disallowed for security.",
            "target": target,
            "ip": resolved_ip,
        }

    results = []
    open_count = 0

    for port, service, description in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        state = "closed"
        try:
            res = s.connect_ex((resolved_ip, port))
            if res == 0:
                state = "open"
                open_count += 1
        except Exception:
            state = "filtered"
        finally:
            s.close()

        results.append({
            "port": port,
            "service": service,
            "state": state,
            "description": description,
            "risk": "High" if port in (21, 23, 3306, 3389, 5432) and state == "open" else "Normal",
        })

    return {
        "target": hostname,
        "resolved_ip": resolved_ip,
        "open_ports_count": open_count,
        "ports": results,
    }


# ============================================================================
# 5. Universal File Threat Hash Scanner (Any File + VirusTotal)
# ============================================================================

def scan_generic_file(file_path: str, filename: str, vt_api_key: str = None) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    sha256_hash = sha256.hexdigest()
    md5_hash = md5.hexdigest()
    sha1_hash = sha1.hexdigest()

    vt_result = None
    if vt_api_key:
        vt_result = query_virustotal(sha256_hash, vt_api_key)

    verdict = "Unknown (No VT Key)"
    if vt_result and vt_result.get("found"):
        positives = vt_result.get("positives", 0)
        if positives >= 5:
            verdict = "Malicious"
        elif positives > 0:
            verdict = "Suspicious"
        else:
            verdict = "Clean / Undetected"

    return {
        "filename": filename,
        "size_bytes": size,
        "size_formatted": f"{(size / (1024 * 1024)):.2f} MB" if size >= 1048576 else f"{(size / 1024):.1f} KB",
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
        },
        "verdict": verdict,
        "virustotal": vt_result,
    }

