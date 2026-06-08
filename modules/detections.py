import math
import re
import statistics
from collections import defaultdict
from pathlib import Path

from modules.allowlists import (
    is_benign_beacon_destination,
    is_cdn_or_cloud_domain,
)
from modules.utils import human_readable_bytes, is_noise_ip, is_private_ip


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Executable / script types — fetching these over HTTP is genuinely suspicious.
HIGH_RISK_DOWNLOAD_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".iso", ".js", ".jse",
    ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".jar", ".scr", ".lnk",
}

# Document / archive types — can carry malware but are commonly benign, so they
# are flagged at MEDIUM. Content-based detection (carving + YARA + hashing)
# still inspects the actual bytes on the extraction path.
MEDIUM_RISK_DOWNLOAD_EXTENSIONS = {
    ".zip", ".pdf", ".docm", ".xlsm", ".pptm", ".rar", ".7z",
}

HIGH_RISK_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-ms-installer",
}

MEDIUM_RISK_CONTENT_TYPES = {
    "application/zip",
    "application/pdf",
}

CREDENTIAL_PATTERNS = [
    ("password", re.compile(r"(?i)\bpassword\s*[:=]\s*[^\s&;]+"), 90),
    ("passwd", re.compile(r"(?i)\bpasswd\s*[:=]\s*[^\s&;]+"), 90),
    ("pwd", re.compile(r"(?i)\bpwd\s*[:=]\s*[^\s&;]+"), 80),
    ("username", re.compile(r"(?i)\busername\s*[:=]\s*[^\s&;]+"), 50),
    ("token", re.compile(r"(?i)\b(access_?token|token)\s*[:=]\s*[^\s&;]+"), 85),
    ("api_key", re.compile(r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*[^\s&;]+"), 85),
    ("secret", re.compile(r"(?i)\bsecret\s*[:=]\s*[^\s&;]+"), 85),
    ("bearer", re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-+/=]+"), 95),
    ("basic_auth", re.compile(r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/=]+"), 90),
    ("session_cookie", re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*.*?(session|auth|token)"), 75),
]

SUSPICIOUS_SNI_SUFFIXES = {
    ".zip", ".top", ".xyz", ".icu", ".monster", ".click",
    ".link", ".work", ".shop", ".cam",
}

# Tool and scripted user-agent substrings (lowercase match)
SUSPICIOUS_UA_STRINGS = [
    "python-requests", "python-urllib", "python/",
    "go-http-client", "go http",
    "curl/", "wget/",
    "libwww-perl", "lwp-trivial",
    "nikto", "sqlmap", "nmap", "masscan", "zgrab", "zmap",
    "nessus", "openvas", "acunetix", "burpsuite",
    "metasploit", "msfconsole",
    "powershell", "invoke-webrequest", "invoke-restmethod",
    "certutil", "bitsadmin", "wfetch",
    "java/", "okhttp/", "apache-httpclient",
    "scrapy", "mechanize",
]

# Known malware-associated user-agent patterns (lowercase full-string match)
KNOWN_MALWARE_UA_STRINGS = [
    "mozilla/5.0 (compatible; msie 9.0; windows nt 6.1; trident/5.0)",  # Emotet
    "mozilla/4.0 (compatible; msie 7.0; windows nt 5.1)",               # various RATs
    "mozilla/5.0 (windows nt 6.1) applewebkit/537.36",                  # Trickbot variant
]

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

MITRE_MAP = {
    "LARGE_PRIVATE_TO_EXTERNAL_TRANSFER": ("T1041",    "Exfiltration",          "Exfiltration Over C2 Channel"),
    "FILE_NAME_INDICATOR_OBSERVED":       ("T1105",    "Command and Control",   "Ingress Tool Transfer"),
    "HTTP_BODY_PRESENT":                  ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "TLS_SNI_OBSERVED":                   ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "BEACONING_CANDIDATE":                ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "CREDENTIAL_INDICATOR":               ("T1552",    "Credential Access",     "Unsecured Credentials"),
    "SUSPICIOUS_DOWNLOAD":                ("T1105",    "Command and Control",   "Ingress Tool Transfer"),
    "ENTROPY_BASED_EXFIL_CANDIDATE":      ("T1048.003","Exfiltration",          "Exfiltration Over Unencrypted Non-C2 Protocol"),
    "CREDENTIAL_POST_RECONSTRUCTED":      ("T1056.003","Collection",            "Input Capture: Web Portal Capture"),
    "TLS_SNI_ANOMALY":                    ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "DNS_TUNNELING_CANDIDATE":            ("T1071.004","Command and Control",   "Application Layer Protocol: DNS"),
    "SUSPICIOUS_USER_AGENT":              ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "PROTOCOL_ANOMALY":                   ("T1571",    "Command and Control",   "Non-Standard Port"),
    "LATERAL_MOVEMENT_CANDIDATE":         ("T1021.002","Lateral Movement",      "Remote Services: SMB/Windows Admin Shares"),
    "INTERNAL_SCAN_CANDIDATE":            ("T1046",    "Discovery",             "Network Service Discovery"),
    "MALICIOUS_JA3":                      ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "MALICIOUS_JA4":                      ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "MALICIOUS_JARM":                     ("T1071.001","Command and Control",   "Application Layer Protocol: Web Protocols"),
    "ICMP_TUNNELING_CANDIDATE":           ("T1095",    "Command and Control",   "Non-Application Layer Protocol"),
    "ARP_SPOOFING_CANDIDATE":             ("T1557.002","Credential Access",     "Adversary-in-the-Middle: ARP Cache Poisoning"),
    "YARA_MATCH":                         ("T1105",    "Command and Control",   "Ingress Tool Transfer"),
    "KERBEROS_ANOMALY":                   ("T1558",    "Credential Access",     "Steal or Forge Kerberos Tickets"),
    "EMAIL_ACTIVITY":                     ("T1048",    "Exfiltration",          "Exfiltration Over Alternative Protocol"),
    "HTTP_RESPONSE_ANOMALY":              ("T1105",    "Command and Control",   "Ingress Tool Transfer"),
    "CLEARTEXT_CREDENTIAL":               ("T1552",    "Credential Access",     "Unsecured Credentials"),
    "NTLM_EXTERNAL_AUTH":                 ("T1187",    "Credential Access",     "Forced Authentication"),
    "LDAP_CLEARTEXT_BIND":                ("T1552",    "Credential Access",     "Unsecured Credentials"),
    "LDAP_ENUMERATION":                   ("T1087",    "Discovery",             "Account Discovery"),
    "DCERPC_DCSYNC":                      ("T1003.006","Credential Access",     "OS Credential Dumping: DCSync"),
    "DCERPC_FORCED_AUTH":                 ("T1187",    "Credential Access",     "Forced Authentication"),
    "DCERPC_SCHEDULED_TASK":              ("T1053.005","Execution",             "Scheduled Task/Job: Scheduled Task"),
    "KERBEROASTING_CANDIDATE":            ("T1558.003","Credential Access",     "Steal or Forge Kerberos Tickets: Kerberoasting"),
    "ASREP_ROASTING_CANDIDATE":           ("T1558.004","Credential Access",     "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
}

ALERT_SEVERITY_MAP = {
    "CREDENTIAL_POST_RECONSTRUCTED":      "CRITICAL",
    "MALICIOUS_JA3":                      "CRITICAL",
    "MALICIOUS_JA4":                      "CRITICAL",
    "MALICIOUS_JARM":                     "CRITICAL",
    "ARP_SPOOFING_CANDIDATE":             "HIGH",
    "ICMP_TUNNELING_CANDIDATE":           "MEDIUM",
    "YARA_MATCH":                         "HIGH",
    "DNS_TUNNELING_CANDIDATE":            "HIGH",
    "CREDENTIAL_INDICATOR":               "HIGH",
    "ENTROPY_BASED_EXFIL_CANDIDATE":      "HIGH",
    "LARGE_PRIVATE_TO_EXTERNAL_TRANSFER": "HIGH",
    "SUSPICIOUS_DOWNLOAD":                "HIGH",
    "LATERAL_MOVEMENT_CANDIDATE":         "HIGH",
    "INTERNAL_SCAN_CANDIDATE":            "HIGH",
    "BEACONING_CANDIDATE":                "HIGH",
    "KERBEROS_ANOMALY":                   "HIGH",
    "TLS_SNI_ANOMALY":                    "MEDIUM",
    "SUSPICIOUS_USER_AGENT":              "MEDIUM",
    "PROTOCOL_ANOMALY":                   "MEDIUM",
    "HTTP_BODY_PRESENT":                  "MEDIUM",
    "EMAIL_ACTIVITY":                     "LOW",
    "HTTP_RESPONSE_ANOMALY":              "MEDIUM",
    "CLEARTEXT_CREDENTIAL":               "HIGH",
    "NTLM_EXTERNAL_AUTH":                 "MEDIUM",
    "LDAP_CLEARTEXT_BIND":                "HIGH",
    "LDAP_ENUMERATION":                   "MEDIUM",
    "DCERPC_DCSYNC":                      "HIGH",
    "DCERPC_FORCED_AUTH":                 "MEDIUM",
    "DCERPC_SCHEDULED_TASK":              "MEDIUM",
    "KERBEROASTING_CANDIDATE":            "MEDIUM",
    "ASREP_ROASTING_CANDIDATE":           "MEDIUM",
    "FILE_NAME_INDICATOR_OBSERVED":       "LOW",
    "TLS_SNI_OBSERVED":                   "INFO",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Expert Info groups that are almost always network conditions rather than
# security-relevant events (retransmissions, checksum offload artifacts).
# Suppressed from alerts but still written to expert_info.csv.
_EXPERT_NOISE_GROUPS = {"Sequence", "Checksum"}

# Warning-severity Expert Info groups worth surfacing as low alerts.
_EXPERT_WARN_GROUPS = {"Malformed", "Security", "Decryption", "Protocol", "Reassemble"}


def _enrich_alert(alert: dict) -> dict:
    alert_type = alert.get("alert_type", "")
    # Preserve caller-supplied severity (e.g., from YARA rule metadata)
    if "severity" not in alert:
        alert["severity"] = ALERT_SEVERITY_MAP.get(alert_type, "INFO")
    technique_id, tactic, technique_name = MITRE_MAP.get(alert_type, ("", "", ""))
    alert["mitre_technique_id"] = technique_id
    alert["mitre_tactic"] = tactic
    alert["mitre_technique_name"] = technique_name
    return alert


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def classify_credential_severity(score: int) -> str:
    if score >= 90:
        return "HIGH"
    if score >= 70:
        return "MEDIUM"
    return "LOW"


def build_credential_score(label: str, context: str) -> tuple[int, str]:
    base_score = 50
    for pattern_label, _, score in CREDENTIAL_PATTERNS:
        if pattern_label == label:
            base_score = score
            break

    lowered = context.lower()
    if "post " in lowered or "http/1." in lowered:
        base_score += 5
    if "authorization:" in lowered:
        base_score += 5
    if "set-cookie:" in lowered or "cookie:" in lowered:
        base_score += 5

    base_score = min(base_score, 100)
    return base_score, classify_credential_severity(base_score)


# ---------------------------------------------------------------------------
# Existing detection functions
# ---------------------------------------------------------------------------

def find_credential_indicators(http_body_previews: list[dict], extracted_payloads: list[dict]) -> list[dict]:
    findings = []

    for row in http_body_previews:
        text = row.get("body_preview", "") or ""
        if not text:
            continue

        context = f"{row.get('http_method', '')} {row.get('host', '')} {row.get('uri', '')} {text}"
        for label, pattern, _ in CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                score, severity = build_credential_score(label, context)
                findings.append({
                    "source_type": "http_body_preview",
                    "tcp_stream": row.get("tcp_stream", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "host": row.get("host", ""),
                    "uri": row.get("uri", ""),
                    "indicator_type": label,
                    "severity": severity,
                    "score": score,
                    "match_excerpt": match.group(0)[:200],
                })

    for row in extracted_payloads:
        if not row.get("is_text"):
            continue

        output_file = row.get("output_file", "")
        try:
            text = Path(output_file).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        context = f"{row.get('filename', '')} {text[:1000]}"
        for label, pattern, _ in CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                score, severity = build_credential_score(label, context)
                findings.append({
                    "source_type": "extracted_payload",
                    "tcp_stream": row.get("tcp_stream", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "host": "",
                    "uri": row.get("filename", ""),
                    "indicator_type": label,
                    "severity": severity,
                    "score": score,
                    "match_excerpt": match.group(0)[:200],
                })

    return findings


def build_suspicious_downloads(http_rows: list[dict], extracted_payloads: list[dict]) -> list[dict]:
    downloads = []

    for row in http_rows:
        method = (row.get("http.request.method", "") or "").upper()
        uri = row.get("http.request.uri", "") or ""
        host = row.get("http.host", "") or ""
        content_type = (row.get("http.content_type", "") or "").lower()

        ext = Path(uri.split("?", 1)[0]).suffix.lower()
        reasons = []
        severity = None

        if method == "GET" and ext in HIGH_RISK_DOWNLOAD_EXTENSIONS:
            reasons.append(f"GET to high-risk file extension {ext}")
            severity = "HIGH"
        elif method == "GET" and ext in MEDIUM_RISK_DOWNLOAD_EXTENSIONS:
            reasons.append(f"GET to file extension {ext}")
            severity = "MEDIUM"

        if content_type in HIGH_RISK_CONTENT_TYPES:
            reasons.append(f"High-risk content-type {content_type}")
            severity = "HIGH"
        elif content_type in MEDIUM_RISK_CONTENT_TYPES:
            reasons.append(f"Suspicious content-type {content_type}")
            severity = severity or "MEDIUM"

        if reasons:
            downloads.append({
                "source": "http_row",
                "tcp_stream": row.get("tcp.stream", ""),
                "src_ip": row.get("ip.src", ""),
                "dst_ip": row.get("ip.dst", ""),
                "host": host,
                "uri": uri,
                "content_type": content_type,
                "severity": severity,
                "reason": " | ".join(reasons),
            })

    for row in extracted_payloads:
        detected = row.get("detected_file_type", "")
        if detected == "PE_EXE":
            severity = "HIGH"
        elif detected in {"PDF", "ZIP", "RAR", "SEVEN_Z"}:
            severity = "MEDIUM"
        else:
            continue
        downloads.append({
            "source": "extracted_payload",
            "tcp_stream": row.get("tcp_stream", ""),
            "src_ip": row.get("src_ip", ""),
            "dst_ip": row.get("dst_ip", ""),
            "host": "",
            "uri": row.get("filename", ""),
            "content_type": row.get("content_type", ""),
            "severity": severity,
            "reason": f"Extracted payload detected as {detected}",
        })

    return downloads


def detect_beaconing(flow_times: dict, flow_bytes: dict) -> list[dict]:
    findings = []

    for flow, timestamps in flow_times.items():
        if len(timestamps) < 5:
            continue

        sorted_times = sorted(timestamps)
        deltas = [
            round(sorted_times[i] - sorted_times[i - 1], 3)
            for i in range(1, len(sorted_times))
            if sorted_times[i] > sorted_times[i - 1]
        ]

        if len(deltas) < 4:
            continue

        mean_delta = statistics.mean(deltas)
        stdev_delta = statistics.pstdev(deltas)

        if mean_delta <= 1:
            continue

        jitter_pct = round((stdev_delta / mean_delta) * 100, 2) if mean_delta else 0.0
        if jitter_pct <= 20:
            src, dst, sport, dport, proto = flow
            findings.append({
                "src_ip": src,
                "dst_ip": dst,
                "sport": sport,
                "dport": dport,
                "protocol": proto,
                "packet_count": len(timestamps),
                "avg_interval_sec": round(mean_delta, 3),
                "stdev_interval_sec": round(stdev_delta, 3),
                "jitter_pct": jitter_pct,
                "bytes": flow_bytes.get(flow, 0),
                "bytes_human": human_readable_bytes(flow_bytes.get(flow, 0)),
                "benign_infrastructure": is_benign_beacon_destination(dst, dport),
            })

    findings.sort(key=lambda x: (x["jitter_pct"], -x["packet_count"]))
    return findings


def detect_entropy_exfil_candidates(extracted_payloads: list[dict]) -> list[dict]:
    findings = []

    for row in extracted_payloads:
        src_ip = row.get("src_ip", "")
        dst_ip = row.get("dst_ip", "")
        # Source must be internal and destination a real external host.
        if not is_private_ip(src_ip) or is_noise_ip(dst_ip):
            continue

        entropy = float(row.get("entropy", 0) or 0)
        size_bytes = int(row.get("size_bytes", 0) or 0)

        if size_bytes >= 50000 and entropy >= 7.2:
            findings.append({
                "tcp_stream": row.get("tcp_stream", ""),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "filename": row.get("filename", ""),
                "size_bytes": size_bytes,
                "size_human": row.get("size_human", ""),
                "entropy": entropy,
                "reason": "Large, high-entropy payload transferred from private to external address",
            })

    return findings


def reconstruct_credential_posts(http_body_previews: list[dict]) -> list[dict]:
    posts = []

    for row in http_body_previews:
        method = (row.get("http_method", "") or "").upper()
        if method != "POST":
            continue

        body = row.get("body_preview", "") or ""
        matches = []
        for label, pattern, _ in CREDENTIAL_PATTERNS:
            match = pattern.search(body)
            if match:
                matches.append(f"{label}={match.group(0)[:100]}")

        if matches:
            posts.append({
                "tcp_stream": row.get("tcp_stream", ""),
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "host": row.get("host", ""),
                "uri": row.get("uri", ""),
                "http_method": method,
                "content_type": row.get("content_type", ""),
                "credential_hits": " | ".join(matches),
                "body_preview": body[:500],
            })

    return posts


def detect_tls_sni_anomalies(tls_summary: list[dict]) -> list[dict]:
    findings = []

    for row in tls_summary:
        sni = (row.get("sni", "") or "").strip().lower()
        if not sni:
            continue

        reasons = []
        # Morphology heuristics (long/hex-like/digit-heavy) can't distinguish a
        # malicious CDN host from a benign one — both look the same — so they
        # only add noise on CDN/cloud domains and are skipped there. The
        # structural checks below (IP literal, suspicious TLD) still apply, and
        # CDN traffic remains subject to JA3/JA4, beaconing, suspicious-download
        # and payload detection elsewhere.
        if not is_cdn_or_cloud_domain(sni):
            if len(sni) > 55:
                reasons.append("Long SNI")
            if re.search(r"[a-f0-9]{20,}", sni):
                reasons.append("Hex-like SNI pattern")
            if sum(ch.isdigit() for ch in sni) > 10:
                reasons.append("Digit-heavy SNI")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", sni):
            reasons.append("SNI is an IP literal")
        if any(sni.endswith(suffix) for suffix in SUSPICIOUS_SNI_SUFFIXES):
            reasons.append("Suspicious SNI suffix")

        if reasons:
            findings.append({
                "tcp_stream": row.get("tcp_stream", ""),
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "sni": sni,
                "cipher_suite": row.get("cipher_suite", ""),
                "reason": " | ".join(reasons),
            })

    return findings


# ---------------------------------------------------------------------------
# New detection functions
# ---------------------------------------------------------------------------

def _label_shannon_entropy(label: str) -> float:
    if not label:
        return 0.0
    freq = {}
    for ch in label:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_dns_tunneling(dns_rows: list[dict]) -> list[dict]:
    """Detect potential DNS tunneling via entropy, FQDN length, query volume, and record type."""
    findings = []
    domain_query_map: dict[str, list[dict]] = defaultdict(list)
    seen_keys: set[tuple] = set()

    for row in dns_rows:
        qname = (row.get("dns.qry.name", "") or "").strip().lower().rstrip(".")
        qtype = (row.get("dns.qry.type", "") or "").strip()
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        timestamp = row.get("frame.time", "")

        if not qname:
            continue

        # Reverse-DNS (PTR) lookups are normal operational traffic, never
        # tunneling — exclude them from both the per-query and volume checks.
        if qname.endswith(".in-addr.arpa") or qname.endswith(".ip6.arpa"):
            continue

        parts = qname.split(".")
        registered = ".".join(parts[-2:]) if len(parts) >= 2 else qname
        domain_query_map[registered].append({
            "qname": qname,
            "qtype": qtype,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "frame_time": timestamp,
        })

        reasons = []

        # High-entropy subdomain labels
        if len(parts) >= 3:
            for label in parts[:-2]:
                if len(label) >= 20:
                    ent = _label_shannon_entropy(label)
                    if ent >= 3.5:
                        reasons.append(
                            f"High-entropy subdomain '{label[:30]}' (entropy={ent:.2f})"
                        )

        # Unusually long FQDN
        if len(qname) > 52:
            reasons.append(f"Long FQDN ({len(qname)} chars)")

        # NULL records are rare enough to flag on their own. TXT lookups are
        # ubiquitous (SPF/DKIM/DMARC/verification), so they only count as a
        # corroborating signal when an entropy/length indicator is also present.
        if qtype == "10":
            reasons.append(
                "NULL record query — uncommon in normal traffic, used by tunneling tools"
            )
        elif qtype == "16" and reasons:
            reasons.append(
                "TXT record query alongside high-entropy/long-name indicators"
            )

        if reasons:
            key = (src_ip, qname, ",".join(reasons)[:60])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "qname": qname,
                    "qtype": qtype,
                    "reason": " | ".join(reasons),
                })

    # High query volume to a single registered domain (> 50 queries)
    for registered_domain, entries in domain_query_map.items():
        if len(entries) > 50:
            # CDN/cloud/first-party parents are queried at high volume normally.
            if is_cdn_or_cloud_domain(registered_domain):
                continue
            src_ips = sorted({e["src_ip"] for e in entries})
            key = ("volume", registered_domain)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "timestamp": entries[0]["frame_time"],
                    "src_ip": ", ".join(src_ips[:5]),
                    "dst_ip": entries[0]["dst_ip"],
                    "qname": registered_domain,
                    "qtype": "multiple",
                    "reason": (
                        f"High query volume: {len(entries)} queries to '{registered_domain}' "
                        f"from {len(src_ips)} source(s)"
                    ),
                })

    return findings


def detect_suspicious_user_agents(http_rows: list[dict]) -> list[dict]:
    """Detect empty, tool-based, or malware-associated HTTP User-Agent values."""
    findings = []
    ua_per_src: dict[str, set] = defaultdict(set)
    seen: set[tuple] = set()

    for row in http_rows:
        ua = (row.get("http.user_agent", "") or "").strip()
        src_ip = row.get("ip.src", "")
        if ua and src_ip:
            ua_per_src[src_ip].add(ua)

    for row in http_rows:
        ua = (row.get("http.user_agent", "") or "").strip()
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")
        host = row.get("http.host", "")

        reasons = []

        if not ua:
            reasons.append("Empty or missing User-Agent")
        else:
            ua_lower = ua.lower()
            for sus in SUSPICIOUS_UA_STRINGS:
                if sus in ua_lower:
                    reasons.append(f"Tool/scripted User-Agent contains '{sus}'")
                    break
            for mal in KNOWN_MALWARE_UA_STRINGS:
                if mal in ua_lower:
                    reasons.append("Known malware-associated User-Agent pattern")
                    break

        if reasons:
            key = (src_ip, ua[:80])
            if key not in seen:
                seen.add(key)
                findings.append({
                    "timestamp": row.get("frame.time", ""),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "tcp_stream": row.get("tcp.stream", ""),
                    "host": host,
                    "user_agent": ua[:300],
                    "reason": " | ".join(reasons),
                })

    # Flag single source IPs using an unusually large number of distinct UAs.
    # A normal corporate workstation easily shows 10-30 (per-app, per-version),
    # so the threshold is set high to catch only genuine outliers; the tool/
    # malware substring matching above is the stronger signal.
    for src_ip, uas in ua_per_src.items():
        if len(uas) >= 15:
            key = (src_ip, "multi_ua")
            if key not in seen:
                seen.add(key)
                findings.append({
                    "timestamp": "",
                    "src_ip": src_ip,
                    "dst_ip": "",
                    "tcp_stream": "",
                    "host": "",
                    "user_agent": "; ".join(list(uas)[:4]),
                    "reason": f"Source IP using {len(uas)} distinct User-Agent strings",
                })

    return findings


def detect_lateral_movement(flow_bytes: dict, flow_times: dict) -> list[dict]:
    """Detect internal SMB spread and TCP port-scan patterns consistent with lateral movement."""
    findings = []

    smb_targets: dict[str, set] = defaultdict(set)
    internal_tcp_targets: dict[str, set] = defaultdict(set)

    for flow_key, byte_count in flow_bytes.items():
        src, dst, sport, dport, proto = flow_key

        if not (is_private_ip(src) and is_private_ip(dst)):
            continue

        if proto != "TCP":
            continue

        if dport == 445:
            smb_targets[src].add(dst)

        # Small flows to many targets = likely scanning
        if byte_count < 500:
            internal_tcp_targets[src].add((dst, dport))

    # SMB spread: one host → 3+ internal targets on port 445
    for src_ip, dst_ips in smb_targets.items():
        if len(dst_ips) >= 3:
            findings.append({
                "src_ip": src_ip,
                "dst_ips": ", ".join(sorted(dst_ips)),
                "dst_count": len(dst_ips),
                "protocol": "SMB",
                "dport": 445,
                "indicator": "LATERAL_MOVEMENT_CANDIDATE",
                "reason": (
                    f"Host connected to {len(dst_ips)} internal targets via SMB (port 445) "
                    "— possible lateral movement or ransomware propagation"
                ),
            })

    # Internal port scan: many IPs or many ports from one host
    for src_ip, targets in internal_tcp_targets.items():
        unique_dst_ips = {t[0] for t in targets}
        unique_ports = {t[1] for t in targets}

        if len(unique_dst_ips) >= 10 or (len(unique_ports) >= 10 and len(unique_dst_ips) >= 3):
            findings.append({
                "src_ip": src_ip,
                "dst_ips": ", ".join(sorted(unique_dst_ips)[:10]),
                "dst_count": len(unique_dst_ips),
                "protocol": "TCP",
                "dport": f"{len(unique_ports)} unique ports",
                "indicator": "INTERNAL_SCAN_CANDIDATE",
                "reason": (
                    f"Small TCP connections to {len(unique_dst_ips)} internal IPs "
                    f"across {len(unique_ports)} ports — possible network reconnaissance"
                ),
            })

    findings.sort(key=lambda x: x["dst_count"], reverse=True)
    return findings


# ---------------------------------------------------------------------------
# HTTP response anomaly detection
# ---------------------------------------------------------------------------

def detect_http_response_anomalies(http_response_rows: list[dict]) -> list[dict]:
    """Flag scanning indicators and confirmed-successful suspicious transfers in HTTP responses."""
    findings = []
    not_found_per_src: dict[str, int] = defaultdict(int)

    for row in http_response_rows:
        code = (row.get("http.response.code", "") or "").strip()
        content_type = (row.get("http.content_type", "") or "").lower()
        src_ip = row.get("ip.src", "")

        if code == "404":
            not_found_per_src[src_ip] += 1

    # Many 404s from a single source = path enumeration / scanning
    for src_ip, count in not_found_per_src.items():
        if count >= 10:
            findings.append({
                "src_ip": src_ip,
                "dst_ip": "",
                "tcp_stream": "",
                "response_code": "404",
                "content_type": "",
                "reason": f"{count} HTTP 404 responses involving {src_ip} — possible path enumeration or scanning",
            })

    # 200 OK for suspicious content types = confirmed delivery
    suspicious_delivered = {
        "application/x-dosexec", "application/x-msdownload",
        "application/x-ms-installer", "application/vnd.ms-office",
    }
    seen_streams: set[str] = set()
    for row in http_response_rows:
        code = (row.get("http.response.code", "") or "").strip()
        content_type = (row.get("http.content_type", "") or "").lower().split(";")[0].strip()
        tcp_stream = (row.get("tcp.stream", "") or "").strip()

        if code == "200" and content_type in suspicious_delivered:
            if tcp_stream not in seen_streams:
                seen_streams.add(tcp_stream)
                findings.append({
                    "src_ip": row.get("ip.src", ""),
                    "dst_ip": row.get("ip.dst", ""),
                    "tcp_stream": tcp_stream,
                    "response_code": code,
                    "content_type": content_type,
                    "reason": f"HTTP 200 OK delivering suspicious content-type '{content_type}' — transfer confirmed",
                })

    return findings


# ---------------------------------------------------------------------------
# Alert aggregation
# ---------------------------------------------------------------------------

def build_alerts(
    flow_bytes,
    file_indicators,
    http_body_previews=None,
    tls_summary=None,
    beaconing_candidates=None,
    credential_findings=None,
    suspicious_downloads=None,
    entropy_exfil_candidates=None,
    credential_posts=None,
    tls_sni_anomalies=None,
    dns_tunneling_candidates=None,
    suspicious_user_agents=None,
    lateral_movement_candidates=None,
    protocol_anomalies=None,
    malicious_ja3_findings=None,
    malicious_ja4_findings=None,
    icmp_candidates=None,
    arp_anomalies=None,
    jarm_results=None,
    yara_hits=None,
    kerberos_rows=None,
    http_response_anomalies=None,
    expert_info_items=None,
    credential_tap_items=None,
    ntlm_external_findings=None,
    ldap_findings=None,
    dcerpc_findings=None,
    kerberos_attack_findings=None,
):
    alerts = []
    http_body_previews = http_body_previews or []
    tls_summary = tls_summary or []
    beaconing_candidates = beaconing_candidates or []
    credential_findings = credential_findings or []
    suspicious_downloads = suspicious_downloads or []
    entropy_exfil_candidates = entropy_exfil_candidates or []
    credential_posts = credential_posts or []
    tls_sni_anomalies = tls_sni_anomalies or []
    dns_tunneling_candidates = dns_tunneling_candidates or []
    suspicious_user_agents = suspicious_user_agents or []
    lateral_movement_candidates = lateral_movement_candidates or []
    protocol_anomalies = protocol_anomalies or []
    malicious_ja3_findings = malicious_ja3_findings or []
    malicious_ja4_findings = malicious_ja4_findings or []
    icmp_candidates = icmp_candidates or []
    arp_anomalies = arp_anomalies or []
    jarm_results = jarm_results or []
    yara_hits = yara_hits or []
    kerberos_rows = kerberos_rows or []
    http_response_anomalies = http_response_anomalies or []
    expert_info_items = expert_info_items or []
    credential_tap_items = credential_tap_items or []
    ntlm_external_findings = ntlm_external_findings or []
    ldap_findings = ldap_findings or []
    dcerpc_findings = dcerpc_findings or []
    kerberos_attack_findings = kerberos_attack_findings or []

    for flow, byte_count in flow_bytes.items():
        src, dst, sport, dport, proto = flow
        if is_private_ip(src) and not is_noise_ip(dst) and byte_count >= 1_000_000:
            alerts.append(_enrich_alert({
                "alert_type": "LARGE_PRIVATE_TO_EXTERNAL_TRANSFER",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "sport": sport,
                "dport": dport,
                "bytes": byte_count,
                "reason": "High-volume outbound flow from private IP to external IP",
            }))

    for item in file_indicators:
        alerts.append(_enrich_alert({
            "alert_type": "FILE_NAME_INDICATOR_OBSERVED",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": item.get("protocol"),
            "tcp_stream": item.get("tcp_stream"),
            "filename": item.get("filename"),
            "reason": "Potential file transfer or filename reference observed",
        }))

    for item in http_body_previews:
        method = (item.get("http_method") or "").upper()
        if method in {"POST", "PUT", "PATCH"} and item.get("body_preview"):
            alerts.append(_enrich_alert({
                "alert_type": "HTTP_BODY_PRESENT",
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "protocol": "HTTP",
                "tcp_stream": item.get("tcp_stream"),
                "host": item.get("host"),
                "uri": item.get("uri"),
                "reason": "HTTP request body reconstructed or previewed",
            }))

    for item in tls_summary:
        if item.get("sni"):
            alerts.append(_enrich_alert({
                "alert_type": "TLS_SNI_OBSERVED",
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "protocol": "TLS",
                "tcp_stream": item.get("tcp_stream"),
                "host": item.get("sni"),
                "reason": "TLS metadata observed; content remains encrypted without TLS secrets",
            }))

    for item in beaconing_candidates:
        benign = item.get("benign_infrastructure")
        reason = f"Regular timing detected with low jitter ({item.get('jitter_pct')}%)"
        beacon_alert = {
            "alert_type": "BEACONING_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": item.get("protocol"),
            "sport": item.get("sport"),
            "dport": item.get("dport"),
            "reason": reason + (
                " — benign infrastructure destination (NTP/public resolver)" if benign else ""
            ),
        }
        if benign:
            beacon_alert["severity"] = "INFO"
        alerts.append(_enrich_alert(beacon_alert))

    for item in credential_findings:
        alerts.append(_enrich_alert({
            "alert_type": "CREDENTIAL_INDICATOR",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": (
                f"{item.get('severity')} severity credential indicator detected: "
                f"{item.get('indicator_type')}"
            ),
        }))

    for item in suspicious_downloads:
        download_alert = {
            "alert_type": "SUSPICIOUS_DOWNLOAD",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }
        if item.get("severity"):
            download_alert["severity"] = item["severity"]
        alerts.append(_enrich_alert(download_alert))

    for item in entropy_exfil_candidates:
        alerts.append(_enrich_alert({
            "alert_type": "ENTROPY_BASED_EXFIL_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in credential_posts:
        alerts.append(_enrich_alert({
            "alert_type": "CREDENTIAL_POST_RECONSTRUCTED",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": "POST body contains likely credential or token material",
        }))

    for item in tls_sni_anomalies:
        alerts.append(_enrich_alert({
            "alert_type": "TLS_SNI_ANOMALY",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "TLS",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in dns_tunneling_candidates:
        alerts.append(_enrich_alert({
            "alert_type": "DNS_TUNNELING_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "DNS",
            "tcp_stream": "",
            "host": item.get("qname"),
            "reason": item.get("reason"),
        }))

    for item in suspicious_user_agents:
        alerts.append(_enrich_alert({
            "alert_type": "SUSPICIOUS_USER_AGENT",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in lateral_movement_candidates:
        indicator = item.get("indicator", "LATERAL_MOVEMENT_CANDIDATE")
        alerts.append(_enrich_alert({
            "alert_type": indicator,
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ips", ""),
            "protocol": item.get("protocol"),
            "dport": item.get("dport"),
            "reason": item.get("reason"),
        }))

    for item in protocol_anomalies:
        alerts.append(_enrich_alert({
            "alert_type": "PROTOCOL_ANOMALY",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": item.get("protocol"),
            "tcp_stream": item.get("tcp_stream"),
            "dport": item.get("dport"),
            "reason": item.get("reason"),
        }))

    for item in malicious_ja3_findings:
        alerts.append(_enrich_alert({
            "alert_type": "MALICIOUS_JA3",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "TLS",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in malicious_ja4_findings:
        alerts.append(_enrich_alert({
            "alert_type": "MALICIOUS_JA4",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "TLS",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in kerberos_rows:
        error_code = (item.get("kerberos.error_code", "") or "").strip()
        if error_code:
            alerts.append(_enrich_alert({
                "alert_type": "KERBEROS_ANOMALY",
                "src_ip": item.get("ip.src", ""),
                "dst_ip": item.get("ip.dst", ""),
                "protocol": "Kerberos",
                "tcp_stream": item.get("tcp.stream", ""),
                "reason": f"Kerberos error {error_code} for user {item.get('kerberos.CNameString', '')}",
            }))

    for item in http_response_anomalies:
        alerts.append(_enrich_alert({
            "alert_type": "HTTP_RESPONSE_ANOMALY",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in icmp_candidates:
        alerts.append(_enrich_alert({
            "alert_type": "ICMP_TUNNELING_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "ICMP",
            "reason": item.get("reason"),
        }))

    for item in arp_anomalies:
        alerts.append(_enrich_alert({
            "alert_type": "ARP_SPOOFING_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "ARP",
            "severity": item.get("severity"),
            "reason": item.get("reason"),
        }))

    for item in jarm_results:
        if item.get("malware_family"):
            alerts.append(_enrich_alert({
                "alert_type": "MALICIOUS_JARM",
                "src_ip": "",
                "dst_ip": item.get("dst_ip"),
                "protocol": "TLS",
                "reason": (
                    f"JARM {item.get('jarm')} matches {item.get('malware_family')} "
                    f"({item.get('intel_source')})"
                ),
            }))

    for item in yara_hits:
        alerts.append(_enrich_alert({
            "alert_type": "YARA_MATCH",
            "src_ip": "",
            "dst_ip": "",
            "protocol": "",
            "severity": item.get("severity"),
            "reason": (
                f"YARA rule '{item.get('rule_name')}' matched "
                f"{item.get('file_path', '')}"
            ),
        }))

    for item in ntlm_external_findings:
        alerts.append(_enrich_alert({
            "alert_type": "NTLM_EXTERNAL_AUTH",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "NTLM",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in ldap_findings:
        alerts.append(_enrich_alert({
            "alert_type": item.get("alert_type", "LDAP_CLEARTEXT_BIND"),
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "LDAP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in dcerpc_findings:
        alerts.append(_enrich_alert({
            "alert_type": item.get("alert_type", "DCERPC_DCSYNC"),
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "DCERPC",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    for item in kerberos_attack_findings:
        alerts.append(_enrich_alert({
            "alert_type": item.get("alert_type", "KERBEROASTING_CANDIDATE"),
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "Kerberos",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        }))

    # Cleartext credentials recovered by TShark's credentials tap
    # (FTP, HTTP basic, IMAP, POP, SMTP).
    for item in credential_tap_items:
        protocol = (item.get("protocol", "") or "").strip()
        username = (item.get("username", "") or "").strip()
        alerts.append(_enrich_alert({
            "alert_type": "CLEARTEXT_CREDENTIAL",
            "src_ip": "",
            "dst_ip": "",
            "protocol": protocol,
            "reason": (
                f"Cleartext credential exposed via {protocol}"
                + (f" (username '{username}')" if username else "")
                + f" — packet {item.get('packet', '')}"
            ),
        }))

    # Expert Info: dissector-recognized anomalies. Suppress pure network-noise
    # groups; surface Errors (MEDIUM) and high-interest Warnings (LOW) only.
    for item in expert_info_items:
        group = (item.get("group", "") or "").strip()
        section = (item.get("severity", "") or "").strip()
        if group in _EXPERT_NOISE_GROUPS:
            continue
        if section == "Error":
            severity = "MEDIUM"
        elif section == "Warning" and group in _EXPERT_WARN_GROUPS:
            severity = "LOW"
        else:
            continue
        alerts.append(_enrich_alert({
            "alert_type": "EXPERT_INFO_ANOMALY",
            "src_ip": "",
            "dst_ip": "",
            "protocol": item.get("protocol", ""),
            "severity": severity,
            "reason": (
                f"{section}/{group}: {item.get('summary', '')} "
                f"(x{item.get('frequency', 0)})"
            ),
        }))

    alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a.get("severity", "INFO"), 4))
    return alerts
