import re
import statistics
from pathlib import Path

from modules.utils import human_readable_bytes, is_private_ip


SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".zip", ".iso", ".js", ".jse",
    ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".pdf",
    ".docm", ".xlsm", ".pptm", ".jar", ".scr", ".lnk",
}

SUSPICIOUS_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-dosexec",
    "application/x-msdownload",
    "application/zip",
    "application/pdf",
    "application/x-ms-installer",
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

        if method == "GET" and ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS:
            reasons.append(f"GET to suspicious file extension {ext}")
        if content_type in SUSPICIOUS_CONTENT_TYPES:
            reasons.append(f"Suspicious content-type {content_type}")

        if reasons:
            downloads.append({
                "source": "http_row",
                "tcp_stream": row.get("tcp.stream", ""),
                "src_ip": row.get("ip.src", ""),
                "dst_ip": row.get("ip.dst", ""),
                "host": host,
                "uri": uri,
                "content_type": content_type,
                "reason": " | ".join(reasons),
            })

    for row in extracted_payloads:
        detected = row.get("detected_file_type", "")
        if detected in {"PDF", "ZIP", "PE_EXE", "RAR", "SEVEN_Z"}:
            downloads.append({
                "source": "extracted_payload",
                "tcp_stream": row.get("tcp_stream", ""),
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "host": "",
                "uri": row.get("filename", ""),
                "content_type": row.get("content_type", ""),
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
            })

    findings.sort(key=lambda x: (x["jitter_pct"], -x["packet_count"]))
    return findings


def detect_entropy_exfil_candidates(extracted_payloads: list[dict]) -> list[dict]:
    findings = []

    for row in extracted_payloads:
        src_ip = row.get("src_ip", "")
        dst_ip = row.get("dst_ip", "")
        if not is_private_ip(src_ip) or is_private_ip(dst_ip):
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
        if len(sni) > 55:
            reasons.append("Long SNI")
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", sni):
            reasons.append("SNI is an IP literal")
        if re.search(r"[a-f0-9]{20,}", sni):
            reasons.append("Hex-like SNI pattern")
        if sum(ch.isdigit() for ch in sni) > 10:
            reasons.append("Digit-heavy SNI")
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

    for flow, byte_count in flow_bytes.items():
        src, dst, sport, dport, proto = flow
        if is_private_ip(src) and not is_private_ip(dst) and byte_count >= 1_000_000:
            alerts.append({
                "alert_type": "LARGE_PRIVATE_TO_EXTERNAL_TRANSFER",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "sport": sport,
                "dport": dport,
                "bytes": byte_count,
                "reason": "High-volume outbound flow from private IP to external IP",
            })

    for item in file_indicators:
        alerts.append({
            "alert_type": "FILE_NAME_INDICATOR_OBSERVED",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": item.get("protocol"),
            "tcp_stream": item.get("tcp_stream"),
            "filename": item.get("filename"),
            "reason": "Potential file transfer or filename reference observed",
        })

    for item in http_body_previews:
        method = (item.get("http_method") or "").upper()
        if method in {"POST", "PUT", "PATCH"} and item.get("body_preview"):
            alerts.append({
                "alert_type": "HTTP_BODY_PRESENT",
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "protocol": "HTTP",
                "tcp_stream": item.get("tcp_stream"),
                "host": item.get("host"),
                "uri": item.get("uri"),
                "reason": "HTTP request body reconstructed or previewed",
            })

    for item in tls_summary:
        if item.get("sni"):
            alerts.append({
                "alert_type": "TLS_SNI_OBSERVED",
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "protocol": "TLS",
                "tcp_stream": item.get("tcp_stream"),
                "host": item.get("sni"),
                "reason": "TLS metadata observed; content remains encrypted without TLS secrets",
            })

    for item in beaconing_candidates:
        alerts.append({
            "alert_type": "BEACONING_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": item.get("protocol"),
            "sport": item.get("sport"),
            "dport": item.get("dport"),
            "reason": f"Regular timing detected with low jitter ({item.get('jitter_pct')}%)",
        })

    for item in credential_findings:
        alerts.append({
            "alert_type": "CREDENTIAL_INDICATOR",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": f"{item.get('severity')} severity credential/token-like content detected: {item.get('indicator_type')}",
        })

    for item in suspicious_downloads:
        alerts.append({
            "alert_type": "SUSPICIOUS_DOWNLOAD",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        })

    for item in entropy_exfil_candidates:
        alerts.append({
            "alert_type": "ENTROPY_BASED_EXFIL_CANDIDATE",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        })

    for item in credential_posts:
        alerts.append({
            "alert_type": "CREDENTIAL_POST_RECONSTRUCTED",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": "POST body contains likely credential or token material",
        })

    for item in tls_sni_anomalies:
        alerts.append({
            "alert_type": "TLS_SNI_ANOMALY",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "TLS",
            "tcp_stream": item.get("tcp_stream"),
            "reason": item.get("reason"),
        })

    return alerts