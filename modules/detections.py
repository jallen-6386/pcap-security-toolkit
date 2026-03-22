import base64
import binascii
import re
import statistics
from pathlib import Path

from modules.utils import human_readable_bytes, is_private_ip


SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".exe",
    ".dll",
    ".msi",
    ".zip",
    ".iso",
    ".js",
    ".jse",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
    ".pdf",
    ".docm",
    ".xlsm",
    ".pptm",
    ".jar",
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
    ("password", re.compile(r"(?i)\bpassword\s*[:=]\s*[^\s&;]+")),
    ("passwd", re.compile(r"(?i)\bpasswd\s*[:=]\s*[^\s&;]+")),
    ("pwd", re.compile(r"(?i)\bpwd\s*[:=]\s*[^\s&;]+")),
    ("username", re.compile(r"(?i)\busername\s*[:=]\s*[^\s&;]+")),
    ("token", re.compile(r"(?i)\b(access_?token|token)\s*[:=]\s*[^\s&;]+")),
    ("api_key", re.compile(r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*[^\s&;]+")),
    ("secret", re.compile(r"(?i)\bsecret\s*[:=]\s*[^\s&;]+")),
    ("bearer", re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-+/=]+")),
    ("basic_auth", re.compile(r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/=]+")),
    ("session_cookie", re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*.*?(session|auth|token)")),
]

BASE64_CANDIDATE_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")


def looks_mostly_text(data: bytes) -> bool:
    if not data or len(data) < 20:
        return False

    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= 0.90


def detect_magic_file_type(data: bytes) -> tuple[str, str]:
    if data.startswith(b"%PDF-"):
        return "PDF", ".pdf"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP", ".zip"
    if data.startswith(b"MZ"):
        return "PE_EXE", ".exe"
    if looks_mostly_text(data):
        return "TEXT", ".txt"
    return "UNKNOWN", ".bin"


def annotate_extracted_payload_types(extracted_payloads: list[dict]) -> list[dict]:
    annotated = []

    for row in extracted_payloads:
        updated = dict(row)
        output_file = updated.get("output_file", "")
        try:
            data = Path(output_file).read_bytes()
        except Exception:
            data = b""

        detected_type, detected_ext = detect_magic_file_type(data)
        updated["detected_file_type"] = detected_type
        updated["detected_extension"] = detected_ext
        updated["size_human"] = human_readable_bytes(len(data)) if data else ""
        annotated.append(updated)

    return annotated


def find_credential_indicators(http_body_previews: list[dict], extracted_payloads: list[dict]) -> list[dict]:
    findings = []

    for row in http_body_previews:
        text = row.get("body_preview", "") or ""
        for label, pattern in CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append({
                    "source_type": "http_body_preview",
                    "tcp_stream": row.get("tcp_stream", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "host": row.get("host", ""),
                    "uri": row.get("uri", ""),
                    "indicator_type": label,
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

        for label, pattern in CREDENTIAL_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append({
                    "source_type": "extracted_payload",
                    "tcp_stream": row.get("tcp_stream", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "host": "",
                    "uri": row.get("filename", ""),
                    "indicator_type": label,
                    "match_excerpt": match.group(0)[:200],
                })

    return findings


def decode_base64_payloads(extracted_payloads: list[dict], case_output_dir: Path) -> list[dict]:
    decoded_dir = case_output_dir / "decoded_payloads"
    decoded_dir.mkdir(parents=True, exist_ok=True)

    results = []
    counter = 1

    for row in extracted_payloads:
        if not row.get("is_text"):
            continue

        output_file = row.get("output_file", "")
        try:
            text = Path(output_file).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for match in BASE64_CANDIDATE_RE.finditer(text):
            candidate = match.group(0)

            if len(candidate) < 64 or (len(candidate) % 4 != 0):
                continue

            try:
                decoded = base64.b64decode(candidate, validate=True)
            except (binascii.Error, ValueError):
                continue

            if len(decoded) < 24:
                continue

            decoded_type, decoded_ext = detect_magic_file_type(decoded)
            if decoded_type == "UNKNOWN":
                continue

            base_name = Path(row.get("filename", f"payload_{counter}")).stem
            out_name = (
                f"decoded__tcpstream_{row.get('tcp_stream', 'unknown')}"
                f"__{base_name}_{counter}{decoded_ext}"
            )
            out_path = decoded_dir / out_name
            out_path.write_bytes(decoded)

            preview = ""
            if looks_mostly_text(decoded):
                preview = decoded[:200].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")

            results.append({
                "source_file": output_file,
                "decoded_file": str(out_path),
                "tcp_stream": row.get("tcp_stream", ""),
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "decoded_type": decoded_type,
                "decoded_extension": decoded_ext,
                "size_bytes": len(decoded),
                "size_human": human_readable_bytes(len(decoded)),
                "preview": preview,
            })
            counter += 1

    return results


def build_suspicious_downloads(http_rows: list[dict], extracted_payloads: list[dict]) -> list[dict]:
    downloads = []

    for row in http_rows:
        method = (row.get("http.request.method", "") or "").upper()
        uri = row.get("http.request.uri", "") or ""
        host = row.get("http.host", "") or ""
        content_type = (row.get("http.content_type", "") or "").lower()
        disposition = row.get("http.content_disposition", "") or ""

        ext = Path(uri.split("?", 1)[0]).suffix.lower()

        reasons = []
        if method == "GET" and ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS:
            reasons.append(f"GET to suspicious file extension {ext}")
        if content_type in SUSPICIOUS_CONTENT_TYPES:
            reasons.append(f"Suspicious content-type {content_type}")
        if "filename=" in disposition.lower():
            disp_ext = Path(disposition).suffix.lower()
            if disp_ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS:
                reasons.append(f"Content-Disposition references suspicious file extension {disp_ext}")

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
        if detected in {"PDF", "ZIP", "PE_EXE"}:
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

        if mean_delta > 1 and stdev_delta < max(1.0, mean_delta * 0.2):
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
                "bytes": flow_bytes.get(flow, 0),
                "bytes_human": human_readable_bytes(flow_bytes.get(flow, 0)),
            })

    findings.sort(key=lambda x: (x["stdev_interval_sec"], -x["packet_count"]))
    return findings


def build_alerts(
    flow_bytes,
    file_indicators,
    http_body_previews=None,
    tls_summary=None,
    beaconing_candidates=None,
    credential_findings=None,
    suspicious_downloads=None,
):
    alerts = []
    http_body_previews = http_body_previews or []
    tls_summary = tls_summary or []
    beaconing_candidates = beaconing_candidates or []
    credential_findings = credential_findings or []
    suspicious_downloads = suspicious_downloads or []

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
            "reason": (
                f"Regular timing detected (avg={item.get('avg_interval_sec')}s, "
                f"stdev={item.get('stdev_interval_sec')}s)"
            ),
        })

    for item in credential_findings:
        alerts.append({
            "alert_type": "CREDENTIAL_INDICATOR",
            "src_ip": item.get("src_ip"),
            "dst_ip": item.get("dst_ip"),
            "protocol": "HTTP",
            "tcp_stream": item.get("tcp_stream"),
            "reason": f"Credential/token-like content detected: {item.get('indicator_type')}",
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

    return alerts