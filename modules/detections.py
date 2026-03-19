from modules.utils import is_private_ip


def build_alerts(flow_bytes, file_indicators, http_body_previews=None, tls_summary=None):
    alerts = []
    http_body_previews = http_body_previews or []
    tls_summary = tls_summary or []

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

    return alerts