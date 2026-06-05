"""
IOC extraction and deduplication.

Collects IPs, domains, URLs, SHA-256 hashes, user agents, JA3, JA4, and JA4H
fingerprints from all analysis results and outputs a deduplicated iocs.csv
that can be imported into MISP, OpenCTI, TheHive, or a SIEM block-rule pipeline.
"""

from modules.allowlists import is_benign_resolver
from modules.utils import is_noise_ip


def extract_iocs(
    flow_bytes: dict,
    dns_rows: list[dict],
    tls_summary: list[dict],
    http_rows: list[dict],
    extracted_payloads: list[dict],
    carved_files: list[dict],
    alerts: list[dict],
    geoip_map: dict | None = None,
    ja4h_rows: list[dict] | None = None,
    smtp_attachments: list[dict] | None = None,
) -> list[dict]:
    """
    Return a deduplicated list of IOC dicts with keys:
        ioc_type, value, source, confidence, first_seen, country_iso, asn, asn_org
    """
    geoip_map = geoip_map or {}
    ja4h_rows = ja4h_rows or []
    smtp_attachments = smtp_attachments or []
    iocs: dict[tuple, dict] = {}

    def _add(ioc_type: str, value: str, source: str, confidence: str, first_seen: str = ""):
        if not value or not value.strip():
            return
        value = value.strip()
        key = (ioc_type, value.lower())
        if key not in iocs:
            geo = {}
            if ioc_type == "ipv4":
                geo = geoip_map.get(value, {})
            # Annotate (don't drop) well-known benign endpoints so a SIEM import
            # can filter them instead of block-listing a public resolver. Only
            # genuinely-benign endpoints qualify — CDN/cloud domains are NOT
            # marked benign, because a specific distribution/host on a trusted
            # CDN can itself be malicious (phishing kits, C2 redirectors).
            benign_infra = ioc_type == "ipv4" and is_benign_resolver(value)
            iocs[key] = {
                "ioc_type": ioc_type,
                "value": value,
                "source": source,
                "confidence": confidence,
                "first_seen": first_seen,
                "benign_infra": benign_infra,
                "country_iso": geo.get("country_iso", ""),
                "asn": geo.get("asn", ""),
                "asn_org": geo.get("asn_org", ""),
            }
        else:
            # Keep highest-confidence source note
            existing = iocs[key]
            if existing["confidence"] == "LOW" and confidence in {"MEDIUM", "HIGH"}:
                existing["confidence"] = confidence
            if not existing["first_seen"] and first_seen:
                existing["first_seen"] = first_seen

    # External IPs from flows
    for flow_key in flow_bytes:
        src, dst, sport, dport, proto = flow_key
        for ip in (src, dst):
            if ip and not is_noise_ip(ip):
                _add("ipv4", ip, "flow_analysis", "LOW")

    # DNS-resolved domains and IPs
    for row in dns_rows:
        qname = (row.get("dns.qry.name", "") or "").strip().lower().rstrip(".")
        resolved_a = (row.get("dns.a", "") or "").strip()
        ts = row.get("frame.time", "")
        if qname:
            _add("domain", qname, "dns_query", "MEDIUM", ts)
        if resolved_a and not is_noise_ip(resolved_a):
            _add("ipv4", resolved_a, "dns_answer", "MEDIUM", ts)

    # TLS SNI values, JA3, and JA4 fingerprints
    for row in tls_summary:
        sni = (row.get("sni", "") or "").strip()
        ja3 = (row.get("ja3", "") or "").strip()
        ja4 = (row.get("ja4", "") or "").strip()
        ja4s = (row.get("ja4s", "") or "").strip()
        ts = row.get("timestamp", "")
        dst_ip = row.get("dst_ip", "")
        if sni:
            _add("domain", sni, "tls_sni", "MEDIUM", ts)
        if ja3:
            _add("ja3_fingerprint", ja3, "tls_handshake_ja3", "MEDIUM", ts)
        if ja4:
            _add("ja4_fingerprint", ja4, "tls_handshake_ja4", "MEDIUM", ts)
        if ja4s:
            _add("ja4s_fingerprint", ja4s, "tls_handshake_ja4s", "LOW", ts)
        if dst_ip and not is_noise_ip(dst_ip):
            _add("ipv4", dst_ip, "tls_session", "LOW", ts)

    # JA4H fingerprints from HTTP streams
    for row in ja4h_rows:
        ja4h = (row.get("ja4h", "") or "").strip()
        ts = ""
        if ja4h:
            _add("ja4h_fingerprint", ja4h, "http_stream_ja4h", "MEDIUM", ts)

    # HTTP URLs and user agents
    for row in http_rows:
        host = (row.get("http.host", "") or "").strip()
        uri = (row.get("http.request.uri", "") or "").strip()
        ua = (row.get("http.user_agent", "") or "").strip()
        dst_ip = row.get("ip.dst", "")
        ts = row.get("frame.time", "")
        if host:
            _add("domain", host, "http_host", "MEDIUM", ts)
            if uri:
                url = f"http://{host}{uri}"
                _add("url", url, "http_request", "MEDIUM", ts)
        if ua:
            _add("user_agent", ua, "http_user_agent", "LOW", ts)
        if dst_ip and not is_noise_ip(dst_ip):
            _add("ipv4", dst_ip, "http_destination", "LOW", ts)

    # SHA-256 hashes from extracted payloads
    for row in extracted_payloads:
        sha = (row.get("sha256", "") or "").strip()
        if sha:
            _add("sha256", sha, "extracted_payload", "HIGH", "")

    # SHA-256 hashes from carved files
    for row in carved_files:
        sha = (row.get("sha256", "") or "").strip()
        if sha:
            _add("sha256", sha, "carved_file", "HIGH", "")

    # SHA-256 hashes from SMTP attachments
    for row in smtp_attachments:
        sha = (row.get("sha256", "") or "").strip()
        if sha:
            _add("sha256", sha, "smtp_attachment", "HIGH", "")

    # External IPs from high-confidence alerts
    high_conf = {"CRITICAL", "HIGH"}
    for alert in alerts:
        sev = alert.get("severity", "")
        if sev not in high_conf:
            continue
        for field in ("src_ip", "dst_ip"):
            ip = (alert.get(field, "") or "").strip()
            if ip and not is_noise_ip(ip):
                _add("ipv4", ip, f"alert_{alert.get('alert_type','').lower()}", "HIGH")

    # Sort: CRITICAL/HIGH confidence first, then by type, then value
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    result = sorted(
        iocs.values(),
        key=lambda x: (order.get(x["confidence"], 3), x["ioc_type"], x["value"]),
    )
    return result
