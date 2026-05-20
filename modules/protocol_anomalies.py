"""
Detect protocol-on-wrong-port anomalies.

Attackers commonly run C2 on non-standard ports (HTTP on 4444, TLS on 8080,
SSH on 443) to evade port-based firewall rules. This module cross-references
known protocol traffic with their expected port ranges and flags deviations.
"""

# Standard port sets for each protocol
_HTTP_PORTS = {80, 8080, 8000, 8008, 3000, 8888, 8081, 8180}
_HTTPS_PORTS = {443, 8443, 9443, 4443}
_FTP_PORTS = {21, 20}
_SSH_PORTS = {22}
_SMB_PORTS = {445, 139}
_SMTP_PORTS = {25, 587, 465, 2525}
_IMAP_PORTS = {143, 993}
_POP3_PORTS = {110, 995}
_DNS_PORTS = {53, 853}
_KERBEROS_PORTS = {88}


def _to_int(val) -> int:
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return 0


def detect_protocol_anomalies(
    http_rows: list[dict],
    tls_summary: list[dict],
    ftp_rows: list[dict],
    smtp_rows: list[dict],
    kerberos_rows: list[dict],
) -> list[dict]:
    """Return rows where a protocol is observed on a non-standard port."""
    findings = []
    seen: set[tuple] = set()

    def _flag(src_ip, dst_ip, tcp_stream, protocol, port, reason):
        key = (src_ip, dst_ip, protocol, port)
        if key not in seen:
            seen.add(key)
            findings.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "tcp_stream": str(tcp_stream),
                "protocol": protocol,
                "dport": port,
                "reason": reason,
            })

    # HTTP on non-standard ports
    for row in http_rows:
        dport = _to_int(row.get("tcp.dstport", ""))
        sport = _to_int(row.get("tcp.srcport", ""))
        effective_port = dport if dport else sport
        if effective_port and effective_port not in _HTTP_PORTS and effective_port not in _HTTPS_PORTS:
            _flag(
                row.get("ip.src", ""),
                row.get("ip.dst", ""),
                row.get("tcp.stream", ""),
                "HTTP",
                effective_port,
                f"HTTP traffic observed on port {effective_port} (expected 80/8080/etc.)",
            )

    # TLS on non-standard ports
    for row in tls_summary:
        dport = _to_int(row.get("dst_port", ""))
        if dport and dport not in _HTTPS_PORTS:
            _flag(
                row.get("src_ip", ""),
                row.get("dst_ip", ""),
                row.get("tcp_stream", ""),
                "TLS",
                dport,
                f"TLS handshake on port {dport} (expected 443/8443/etc.)",
            )

    # FTP on non-standard ports
    for row in ftp_rows:
        dport = _to_int(row.get("tcp.dstport", ""))
        if dport and dport not in _FTP_PORTS:
            _flag(
                row.get("ip.src", ""),
                row.get("ip.dst", ""),
                row.get("tcp.stream", ""),
                "FTP",
                dport,
                f"FTP commands observed on port {dport} (expected 21)",
            )

    # SMTP/IMAP/POP3 on non-standard ports
    for row in smtp_rows:
        dport = _to_int(row.get("tcp.dstport", ""))
        all_email_ports = _SMTP_PORTS | _IMAP_PORTS | _POP3_PORTS
        if dport and dport not in all_email_ports:
            proto = "SMTP/IMAP/POP3"
            _flag(
                row.get("ip.src", ""),
                row.get("ip.dst", ""),
                row.get("tcp.stream", ""),
                proto,
                dport,
                f"{proto} activity on port {dport} (expected 25/587/143/110/etc.)",
            )

    # Kerberos on non-standard ports
    for row in kerberos_rows:
        dport = _to_int(row.get("tcp.dstport", ""))
        if dport and dport not in _KERBEROS_PORTS:
            _flag(
                row.get("ip.src", ""),
                row.get("ip.dst", ""),
                row.get("tcp.stream", ""),
                "Kerberos",
                dport,
                f"Kerberos traffic on port {dport} (expected 88)",
            )

    return findings
