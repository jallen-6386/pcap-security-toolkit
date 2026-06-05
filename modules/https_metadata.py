from modules.tshark_extract import run_tshark_fields


# ---------------------------------------------------------------------------
# Known-malicious JA3 fingerprints — format: hash → (label, source)
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_JA3 = {
    "72a589da586844d7f0818ce684948eea": ("Cobalt Strike default", "abuse.ch"),
    "a0e9f5d64349fb13191bc781f81f42e1": ("Metasploit Meterpreter", "abuse.ch"),
    "6734f37431670b3ab4292b8f60f29984": ("Dridex", "abuse.ch"),
    "b386946a5a44d1ddcc843bc75336dfce": ("Trickbot", "abuse.ch"),
    "3b5074b1b5d032e5620f69f9f700ff0e": ("AgentTesla", "abuse.ch"),
    "c12f54a3f91dc7bafd92cb59fe009a35": ("Mirai botnet", "abuse.ch"),
    "d0ec4b50a944b182fc10ff51f883ccf7": ("AsyncRAT", "abuse.ch"),
    "bc6c386f480f78b0b6e1af699893bdee": ("njRAT", "abuse.ch"),
    "839bbe3ed07fed922ded5aaf714d6842": ("Emotet", "abuse.ch"),
}

# ---------------------------------------------------------------------------
# Known-malicious JA4 fingerprints — format: hash → (label, source)
# Extend this list with entries from https://github.com/FoxIO-LLC/ja4/blob/main/database/ja4db.csv
# or your own threat intelligence feed.
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS_JA4 = {
    # Cobalt Strike Beacon (malleable C2 default profile)
    "t13d881000000000_b20f5b05acbd83c9_f72b7e346e21fd5f": ("Cobalt Strike Beacon", "FoxIO"),
    # Metasploit Meterpreter
    "t13d190900_9dc949149365_97f8aa674fd9":                ("Metasploit Meterpreter", "FoxIO"),
    # Sliver C2
    "t13d190900_9dc949149365_e7c285222651":                ("Sliver C2", "FoxIO"),
    # Brute Ratel C4
    "t13d881000000000_8daaf6152771_e5627efa2ab1":          ("Brute Ratel C4", "FoxIO"),
    # Havoc C2
    "t13d190900_9dc949149365_4a4548c62f5e":                ("Havoc C2", "FoxIO"),
}


# ---------------------------------------------------------------------------
# TLS metadata extraction
# ---------------------------------------------------------------------------

def extract_tls_metadata(pcap_path):
    fields = [
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.ciphersuite",
        "tls.handshake.ja3",
        "tls.handshake.ja3s",
        "tls.handshake.ja4",
        "tls.handshake.ja4s",
        "x509ce.dNSName",
        "x509af.serialNumber",
        "x509ce.notBefore",
        "x509ce.notAfter",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="tls")


def summarize_tls_rows(tls_rows):
    seen = set()
    results = []

    for row in tls_rows:
        key = (
            row.get("ip.src", ""),
            row.get("ip.dst", ""),
            row.get("tcp.stream", ""),
            row.get("tls.handshake.extensions_server_name", ""),
            row.get("x509ce.dNSName", ""),
        )
        if key in seen:
            continue
        seen.add(key)

        results.append({
            "timestamp": row.get("frame.time", ""),
            "src_ip": row.get("ip.src", ""),
            "src_port": row.get("tcp.srcport", ""),
            "dst_ip": row.get("ip.dst", ""),
            "dst_port": row.get("tcp.dstport", ""),
            "tcp_stream": row.get("tcp.stream", ""),
            "sni": row.get("tls.handshake.extensions_server_name", ""),
            "alpn": row.get("tls.handshake.extensions_alpn_str", ""),
            "cipher_suite": row.get("tls.handshake.ciphersuite", ""),
            "ja3": row.get("tls.handshake.ja3", ""),
            "ja3s": row.get("tls.handshake.ja3s", ""),
            "ja4": row.get("tls.handshake.ja4", ""),
            "ja4s": row.get("tls.handshake.ja4s", ""),
            "ja4_source": "",
            "cert_dns_names": row.get("x509ce.dNSName", ""),
            "cert_serial": row.get("x509af.serialNumber", ""),
            "cert_not_before": row.get("x509ce.notBefore", ""),
            "cert_not_after": row.get("x509ce.notAfter", ""),
        })

    return results


# ---------------------------------------------------------------------------
# Malicious fingerprint detection
# ---------------------------------------------------------------------------

def detect_malicious_ja3(tls_summary: list[dict]) -> list[dict]:
    """Flag TLS sessions whose JA3 hash matches known-malicious fingerprints."""
    findings = []
    seen: set[tuple] = set()

    for row in tls_summary:
        ja3 = (row.get("ja3", "") or "").strip().lower()
        if not ja3:
            continue

        match = KNOWN_MALICIOUS_JA3.get(ja3)
        if match:
            label, source = match
            key = (row.get("src_ip", ""), ja3)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "fingerprint_type": "JA3",
                    "timestamp": row.get("timestamp", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "tcp_stream": row.get("tcp_stream", ""),
                    "sni": row.get("sni", ""),
                    "ja3": ja3,
                    "ja3s": row.get("ja3s", ""),
                    "ja4": row.get("ja4", ""),
                    "ja4s": row.get("ja4s", ""),
                    "malware_family": label,
                    "intel_source": source,
                    "reason": f"JA3 {ja3} matches {label} ({source})",
                })

    return findings


def detect_malicious_ja4(tls_summary: list[dict]) -> list[dict]:
    """Flag TLS sessions whose JA4 hash matches known-malicious fingerprints."""
    findings = []
    seen: set[tuple] = set()

    for row in tls_summary:
        ja4 = (row.get("ja4", "") or "").strip().lower()
        if not ja4:
            continue

        match = KNOWN_MALICIOUS_JA4.get(ja4)
        if match:
            label, source = match
            key = (row.get("src_ip", ""), ja4)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "fingerprint_type": "JA4",
                    "timestamp": row.get("timestamp", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "tcp_stream": row.get("tcp_stream", ""),
                    "sni": row.get("sni", ""),
                    "ja3": row.get("ja3", ""),
                    "ja3s": row.get("ja3s", ""),
                    "ja4": ja4,
                    "ja4s": row.get("ja4s", ""),
                    "malware_family": label,
                    "intel_source": source,
                    "reason": f"JA4 {ja4} matches {label} ({source})",
                })

    return findings
