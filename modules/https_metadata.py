import csv
import io
import subprocess


def run_tshark_fields(pcap_path, fields, display_filter=None):
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields"]

    if display_filter:
        cmd.extend(["-Y", display_filter])

    for field in fields:
        cmd.extend(["-e", field])

    cmd.extend(["-E", "header=y", "-E", "separator=,", "-E", "quote=d"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return [], result.stderr.strip()

    reader = csv.DictReader(io.StringIO(result.stdout))
    return list(reader), None


def extract_tls_metadata(pcap_path):
    fields = [
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "x509ce.dNSName",
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
            "cipher_suite": row.get("tls.handshake.ciphersuite", ""),
            "cert_dns_names": row.get("x509ce.dNSName", ""),
            "cert_not_before": row.get("x509ce.notBefore", ""),
            "cert_not_after": row.get("x509ce.notAfter", ""),
        })

    return results