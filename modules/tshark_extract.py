import csv
import io
import subprocess
import sys

from modules.dependencies import find_tshark
from modules.tshark_capabilities import filter_available_fields


def set_csv_field_limit():
    max_size = sys.maxsize
    while True:
        try:
            csv.field_size_limit(max_size)
            break
        except OverflowError:
            max_size = max_size // 10


def run_tshark_fields(pcap_path, fields, display_filter=None):
    tshark_path = find_tshark()
    if not tshark_path:
        return [], "TShark not found"

    # Drop fields this TShark version doesn't know about so a single
    # unsupported field can't fail the whole pass. -n disables name
    # resolution for deterministic, faster offline analysis.
    usable_fields, _dropped = filter_available_fields(fields)

    cmd = [tshark_path, "-n", "-r", str(pcap_path), "-T", "fields"]

    if display_filter:
        cmd.extend(["-Y", display_filter])

    for field in usable_fields:
        cmd.extend(["-e", field])

    cmd.extend(["-E", "header=y", "-E", "separator=,", "-E", "quote=d"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return [], result.stderr.strip()

    set_csv_field_limit()
    reader = csv.DictReader(io.StringIO(result.stdout))
    return list(reader), None


def extract_http_fields(pcap_path):
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "http.request.method",
        "http.request.uri",
        "http.host",
        "http.user_agent",
        "http.content_type",
        "http.content_length",
        "http.file_data",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="http.request")


def extract_http_response_fields(pcap_path):
    """Extract HTTP response metadata to correlate results with requests."""
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "http.response.code",
        "http.response.phrase",
        "http.content_type",
        "http.content_length",
        "http.server",
        "http.location",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="http.response")


def extract_dns_fields(pcap_path):
    """Extract DNS queries and answers for tunneling detection and passive DNS correlation."""
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.qry.type",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.resp.ttl",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="dns")


def extract_smb_fields(pcap_path):
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "smb.file",
        "smb.path",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="smb || smb2")


def extract_ftp_fields(pcap_path):
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "ftp.request.command",
        "ftp.request.arg",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="ftp")


def extract_smtp_fields(pcap_path):
    """Extract SMTP/IMAP/POP3 activity for email-based exfiltration and credential detection."""
    fields = [
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "smtp.req.command",
        "smtp.req.parameter",
        "smtp.auth.username",
        "imap.request",
        "pop.request",
    ]
    return run_tshark_fields(
        pcap_path, fields, display_filter="smtp or imap or pop"
    )


def extract_kerberos_fields(pcap_path):
    """Extract Kerberos authentication events for credential attack detection."""
    fields = [
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "kerberos.msg_type",
        "kerberos.CNameString",
        "kerberos.realm",
        "kerberos.error_code",
        "kerberos.etype",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="kerberos")


def extract_icmp_fields(pcap_path):
    """Extract ICMP packet metadata for tunnel and covert channel detection."""
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.code",
        "icmp.seq",
        "frame.len",
        "data.len",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="icmp")


def extract_arp_fields(pcap_path):
    """Extract ARP packet fields for spoofing and MITM detection."""
    fields = [
        "frame.time",
        "arp.opcode",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "arp.src.hw_mac",
        "arp.dst.hw_mac",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="arp")


def extract_tcp_syn_fields(pcap_path):
    """Extract TCP SYN characteristics for passive OS fingerprinting."""
    fields = [
        "frame.time",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "ip.ttl",
        "tcp.window_size_value",
        "tcp.options.mss_val",
        "tcp.options.wscale.multiplier",
    ]
    return run_tshark_fields(
        pcap_path,
        fields,
        display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
    )


def extract_tcp_stream_stats(pcap_path):
    """Extract per-packet TCP fields used to score and triage streams."""
    fields = [
        "tcp.stream",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.flags.reset",
        "tcp.analysis.retransmission",
        "tcp.analysis.zero_window",
        "tcp.analysis.lost_segment",
        "tcp.completeness.str",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="tcp")
