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
        "http.content_disposition",
        "http.file_data",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="http")


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