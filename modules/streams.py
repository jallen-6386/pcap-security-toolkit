import csv
import io
import subprocess

from modules.dependencies import find_tshark


def run_tshark_fields(pcap_path, fields, display_filter=None):
    tshark_path = find_tshark()
    if not tshark_path:
        return [], "TShark not found"

    cmd = [tshark_path, "-r", str(pcap_path), "-T", "fields"]

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


def extract_tcp_stream_index(pcap_path):
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
    ]
    return run_tshark_fields(pcap_path, fields, display_filter="tcp")


def export_follow_stream(pcap_path, stream_id, mode="ascii"):
    tshark_path = find_tshark()
    if not tshark_path:
        return None, "TShark not found"

    cmd = [
        tshark_path,
        "-r", str(pcap_path),
        "-q",
        "-z", f"follow,tcp,{mode},{stream_id}",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr.strip()

    return result.stdout, None


def get_unique_tcp_stream_ids(stream_rows):
    stream_ids = set()
    for row in stream_rows:
        value = (row.get("tcp.stream") or "").strip()
        if value.isdigit():
            stream_ids.add(int(value))
    return sorted(stream_ids)