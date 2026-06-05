import subprocess

from modules.dependencies import find_tshark
from modules.tshark_extract import run_tshark_fields


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
        "-n",
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
