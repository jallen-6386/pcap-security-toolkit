import subprocess

from modules.dependencies import find_tshark
from modules.tshark_extract import for_each_tshark_field_row


def extract_tcp_stream_index(pcap_path):
    """
    Return (rows, err) with one row per TCP stream — the first packet seen for
    each stream. That is all downstream consumers need (unique stream IDs and a
    stream->endpoint lookup), so the index is built by streaming and keeping
    only the first row per stream. Memory is bounded by the number of streams
    rather than the packet count, which matters on multi-million-packet captures.
    """
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
    ]
    first_by_stream: dict[str, dict] = {}

    def handler(row):
        stream_id = (row.get("tcp.stream") or "").strip()
        if stream_id and stream_id not in first_by_stream:
            first_by_stream[stream_id] = row

    err = for_each_tshark_field_row(pcap_path, fields, "tcp", handler)
    if err is not None:
        return [], err
    return list(first_by_stream.values()), None


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
