"""
HTTP object export via TShark.

`tshark --export-objects http,<dir>` reconstructs files transferred over HTTP,
correctly handling chunked transfer-encoding and gzip/deflate compression that
raw-stream carving cannot. This complements the existing carving/payload paths
with reliable HTTP file recovery, then hashes and fingerprints each object.
"""

import subprocess
from pathlib import Path

from modules.dependencies import find_tshark
from modules.payloads import detect_file_signature, sha256_hex, shannon_entropy


def export_http_objects(pcap_path, output_dir: Path) -> list[dict]:
    """
    Export HTTP objects into output_dir/http_objects and return an index.

    Each row: filename, saved_path, size_bytes, size_human, sha256, entropy,
    detected_file_type, detected_extension. Returns [] if TShark is missing or
    nothing was exported.
    """
    tshark = find_tshark()
    if not tshark:
        return []

    objects_dir = Path(output_dir) / "http_objects"
    objects_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        tshark, "-n", "-q",
        "-r", str(pcap_path),
        "--export-objects", f"http,{objects_dir}",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        return []

    results = []
    for path in sorted(objects_dir.iterdir()):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if not data:
            continue
        file_type, detected_ext = detect_file_signature(data)
        results.append({
            "filename": path.name,
            "saved_path": str(path),
            "size_bytes": len(data),
            "size_human": f"{len(data)} B",
            "sha256": sha256_hex(data),
            "entropy": round(shannon_entropy(data[:4096]), 3),
            "detected_file_type": file_type,
            "detected_extension": detected_ext,
        })
    return results
