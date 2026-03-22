import base64
import binascii
import csv
import hashlib
import math
import re
from pathlib import Path


FILENAME_RE = re.compile(
    r'filename="([^"]+)"|filename=([^;\r\n]+)',
    re.IGNORECASE,
)

CONTENT_TYPE_RE = re.compile(
    r"Content-Type:\s*([^\r\n;]+)",
    re.IGNORECASE,
)

HTTP_STATUS_RE = re.compile(
    r"^HTTP/\d\.\d\s+\d{3}",
    re.MULTILINE,
)

HTTP_REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+.+\s+HTTP/\d\.\d",
    re.MULTILINE,
)

BOUNDARY_RE = re.compile(
    r'boundary="?([^";\r\n]+)"?',
    re.IGNORECASE,
)


def sanitize_filename(name: str) -> str:
    name = name.strip().strip('"').strip("'")
    name = Path(name).name
    if not name:
        return "payload.bin"

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return safe[:180] or "payload.bin"


def sanitize_ip(ip: str) -> str:
    return ip.replace(":", "_").replace(".", "_")


def decode_lossy(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def looks_mostly_text(data: bytes) -> bool:
    if not data or len(data) < 20:
        return False

    printable = sum(
        1 for b in data
        if 32 <= b <= 126 or b in (9, 10, 13)
    )
    return (printable / len(data)) >= 0.90


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs = {}
    for b in data:
        freqs[b] = freqs.get(b, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freqs.values())


def infer_extension(content_type: str, is_text: bool, detected_ext: str = "") -> str:
    content_type = (content_type or "").lower()

    if detected_ext:
        return detected_ext
    if content_type == "text/plain":
        return ".txt"
    if content_type == "text/html":
        return ".html"
    if content_type == "application/json":
        return ".json"
    if content_type in {"application/xml", "text/xml"}:
        return ".xml"
    if content_type == "application/zip":
        return ".zip"
    if content_type == "application/pdf":
        return ".pdf"
    if content_type.startswith("image/jpeg"):
        return ".jpg"
    if content_type.startswith("image/png"):
        return ".png"
    if content_type.startswith("image/gif"):
        return ".gif"
    if content_type.startswith("application/octet-stream"):
        return ".bin"

    return ".txt" if is_text else ".bin"


def detect_file_signature(data: bytes) -> tuple[str, str]:
    if not data:
        return "UNKNOWN", ".bin"

    if data.startswith(b"%PDF-"):
        return "PDF", ".pdf"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ZIP", ".zip"
    if data.startswith(b"MZ"):
        return "PE_EXE", ".exe"
    if data.startswith(b"\x7fELF"):
        return "ELF", ".elf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG", ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG", ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF", ".gif"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR", ".rar"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "SEVEN_Z", ".7z"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP", ".gz"
    if data.startswith(b"BZh"):
        return "BZIP2", ".bz2"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLITE", ".sqlite"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE2", ".doc"
    if data.startswith(b"<?xml") or data.startswith(b"<rss") or data.startswith(b"<feed"):
        return "XML", ".xml"
    if data.startswith(b"{") or data.startswith(b"["):
        if looks_mostly_text(data[:512]):
            return "JSON_OR_TEXT", ".json"
    if looks_mostly_text(data[:2048]):
        return "TEXT", ".txt"

    return "UNKNOWN", ".bin"


def extract_filename_from_headers(content: str) -> str | None:
    match = FILENAME_RE.search(content)
    if not match:
        return None

    filename = match.group(1) or match.group(2)
    if not filename:
        return None

    return sanitize_filename(filename)


def extract_content_type(content: str) -> str | None:
    match = CONTENT_TYPE_RE.search(content)
    if not match:
        return None
    return match.group(1).strip()


def split_headers_and_body_text(text: str) -> tuple[str, str]:
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def split_headers_and_body_bytes(data: bytes) -> tuple[bytes, bytes]:
    if b"\r\n\r\n" in data:
        return data.split(b"\r\n\r\n", 1)
    if b"\n\n" in data:
        return data.split(b"\n\n", 1)
    return data, b""


def build_output_name(
    tcp_stream: str,
    src_ip: str,
    src_port: str,
    dst_ip: str,
    dst_port: str,
    original_filename: str | None,
    content_type: str,
    body_bytes: bytes,
    counter: int,
) -> str:
    safe_src_ip = sanitize_ip(src_ip)
    safe_dst_ip = sanitize_ip(dst_ip)

    is_text = looks_mostly_text(body_bytes)
    file_type, detected_ext = detect_file_signature(body_bytes)
    ext = infer_extension(content_type, is_text, detected_ext)

    if original_filename:
        base_name = sanitize_filename(original_filename)
    else:
        base_name = f"payload_{counter}{ext}"

    if "." not in Path(base_name).name:
        base_name += ext

    _ = file_type

    return (
        f"tcpstream_{tcp_stream}__"
        f"{safe_src_ip}_{src_port}__to__{safe_dst_ip}_{dst_port}__"
        f"{base_name}"
    )


def extract_multipart_parts_from_ascii(body_text: str, boundary: str) -> list[dict]:
    parts_found = []
    boundary_marker = f"--{boundary}"
    raw_parts = body_text.split(boundary_marker)

    for raw_part in raw_parts:
        raw_part = raw_part.strip()
        if not raw_part or raw_part == "--":
            continue

        headers_text, part_body_text = split_headers_and_body_text(raw_part)
        filename = extract_filename_from_headers(headers_text)
        content_type = extract_content_type(headers_text) or "application/octet-stream"
        body_bytes = part_body_text.strip("\r\n").encode("utf-8", errors="replace")

        if not body_bytes:
            continue

        parts_found.append({
            "filename": filename,
            "content_type": content_type,
            "body_bytes": body_bytes,
            "is_text": looks_mostly_text(body_bytes),
            "source": "multipart_ascii",
        })

    return parts_found


def extract_http_payload_candidates_from_ascii(stream_text: str) -> list[dict]:
    candidates = []

    if not (HTTP_STATUS_RE.search(stream_text) or HTTP_REQUEST_RE.search(stream_text)):
        return candidates

    headers_text, body_text = split_headers_and_body_text(stream_text)
    boundary_match = BOUNDARY_RE.search(headers_text)

    if boundary_match and body_text:
        boundary = boundary_match.group(1)
        candidates.extend(extract_multipart_parts_from_ascii(body_text, boundary))

    content_type = extract_content_type(headers_text) or "application/octet-stream"
    filename = extract_filename_from_headers(headers_text)
    body_bytes = body_text.encode("utf-8", errors="replace")

    if body_bytes:
        candidates.append({
            "filename": filename,
            "content_type": content_type,
            "body_bytes": body_bytes,
            "is_text": looks_mostly_text(body_bytes),
            "source": "http_body_ascii",
        })

    return candidates


def parse_raw_follow_stream_bytes(raw_text: str) -> bytes:
    hex_chars = re.findall(r"[0-9A-Fa-f]{2}", raw_text)
    if not hex_chars:
        return b""
    return bytes.fromhex("".join(hex_chars))


def extract_body_from_raw_bytes(raw_bytes: bytes) -> bytes:
    _, body_bytes = split_headers_and_body_bytes(raw_bytes)
    return body_bytes if body_bytes else raw_bytes


def maybe_decode_base64_payload(data: bytes) -> tuple[bytes | None, str]:
    if not data or not looks_mostly_text(data):
        return None, ""

    compact = "".join(decode_lossy(data).split())
    if len(compact) < 80 or len(compact) % 4 != 0:
        return None, ""

    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None, ""

    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None, ""

    if len(decoded) < 24:
        return None, ""

    detected_type, _ = detect_file_signature(decoded)
    if detected_type == "UNKNOWN" and not looks_mostly_text(decoded):
        return None, ""

    return decoded, detected_type


def carve_files_from_raw_streams(case_output_dir: Path, streams_dir: Path, tcp_stream_rows: list[dict]) -> list[dict]:
    carved_dir = case_output_dir / "carved_files"
    carved_dir.mkdir(parents=True, exist_ok=True)

    stream_lookup = {}
    for row in tcp_stream_rows:
        stream_id = (row.get("tcp.stream") or "").strip()
        if stream_id and stream_id not in stream_lookup:
            stream_lookup[stream_id] = {
                "src_ip": row.get("ip.src", ""),
                "src_port": row.get("tcp.srcport", ""),
                "dst_ip": row.get("ip.dst", ""),
                "dst_port": row.get("tcp.dstport", ""),
            }

    signatures = [
        (b"%PDF-", "PDF", ".pdf"),
        (b"PK\x03\x04", "ZIP", ".zip"),
        (b"MZ", "PE_EXE", ".exe"),
    ]

    results = []
    counter = 1

    for raw_file in sorted(streams_dir.glob("tcp_stream_*.raw.txt")):
        try:
            raw_text = raw_file.read_text(encoding="utf-8", errors="replace")
            raw_bytes = parse_raw_follow_stream_bytes(raw_text)
        except Exception:
            continue

        if not raw_bytes:
            continue

        stream_id_match = re.search(r"tcp_stream_(\d+)", raw_file.name)
        tcp_stream = stream_id_match.group(1) if stream_id_match else "unknown"
        flow_meta = stream_lookup.get(
            tcp_stream,
            {"src_ip": "", "src_port": "", "dst_ip": "", "dst_port": ""},
        )

        for sig, label, ext in signatures:
            idx = raw_bytes.find(sig)
            if idx == -1:
                continue

            carved = raw_bytes[idx:]
            out_name = (
                f"carved__tcpstream_{tcp_stream}__"
                f"{sanitize_ip(flow_meta['src_ip'])}_{flow_meta['src_port']}__to__"
                f"{sanitize_ip(flow_meta['dst_ip'])}_{flow_meta['dst_port']}__"
                f"{label.lower()}_{counter}{ext}"
            )
            out_path = carved_dir / out_name
            out_path.write_bytes(carved)

            results.append({
                "tcp_stream": tcp_stream,
                "src_ip": flow_meta["src_ip"],
                "src_port": flow_meta["src_port"],
                "dst_ip": flow_meta["dst_ip"],
                "dst_port": flow_meta["dst_port"],
                "raw_stream_file": str(raw_file),
                "carved_file": str(out_path),
                "file_type": label,
                "size_bytes": len(carved),
                "sha256": sha256_hex(carved),
            })
            counter += 1

    return results


def save_extracted_payloads(
    case_output_dir: Path,
    streams_dir: Path,
    tcp_stream_rows: list[dict],
) -> list[dict]:
    extracted_dir = case_output_dir / "extracted_payloads"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    stream_lookup = {}
    for row in tcp_stream_rows:
        stream_id = (row.get("tcp.stream") or "").strip()
        if stream_id and stream_id not in stream_lookup:
            stream_lookup[stream_id] = {
                "src_ip": row.get("ip.src", ""),
                "src_port": row.get("tcp.srcport", ""),
                "dst_ip": row.get("ip.dst", ""),
                "dst_port": row.get("tcp.dstport", ""),
            }

    results = []
    counter = 1
    ascii_streams = sorted(streams_dir.glob("tcp_stream_*.ascii.txt"))

    for ascii_file in ascii_streams:
        try:
            ascii_content = ascii_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        candidates = extract_http_payload_candidates_from_ascii(ascii_content)
        if not candidates:
            continue

        stream_id_match = re.search(r"tcp_stream_(\d+)", ascii_file.name)
        tcp_stream = stream_id_match.group(1) if stream_id_match else ""
        raw_file = streams_dir / f"tcp_stream_{tcp_stream}.raw.txt"

        raw_bytes_full = b""
        if raw_file.exists():
            try:
                raw_text = raw_file.read_text(encoding="utf-8", errors="replace")
                raw_bytes_full = parse_raw_follow_stream_bytes(raw_text)
            except Exception:
                raw_bytes_full = b""

        flow_meta = stream_lookup.get(
            tcp_stream,
            {"src_ip": "", "src_port": "", "dst_ip": "", "dst_port": ""},
        )

        for candidate in candidates:
            body_bytes = candidate["body_bytes"]

            if raw_bytes_full and candidate["source"] == "http_body_ascii":
                raw_body = extract_body_from_raw_bytes(raw_bytes_full)
                if raw_body:
                    body_bytes = raw_body

            if not body_bytes:
                continue

            file_type, detected_ext = detect_file_signature(body_bytes)
            output_name = build_output_name(
                tcp_stream=tcp_stream or "unknown",
                src_ip=flow_meta["src_ip"],
                src_port=flow_meta["src_port"],
                dst_ip=flow_meta["dst_ip"],
                dst_port=flow_meta["dst_port"],
                original_filename=candidate["filename"],
                content_type=candidate["content_type"],
                body_bytes=body_bytes,
                counter=counter,
            )

            output_path = extracted_dir / output_name
            if output_path.exists():
                stem = output_path.stem
                suffix = output_path.suffix or ".bin"
                output_path = extracted_dir / f"{stem}_{counter}{suffix}"

            output_path.write_bytes(body_bytes)

            preview_text = ""
            is_text = looks_mostly_text(body_bytes)
            if is_text:
                preview_text = decode_lossy(body_bytes[:200]).replace("\r", " ").replace("\n", " ")

            results.append({
                "tcp_stream": tcp_stream,
                "src_ip": flow_meta["src_ip"],
                "src_port": flow_meta["src_port"],
                "dst_ip": flow_meta["dst_ip"],
                "dst_port": flow_meta["dst_port"],
                "ascii_stream_file": str(ascii_file),
                "raw_stream_file": str(raw_file) if raw_file.exists() else "",
                "output_file": str(output_path),
                "filename": output_path.name,
                "content_type": candidate["content_type"],
                "source": candidate["source"],
                "used_raw_bytes": bool(raw_bytes_full and candidate["source"] == "http_body_ascii"),
                "is_text": is_text,
                "size_bytes": len(body_bytes),
                "size_human": f"{len(body_bytes)} B",
                "sha256": sha256_hex(body_bytes),
                "entropy": round(shannon_entropy(body_bytes[:4096]), 3),
                "detected_file_type": file_type,
                "detected_extension": detected_ext,
                "preview": preview_text,
            })
            counter += 1

            decoded_bytes, decoded_type = maybe_decode_base64_payload(body_bytes)
            if decoded_bytes:
                decoded_name = build_output_name(
                    tcp_stream=tcp_stream or "unknown",
                    src_ip=flow_meta["src_ip"],
                    src_port=flow_meta["src_port"],
                    dst_ip=flow_meta["dst_ip"],
                    dst_port=flow_meta["dst_port"],
                    original_filename=f"{Path(output_path.name).stem}__decoded",
                    content_type="application/octet-stream",
                    body_bytes=decoded_bytes,
                    counter=counter,
                )
                decoded_path = extracted_dir / decoded_name
                decoded_path.write_bytes(decoded_bytes)

                decoded_is_text = looks_mostly_text(decoded_bytes)
                decoded_preview = ""
                if decoded_is_text:
                    decoded_preview = decode_lossy(decoded_bytes[:200]).replace("\r", " ").replace("\n", " ")

                decoded_sig, decoded_ext = detect_file_signature(decoded_bytes)
                results.append({
                    "tcp_stream": tcp_stream,
                    "src_ip": flow_meta["src_ip"],
                    "src_port": flow_meta["src_port"],
                    "dst_ip": flow_meta["dst_ip"],
                    "dst_port": flow_meta["dst_port"],
                    "ascii_stream_file": str(ascii_file),
                    "raw_stream_file": str(raw_file) if raw_file.exists() else "",
                    "output_file": str(decoded_path),
                    "filename": decoded_path.name,
                    "content_type": "application/octet-stream",
                    "source": "base64_decoded",
                    "used_raw_bytes": False,
                    "is_text": decoded_is_text,
                    "size_bytes": len(decoded_bytes),
                    "size_human": f"{len(decoded_bytes)} B",
                    "sha256": sha256_hex(decoded_bytes),
                    "entropy": round(shannon_entropy(decoded_bytes[:4096]), 3),
                    "detected_file_type": decoded_type or decoded_sig,
                    "detected_extension": decoded_ext,
                    "preview": decoded_preview,
                })
                counter += 1

    return results


def write_extracted_payload_index(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = sorted(set().union(*(row.keys() for row in rows)))

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)