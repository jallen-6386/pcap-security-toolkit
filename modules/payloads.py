import csv
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


def looks_mostly_text(data: bytes) -> bool:
    if not data or len(data) < 20:
        return False

    printable = sum(
        1 for b in data
        if 32 <= b <= 126 or b in (9, 10, 13)
    )
    ratio = printable / len(data)
    return ratio >= 0.90


def infer_extension(content_type: str, is_text: bool) -> str:
    content_type = (content_type or "").lower()

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


def decode_lossy(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


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
    ext = infer_extension(content_type, is_text)

    if original_filename:
        base_name = sanitize_filename(original_filename)
    else:
        base_name = f"payload_{counter}{ext}"

    if "." not in Path(base_name).name:
        base_name += ext

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
    """
    TShark follow,tcp,raw output is a hex dump as text.
    This function extracts hex characters and converts them to bytes.
    """
    hex_chars = re.findall(r"[0-9A-Fa-f]{2}", raw_text)
    if not hex_chars:
        return b""
    return bytes.fromhex("".join(hex_chars))


def extract_body_from_raw_bytes(raw_bytes: bytes) -> bytes:
    _, body_bytes = split_headers_and_body_bytes(raw_bytes)
    return body_bytes if body_bytes else raw_bytes


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

            if raw_bytes_full:
                raw_body = extract_body_from_raw_bytes(raw_bytes_full)
                if raw_body:
                    body_bytes = raw_body

            if not body_bytes:
                continue

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
                "used_raw_bytes": bool(raw_bytes_full),
                "is_text": is_text,
                "size_bytes": len(body_bytes),
                "preview": preview_text,
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