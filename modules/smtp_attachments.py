"""
SMTP attachment extraction from exported TCP streams.

Parses MIME content from SMTP DATA sections in exported ASCII streams,
extracts attachments, decodes them, saves to disk, and SHA-256 hashes
each file. Requires --export-streams.
"""
import email
import email.policy
import hashlib
import re
from pathlib import Path

_SMTP_PORTS = {25, 465, 587, 2525}

# MIME types that are interesting regardless of Content-Disposition
_INTERESTING_CONTENT_TYPES = {
    "application/", "octet-stream", "zip", "pdf", "exe", "msword",
    "vnd.ms-", "vnd.openxmlformats", "x-dosexec", "x-executable",
    "x-elf", "x-msdos-program", "x-msdownload",
}


def _is_smtp_stream(row: dict) -> bool:
    for port_field in ("tcp.dstport", "tcp.srcport"):
        try:
            if int(row.get(port_field, "") or 0) in _SMTP_PORTS:
                return True
        except (ValueError, TypeError):
            pass
    return False


def _smtp_stream_ids(tcp_stream_rows: list[dict]) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for row in tcp_stream_rows:
        sid = (row.get("tcp.stream", "") or "").strip()
        if sid and sid not in seen and _is_smtp_stream(row):
            seen.add(sid)
            ids.append(sid)
    return ids


def _extract_data_body(stream_text: str) -> str:
    """Return the MIME body from between SMTP DATA and the terminating dot."""
    match = re.search(
        r"(?mi)^DATA\r?\n(.*?)(?:\r?\n\.\r?\n|\r?\n\.\Z|\Z)",
        stream_text,
        re.DOTALL | re.IGNORECASE,
    )
    return match.group(1) if match else ""


def _is_interesting_part(part) -> bool:
    disposition = str(part.get("Content-Disposition", "")).lower()
    content_type = (part.get_content_type() or "").lower()
    filename = part.get_filename() or ""
    if "attachment" in disposition or filename:
        return True
    return any(t in content_type for t in _INTERESTING_CONTENT_TYPES)


def extract_smtp_attachments(
    streams_dir: Path,
    tcp_stream_rows: list[dict],
    output_dir: Path,
) -> list[dict]:
    """
    Parse exported SMTP ASCII streams for MIME attachments.

    Returns a list of dicts describing extracted files (filename, sha256,
    content_type, size, saved path). Files are written to
    output_dir/smtp_attachments/.
    """
    results: list[dict] = []
    stream_ids = _smtp_stream_ids(tcp_stream_rows)
    if not stream_ids:
        return results

    attach_dir = output_dir / "smtp_attachments"

    for sid in stream_ids:
        ascii_path = streams_dir / f"tcp_stream_{sid}.ascii.txt"
        if not ascii_path.exists():
            continue

        try:
            stream_text = ascii_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        mime_body = _extract_data_body(stream_text)
        if not mime_body:
            continue

        # Try to reconstruct a parseable email by prepending any visible headers
        header_block_match = re.search(
            r"(?i)((?:(?:From|To|Subject|Date|MIME-Version|Content-Type)"
            r"[^\n]*\n)+(?:.*\n)*)",
            stream_text,
            re.DOTALL,
        )
        raw_msg = header_block_match.group(1) if header_block_match else mime_body

        try:
            msg = email.message_from_string(raw_msg, policy=email.policy.compat32)
        except Exception:
            continue

        for part in msg.walk():
            if not _is_interesting_part(part):
                continue

            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            if not payload or len(payload) < 8:
                continue

            sha256 = hashlib.sha256(payload).hexdigest()
            filename = part.get_filename() or f"attachment_{sha256[:8]}.bin"
            safe_name = re.sub(r"[^\w.\-]", "_", filename)
            content_type = part.get_content_type() or "application/octet-stream"

            attach_dir.mkdir(parents=True, exist_ok=True)
            out_path = attach_dir / f"stream_{sid}_{safe_name}"
            out_path.write_bytes(payload)

            results.append({
                "tcp_stream": sid,
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "sha256": sha256,
                "saved_path": str(out_path),
            })

    return results
