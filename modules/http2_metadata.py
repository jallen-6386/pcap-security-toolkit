"""
HTTP/2 request and response reconstruction.

TShark decodes HPACK headers automatically (http2.headers.*) and reassembles
DATA frames into bodies (http2.body.reassembled.data), so we delegate all the
hard protocol work to TShark and only need to group frames by
(tcp.stream, http2.streamid), match requests with responses, and decompress
bodies for downstream analysis.

Produces:
  http2_requests.csv    — one row per request/response pair
  http2_bodies/         — decompressed body files (response, and POST/PUT request bodies)

Rows are also normalized to http.* field names so they can be fed directly into
the existing HTTP/1.x detection functions (suspicious downloads, user-agent
checks, credential detection, entropy exfil).
"""

import csv
import gzip
import hashlib
import io
import subprocess
import zlib
from pathlib import Path

from modules.dependencies import find_tshark
from modules.tshark_capabilities import filter_available_fields
from modules.tshark_config import decode_as_args, runtime_args

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# HTTP/2 frame types we care about
_TYPE_DATA = 0
_TYPE_HEADERS = 1

# Cap per-body extraction to avoid memory exhaustion on large file transfers
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB

_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.stream",
    "http2.streamid",
    "http2.type",
    "http2.flags.end_stream",
    # Request pseudo-headers (HEADERS frame from client)
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.authority",
    "http2.headers.scheme",
    # Response pseudo-header (HEADERS frame from server)
    "http2.headers.status",
    # Common request/response headers
    "http2.headers.content_type",
    "http2.headers.content_encoding",
    "http2.headers.content_length",
    "http2.headers.user_agent",
    "http2.headers.authorization",
    "http2.headers.cookie",
    "http2.headers.location",
    "http2.headers.server",
    # Body: per-frame DATA payload and TShark-reassembled complete body
    "http2.data.data",
    "http2.body.reassembled.data",
]


# ---------------------------------------------------------------------------
# TShark extraction
# ---------------------------------------------------------------------------

def extract_http2_frames(pcap_path) -> tuple[list[dict], str | None]:
    """
    Run a TShark fields pass over all HTTP/2 DATA and HEADERS frames.

    Uses tab field separator and comma aggregator so multi-value fields and
    byte-hex values are never ambiguous (byte hex can contain colons but not tabs).
    Returns (rows, error_string_or_None).
    """
    tshark = find_tshark()
    if not tshark:
        return [], "TShark not found"

    usable, dropped = filter_available_fields(_FIELDS)
    if dropped:
        pass  # silently skip unknown fields (older TShark)

    cmd = [
        tshark, "-n",
        *runtime_args(),
        "-r", str(pcap_path),
        "-T", "fields",
        "-Y", "http2.type == 0 || http2.type == 1",
    ]
    for field in usable:
        cmd.extend(["-e", field])
    cmd.extend([
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "aggregator=,",
        "-E", "quote=n",
    ])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return [], str(exc)

    if result.returncode != 0:
        return [], result.stderr.strip() or f"tshark exited {result.returncode}"

    reader = csv.DictReader(io.StringIO(result.stdout), delimiter="\t")
    rows = list(reader)
    return rows, None


# ---------------------------------------------------------------------------
# Byte-decoding helpers
# ---------------------------------------------------------------------------

def _decode_h2_bytes(raw: str) -> bytes:
    """
    Convert TShark FT_BYTES field output to bytes.

    TShark outputs FT_BYTES as colon-separated lowercase hex: ``48:65:6c``.
    When the aggregator joins multiple per-frame values they are comma-joined:
    ``48:65:6c,6c:6f``.  We handle both.
    """
    if not raw:
        return b""
    out = b""
    for segment in raw.split(","):
        clean = segment.strip().replace(":", "").replace(" ", "")
        if clean:
            try:
                out += bytes.fromhex(clean)
            except ValueError:
                pass
    return out


def _decompress(data: bytes, encoding: str) -> bytes:
    """Decompress body bytes given a Content-Encoding value.  Never raises."""
    enc = (encoding or "").lower().strip()
    if not data or not enc or enc == "identity":
        return data
    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(data)
        if enc == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -15)  # raw deflate (no zlib header)
        if enc in ("br", "brotli"):
            try:
                import brotli  # optional dependency
                return brotli.decompress(data)
            except (ImportError, Exception):
                pass
    except Exception:
        pass
    return data


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_text(data: bytes) -> bool:
    sample = data[:512]
    if not sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13))
        return (printable / len(sample)) > 0.85


# ---------------------------------------------------------------------------
# Session grouping
# ---------------------------------------------------------------------------

def _h2_key(row: dict) -> tuple[str, str]:
    return (row.get("tcp.stream", ""), row.get("http2.streamid", ""))


def _accumulate_body(bucket: dict, direction: str, hex_val: str, reassembled: str) -> None:
    """Append hex body data to the per-stream accumulator, respecting the size cap."""
    key_raw = f"{direction}_raw"
    key_reassembled = f"{direction}_reassembled"
    key_size = f"{direction}_raw_size"

    # Prefer reassembled field when TShark provides it on this frame
    if reassembled:
        bucket[key_reassembled] = reassembled  # last one wins (it IS the final reassembly)

    if hex_val and bucket.get(key_size, 0) < MAX_BODY_BYTES * 2:  # *2 for hex overhead
        bucket.setdefault(key_raw, []).append(hex_val)
        # Rough size estimate: hex chars / 2
        bucket[key_size] = bucket.get(key_size, 0) + len(hex_val) // 2


def build_http2_sessions(frames: list[dict]) -> list[dict]:
    """
    Group HTTP/2 frames by (tcp.stream, http2.streamid) and build one dict
    per request/response pair.

    Each result dict contains both the human-readable session metadata (for the
    CSV) and normalised HTTP/1.x-style keys so callers can pass the row straight
    into existing detection functions.
    """
    if not frames:
        return []

    # Phase 1 — accumulate per-stream state
    sessions: dict[tuple, dict] = {}

    for row in frames:
        key = _h2_key(row)
        tcp_stream = row.get("tcp.stream", "")
        h2_sid = row.get("http2.streamid", "")
        if not tcp_stream or not h2_sid or h2_sid == "0":
            continue

        frame_type_raw = (row.get("http2.type") or "").strip()
        try:
            frame_type = int(frame_type_raw)
        except ValueError:
            continue

        bucket = sessions.setdefault(key, {
            "tcp_stream": tcp_stream,
            "h2_stream_id": h2_sid,
        })

        if frame_type == _TYPE_HEADERS:
            method = (row.get("http2.headers.method") or "").strip()
            status = (row.get("http2.headers.status") or "").strip()

            if method and "request_method" not in bucket:
                # First request HEADERS for this stream
                bucket.update({
                    "request_method":   method,
                    "request_path":     (row.get("http2.headers.path") or "").strip(),
                    "authority":        (row.get("http2.headers.authority") or "").strip(),
                    "scheme":           (row.get("http2.headers.scheme") or "").strip(),
                    "user_agent":       (row.get("http2.headers.user_agent") or "").strip(),
                    "req_content_type": (row.get("http2.headers.content_type") or "").strip(),
                    "req_content_length": (row.get("http2.headers.content_length") or "").strip(),
                    "req_content_encoding": (row.get("http2.headers.content_encoding") or "").strip(),
                    "has_auth":         bool((row.get("http2.headers.authorization") or "").strip()),
                    "has_cookie":       bool((row.get("http2.headers.cookie") or "").strip()),
                    "client_ip":        row.get("ip.src", ""),
                    "client_port":      row.get("tcp.srcport", ""),
                    "server_ip":        row.get("ip.dst", ""),
                    "server_port":      row.get("tcp.dstport", ""),
                    "timestamp":        row.get("frame.time_epoch", ""),
                })
            elif status and "response_status" not in bucket:
                bucket.update({
                    "response_status":  status,
                    "resp_content_type": (row.get("http2.headers.content_type") or "").strip(),
                    "resp_content_length": (row.get("http2.headers.content_length") or "").strip(),
                    "resp_content_encoding": (row.get("http2.headers.content_encoding") or "").strip(),
                    "redirect_location": (row.get("http2.headers.location") or "").strip(),
                    "server_header":    (row.get("http2.headers.server") or "").strip(),
                })

        elif frame_type == _TYPE_DATA:
            data_hex = (row.get("http2.data.data") or "").strip()
            reassembled_hex = (row.get("http2.body.reassembled.data") or "").strip()

            client_ip = bucket.get("client_ip", "")
            src_ip = row.get("ip.src", "")
            direction = "request" if (src_ip == client_ip) else "response"

            _accumulate_body(bucket, direction, data_hex, reassembled_hex)

    # Phase 2 — flatten into CSV rows
    results = []
    for bucket in sessions.values():
        if "request_method" not in bucket and "response_status" not in bucket:
            continue  # stream with no readable HEADERS (e.g. PUSH_PROMISE)

        # Resolve bodies from accumulated or reassembled hex
        req_enc = bucket.get("req_content_encoding", "")
        resp_enc = bucket.get("resp_content_encoding", "")

        req_body = _decode_body_from_bucket(bucket, "request", req_enc)
        resp_body = _decode_body_from_bucket(bucket, "response", resp_enc)

        req_preview = ""
        if req_body and _looks_text(req_body):
            req_preview = req_body[:500].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")

        resp_preview = ""
        if resp_body and _looks_text(resp_body):
            resp_preview = resp_body[:200].decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")

        row = {
            "timestamp":            bucket.get("timestamp", ""),
            "src_ip":               bucket.get("client_ip", ""),
            "src_port":             bucket.get("client_port", ""),
            "dst_ip":               bucket.get("server_ip", ""),
            "dst_port":             bucket.get("server_port", ""),
            "tcp_stream":           bucket.get("tcp_stream", ""),
            "h2_stream_id":         bucket.get("h2_stream_id", ""),
            "method":               bucket.get("request_method", ""),
            "path":                 bucket.get("request_path", ""),
            "authority":            bucket.get("authority", ""),
            "scheme":               bucket.get("scheme", ""),
            "status_code":          bucket.get("response_status", ""),
            "user_agent":           bucket.get("user_agent", ""),
            "req_content_type":     bucket.get("req_content_type", ""),
            "resp_content_type":    bucket.get("resp_content_type", ""),
            "content_encoding":     resp_enc or req_enc,
            "resp_content_length":  bucket.get("resp_content_length", ""),
            "server":               bucket.get("server_header", ""),
            "has_auth":             "1" if bucket.get("has_auth") else "",
            "has_cookie":           "1" if bucket.get("has_cookie") else "",
            "redirect_location":    bucket.get("redirect_location", ""),
            "request_body_size":    str(len(req_body)) if req_body else "",
            "response_body_size":   str(len(resp_body)) if resp_body else "",
            "request_body_preview": req_preview,
            "response_body_preview": resp_preview,
            # Internal — used by extract_http2_bodies / build_http2_body_previews,
            # not written to CSV.
            "_request_body":        req_body,
            "_response_body":       resp_body,
        }

        # Normalised HTTP/1.x-style keys for detection functions
        row["http.request.method"] = row["method"]
        row["http.request.uri"]    = row["path"]
        row["http.host"]           = row["authority"]
        row["http.user_agent"]     = row["user_agent"]
        row["http.content_type"]   = row["resp_content_type"] or row["req_content_type"]
        row["http.response.code"]  = row["status_code"]
        row["http.file_data"]      = req_preview  # POST body preview for credential scan

        results.append(row)

    return results


def _decode_body_from_bucket(bucket: dict, direction: str, encoding: str) -> bytes | None:
    """Resolve bytes from a stream accumulator bucket, with decompression."""
    reassembled_hex = bucket.get(f"{direction}_reassembled", "")
    raw_parts = bucket.get(f"{direction}_raw", [])

    if reassembled_hex:
        raw = _decode_h2_bytes(reassembled_hex)
    elif raw_parts:
        raw = b"".join(_decode_h2_bytes(h) for h in raw_parts)
    else:
        return None

    if not raw:
        return None

    return _decompress(raw, encoding)


# ---------------------------------------------------------------------------
# Body file extraction
# ---------------------------------------------------------------------------

_BODY_CSV_FIELDS = [
    "tcp_stream", "h2_stream_id", "direction",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "method", "path", "authority", "status_code",
    "content_type", "output_file", "filename",
    "is_text", "size_bytes", "sha256", "entropy",
    "detected_file_type", "detected_extension", "preview",
    "source",
]


def extract_http2_bodies(
    sessions: list[dict],
    output_dir: Path,
    max_body_bytes: int = MAX_BODY_BYTES,
) -> list[dict]:
    """
    Write decompressed HTTP/2 body files and return extracted_payloads-compatible records.

    Extracts both response bodies and request bodies (POST/PUT).
    Files go into output_dir/http2_bodies/.
    """
    from modules.payloads import detect_file_signature, looks_mostly_text, decode_lossy, shannon_entropy

    bodies_dir = output_dir / "http2_bodies"
    results: list[dict] = []
    counter = 0

    for session in sessions:
        for direction in ("response", "request"):
            body: bytes | None = session.get(f"_{direction}_body")
            if not body:
                continue
            if len(body) > max_body_bytes:
                body = body[:max_body_bytes]  # truncate oversized bodies

            method = session.get("method", "")
            # Only extract request bodies for methods that typically have one
            if direction == "request" and method.upper() not in ("POST", "PUT", "PATCH"):
                continue

            content_type = (
                session.get("resp_content_type", "") if direction == "response"
                else session.get("req_content_type", "")
            )

            file_type, detected_ext = detect_file_signature(body)
            is_text = looks_mostly_text(body)

            ext = detected_ext or (".txt" if is_text else ".bin")
            filename = (
                f"h2_stream{session['tcp_stream']}"
                f"_h2s{session['h2_stream_id']}"
                f"_{direction}{counter:04d}{ext}"
            )
            bodies_dir.mkdir(parents=True, exist_ok=True)
            out_path = bodies_dir / filename
            out_path.write_bytes(body)

            preview = ""
            if is_text:
                preview = decode_lossy(body[:200]).replace("\r", " ").replace("\n", " ")

            results.append({
                "tcp_stream":           session["tcp_stream"],
                "h2_stream_id":         session["h2_stream_id"],
                "direction":            direction,
                "src_ip":               session.get("src_ip", ""),
                "src_port":             session.get("src_port", ""),
                "dst_ip":               session.get("dst_ip", ""),
                "dst_port":             session.get("dst_port", ""),
                "method":               method,
                "path":                 session.get("path", ""),
                "authority":            session.get("authority", ""),
                "status_code":          session.get("status_code", "") if direction == "response" else "",
                "content_type":         content_type,
                "output_file":          str(out_path),
                "filename":             filename,
                "is_text":              is_text,
                "size_bytes":           len(body),
                "sha256":               _sha256_hex(body),
                "entropy":              round(_entropy(body[:4096]), 3),
                "detected_file_type":   file_type,
                "detected_extension":   detected_ext,
                "preview":              preview,
                "source":               "http2_body",
                # Keys that downstream detection functions expect
                "ascii_stream_file":    "",
                "raw_stream_file":      "",
                "original_filename":    "",
                "form_field_name":      "",
                "used_raw_bytes":       True,
            })
            counter += 1

    return results


# ---------------------------------------------------------------------------
# Body previews for credential detection
# ---------------------------------------------------------------------------

def build_http2_body_previews(sessions: list[dict]) -> list[dict]:
    """
    Return HTTP/1.x-style body preview dicts for POST/PUT requests.
    Compatible with find_credential_indicators().
    """
    previews = []
    for session in sessions:
        method = (session.get("method") or "").upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        body: bytes | None = session.get("_request_body")
        if not body:
            file_data = session.get("request_body_preview", "")
        else:
            try:
                file_data = body[:500].decode("utf-8", errors="replace")
            except Exception:
                file_data = ""
        if not file_data:
            continue
        previews.append({
            "http_method":    method,
            "host":           session.get("authority", ""),
            "uri":            session.get("path", ""),
            "content_type":   session.get("req_content_type", ""),
            "content_length": session.get("resp_content_length", ""),
            "file_data":      file_data,
            "src_ip":         session.get("src_ip", ""),
        })
    return previews


# ---------------------------------------------------------------------------
# CSV column list (internal keys stripped)
# ---------------------------------------------------------------------------

HTTP2_CSV_COLUMNS = [
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
    "tcp_stream", "h2_stream_id", "method", "path", "authority", "scheme",
    "status_code", "user_agent", "req_content_type", "resp_content_type",
    "content_encoding", "resp_content_length", "server",
    "has_auth", "has_cookie", "redirect_location",
    "request_body_size", "response_body_size",
    "request_body_preview", "response_body_preview",
]
