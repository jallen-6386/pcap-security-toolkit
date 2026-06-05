"""
JA4+ fingerprinting support.

JA4  — TLS Client fingerprint (FoxIO, 2023)
JA4S — TLS Server fingerprint
JA4H — HTTP Client fingerprint

References:
  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md

JA4 is preferred over JA3 because:
  - Grease-aware (GREASE values are excluded before hashing)
  - Version-aware (uses supported_versions extension, not record-layer version)
  - Alphanumeric-sortable — the first part is human-readable at a glance
  - Produces two independent hashes (cipher-only, then ext+sigalg) which
    allows partial matching when one component changes

TShark native support:
  tls.handshake.ja4  — requires Wireshark 4.4.0+
  tls.handshake.ja4s — requires Wireshark 4.4.0+

When TShark does not populate these fields, this module computes them from
the raw TLS ClientHello fields using a separate tab-delimited TShark pass.

JA4H does not depend on TShark version. It is computed directly from
the ASCII stream export produced by --export-streams.
"""

import csv
import hashlib
import io
import re
import subprocess
from pathlib import Path

from modules.dependencies import find_tshark
from modules.tshark_config import decode_as_args


# ---------------------------------------------------------------------------
# GREASE (RFC 8701) values — excluded from all JA4 hashes
# ---------------------------------------------------------------------------

_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# ---------------------------------------------------------------------------
# TLS version map  (supported_versions or ClientHello.version field)
# ---------------------------------------------------------------------------

_TLS_VERSION_MAP = {
    "0304": "13",   # TLS 1.3
    "0303": "12",   # TLS 1.2
    "0302": "11",   # TLS 1.1
    "0301": "10",   # TLS 1.0
    "0300": "s3",   # SSL 3.0
    "0200": "s2",   # SSL 2.0
    "feff": "d1",   # DTLS 1.0
    "fefd": "d2",   # DTLS 1.2
    "fefc": "d3",   # DTLS 1.3
}

# ---------------------------------------------------------------------------
# HTTP version map for JA4H
# ---------------------------------------------------------------------------

_HTTP_VERSION_MAP = {
    "http/1.0": "10",
    "http/1.1": "11",
    "http/2.0": "20",
    "http/2":   "20",
    "http/3.0": "30",
    "http/3":   "30",
}

# Headers excluded from the JA4H sorted-header hash (per FoxIO spec)
_JA4H_EXCLUDE_FROM_HASH = {"cookie"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_hex(value: str) -> int | None:
    """Parse a hex value (with or without '0x' prefix) to int. Returns None on failure."""
    v = value.strip().lower().lstrip("0x")
    if not v:
        return None
    try:
        return int(v, 16)
    except ValueError:
        return None


def _sha256_12(s: str) -> str:
    """SHA-256 of a string, first 12 hex characters."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _parse_int_list(raw: str) -> list[int]:
    """Split a comma-separated hex string into a list of ints, skipping blanks."""
    result = []
    for part in raw.split(","):
        n = _parse_hex(part)
        if n is not None:
            result.append(n)
    return result


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE]


# ---------------------------------------------------------------------------
# JA4 computation
# ---------------------------------------------------------------------------

def compute_ja4(
    handshake_type: str,
    tls_version_hex: str,
    supported_versions_raw: str,
    sni: str,
    ciphersuites_raw: str,
    extensions_raw: str,
    alpn_raw: str,
    sig_algs_raw: str,
    protocol: str = "t",
) -> str:
    """
    Compute a JA4 fingerprint per the FoxIO specification.

    Returns an empty string if handshake_type is not "1" (ClientHello).

    Args:
        handshake_type:        TLS handshake type ("1" = ClientHello).
        tls_version_hex:       Record-layer version (e.g. "0x0303").
        supported_versions_raw: Comma-separated hex values from the
                               supported_versions extension (e.g. "0x0304,0x0303").
        sni:                   SNI hostname from the server_name extension.
        ciphersuites_raw:      Comma-separated hex cipher suite values.
        extensions_raw:        Comma-separated hex extension type values.
        alpn_raw:              Comma-separated ALPN protocol strings.
        sig_algs_raw:          Comma-separated hex signature algorithm values.
        protocol:              "t" for TCP/TLS, "q" for QUIC.
    """
    if str(handshake_type).strip() != "1":
        return ""

    # --- TLS version ---
    # Prefer highest non-GREASE value from supported_versions extension.
    best_ver = "00"
    if supported_versions_raw and supported_versions_raw.strip():
        sv_ints = _filter_grease(_parse_int_list(supported_versions_raw))
        sv_valid = sorted(
            [v for v in sv_ints if v > 0x0200],
            reverse=True,
        )
        if sv_valid:
            best_ver = _TLS_VERSION_MAP.get(f"{sv_valid[0]:04x}", "00")

    if best_ver == "00" and tls_version_hex and tls_version_hex.strip():
        normalized = tls_version_hex.strip().lower().lstrip("0x").zfill(4)
        best_ver = _TLS_VERSION_MAP.get(normalized, "00")

    # --- SNI indicator ---
    sni = (sni or "").strip()
    sni_flag = (
        "d"
        if sni and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", sni)
        else "i"
    )

    # --- Cipher suites (non-GREASE) ---
    cs_ints = _filter_grease(_parse_int_list(ciphersuites_raw or ""))
    num_ciphers = len(cs_ints)

    # --- Extensions (non-GREASE) ---
    ext_ints = _filter_grease(_parse_int_list(extensions_raw or ""))
    num_extensions = len(ext_ints)

    # --- ALPN first value (first 2 chars) ---
    alpn_val = "00"
    if alpn_raw and alpn_raw.strip():
        first_alpn = alpn_raw.split(",")[0].strip()
        if len(first_alpn) >= 2:
            alpn_val = first_alpn[:2]
        elif len(first_alpn) == 1:
            alpn_val = first_alpn + "0"

    # --- Part A (human-readable prefix) ---
    part_a = f"{protocol}{best_ver}{sni_flag}{num_ciphers:02d}{num_extensions:02d}{alpn_val}"

    # --- Part B: sorted cipher suites → SHA-256[:12] ---
    cs_sorted_hex = ",".join(f"{c:04x}" for c in sorted(cs_ints))
    part_b = _sha256_12(cs_sorted_hex)

    # --- Part C: sorted extensions + "_" + sig algs → SHA-256[:12] ---
    ext_sorted_hex = ",".join(f"{e:04x}" for e in sorted(ext_ints))
    sig_ints = _parse_int_list(sig_algs_raw or "")
    sig_hex = ",".join(f"{s:04x}" for s in sig_ints)
    part_c = _sha256_12(f"{ext_sorted_hex}_{sig_hex}")

    return f"{part_a}_{part_b}_{part_c}"


# ---------------------------------------------------------------------------
# Raw TLS handshake field extraction (fallback when TShark < 4.4)
# ---------------------------------------------------------------------------

def extract_tls_handshake_raw_for_ja4(pcap_path) -> tuple[list[dict], str | None]:
    """
    Extract raw TLS ClientHello fields using a tab-delimited TShark pass.
    The tab separator avoids conflicts with comma-separated multi-value fields
    (cipher suites, extension types, signature algorithms).

    Used as a fallback when TShark does not natively support tls.handshake.ja4.
    """
    tshark_path = find_tshark()
    if not tshark_path:
        return [], "TShark not found"

    fields = [
        "frame.time",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "tls.handshake.type",
        "tls.handshake.version",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "tls.handshake.extension.type",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.sig_hash_alg",
    ]

    cmd = [
        tshark_path, "-n", *decode_as_args(), "-r", str(pcap_path),
        "-T", "fields",
        "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    # Tab between fields; comma between multiple values of the same field.
    cmd.extend(["-E", "header=y", "-E", "separator=\t", "-E", "aggregator=,", "-E", "quote=n"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return [], result.stderr.strip()

    reader = csv.DictReader(io.StringIO(result.stdout), delimiter="\t")
    return list(reader), None


def enrich_tls_summary_with_ja4(tls_summary: list[dict], pcap_path) -> list[dict]:
    """
    Ensure every row in tls_summary has a populated ja4 field.

    Priority:
      1. Use ja4 value already extracted natively by TShark (4.4+).
      2. Compute ja4 from raw ClientHello fields via Python fallback.

    Modifies tls_summary in-place and also returns it.
    """
    if not tls_summary:
        return tls_summary

    # If any row already has a non-empty native JA4, TShark supports it —
    # use native values for all rows and skip computation.
    has_native = any((r.get("ja4") or "").strip() for r in tls_summary)
    if has_native:
        return tls_summary

    raw_rows, err = extract_tls_handshake_raw_for_ja4(pcap_path)
    if err or not raw_rows:
        return tls_summary

    # Build a map: tcp_stream → computed ja4 (first ClientHello per stream)
    stream_ja4: dict[str, str] = {}
    for row in raw_rows:
        handshake_type = (row.get("tls.handshake.type") or "").strip()
        tcp_stream = (row.get("tcp.stream") or "").strip()
        if not tcp_stream or handshake_type != "1":
            continue
        if tcp_stream in stream_ja4:
            continue

        ja4 = compute_ja4(
            handshake_type=handshake_type,
            tls_version_hex=row.get("tls.handshake.version", ""),
            supported_versions_raw=row.get("tls.handshake.extensions.supported_version", ""),
            sni=row.get("tls.handshake.extensions_server_name", ""),
            ciphersuites_raw=row.get("tls.handshake.ciphersuite", ""),
            extensions_raw=row.get("tls.handshake.extension.type", ""),
            alpn_raw=row.get("tls.handshake.extensions_alpn_str", ""),
            sig_algs_raw=row.get("tls.handshake.sig_hash_alg", ""),
        )
        if ja4:
            stream_ja4[tcp_stream] = ja4

    for row in tls_summary:
        tcp_stream = (row.get("tcp_stream") or "").strip()
        if not row.get("ja4") and tcp_stream in stream_ja4:
            row["ja4"] = stream_ja4[tcp_stream]
            row["ja4_source"] = "computed"
        elif row.get("ja4"):
            row["ja4_source"] = "tshark_native"
        else:
            row["ja4_source"] = ""

    return tls_summary


# ---------------------------------------------------------------------------
# JA4H — HTTP Client fingerprint
# ---------------------------------------------------------------------------

def compute_ja4h(stream_text: str) -> str:
    """
    Compute a JA4H fingerprint from a raw ASCII HTTP request stream.

    JA4H captures the HTTP client implementation independent of the User-Agent
    header, making it useful for detecting browser impersonation by malware.

    Returns empty string if the text does not contain a valid HTTP request.
    """
    lines = stream_text.replace("\r\n", "\n").split("\n")
    if not lines:
        return ""

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 3:
        return ""

    method_raw = parts[0].upper()
    http_ver_raw = parts[-1].lower()

    method = method_raw[:2].lower()
    http_ver = _HTTP_VERSION_MAP.get(http_ver_raw, "11")

    # Parse headers
    header_names: list[str] = []
    cookie_field_names: list[str] = []
    accept_lang = "0000"
    has_cookie = False
    has_referer = False

    for line in lines[1:]:
        line = line.strip()
        if not line:
            break
        if ":" not in line:
            continue

        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        name_lower = name.lower()

        header_names.append(name)

        if name_lower == "cookie":
            has_cookie = True
            for pair in value.split(";"):
                field = pair.strip().split("=")[0].strip()
                if field:
                    cookie_field_names.append(field)

        elif name_lower == "referer":
            has_referer = True

        elif name_lower == "accept-language":
            # First 4 chars of the value, lowercased, zero-padded
            lang_val = value[:4].lower() if value else ""
            accept_lang = lang_val.ljust(4, "0")[:4]

    cookie_flag = "c" if has_cookie else "n"
    referer_flag = "r" if has_referer else "n"
    header_count = len(header_names)

    # Part A (human-readable prefix)
    part_a = f"{method}{http_ver}{cookie_flag}{referer_flag}{header_count:02d}{accept_lang}"

    # Part B: sorted lowercase header names (excluding Cookie) → SHA-256[:12]
    sorted_headers = sorted(
        h.lower()
        for h in header_names
        if h.lower() not in _JA4H_EXCLUDE_FROM_HASH
    )
    part_b = _sha256_12(",".join(sorted_headers)) if sorted_headers else "0" * 12

    # Part C: sorted cookie field names → SHA-256[:12]
    if cookie_field_names:
        sorted_cookies = sorted(f.lower() for f in cookie_field_names)
        part_c = _sha256_12(",".join(sorted_cookies))
    else:
        part_c = "0" * 12

    return f"{part_a}_{part_b}_{part_c}"


def compute_ja4h_rows(
    streams_dir: Path,
    tcp_stream_rows: list[dict],
) -> list[dict]:
    """
    Compute JA4H fingerprints for all exported ASCII streams.

    Returns one row per HTTP session found in the exported streams.
    Only processes files matching tcp_stream_*.ascii.txt.
    """
    if not streams_dir or not streams_dir.exists():
        return []

    # Build stream metadata lookup
    stream_lookup: dict[str, dict] = {}
    for row in tcp_stream_rows:
        sid = (row.get("tcp.stream") or "").strip()
        if sid and sid not in stream_lookup:
            stream_lookup[sid] = {
                "src_ip": row.get("ip.src", ""),
                "src_port": row.get("tcp.srcport", ""),
                "dst_ip": row.get("ip.dst", ""),
                "dst_port": row.get("tcp.dstport", ""),
            }

    results = []
    http_request_re = re.compile(
        r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP/\d",
        re.IGNORECASE | re.MULTILINE,
    )

    for ascii_file in sorted(streams_dir.glob("tcp_stream_*.ascii.txt")):
        try:
            content = ascii_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        if not http_request_re.search(content):
            continue

        sid_match = re.search(r"tcp_stream_(\d+)", ascii_file.name)
        tcp_stream = sid_match.group(1) if sid_match else "unknown"
        meta = stream_lookup.get(
            tcp_stream,
            {"src_ip": "", "src_port": "", "dst_ip": "", "dst_port": ""},
        )

        # Split on HTTP request boundaries to handle keep-alive streams
        # with multiple requests
        segments = re.split(
            r"(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP/\d)",
            content,
            flags=re.IGNORECASE,
        )

        seen_fp: set[str] = set()
        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue
            if not http_request_re.match(segment):
                continue

            ja4h = compute_ja4h(segment)
            if not ja4h or ja4h in seen_fp:
                continue
            seen_fp.add(ja4h)

            # Extract method and host for context
            first_line = segment.split("\n")[0].strip()
            req_parts = first_line.split()
            method = req_parts[0].upper() if req_parts else ""
            uri = req_parts[1] if len(req_parts) > 1 else ""

            host = ""
            for line in segment.split("\n")[1:20]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            results.append({
                "tcp_stream": tcp_stream,
                "src_ip": meta["src_ip"],
                "src_port": meta["src_port"],
                "dst_ip": meta["dst_ip"],
                "dst_port": meta["dst_port"],
                "http_method": method,
                "http_host": host,
                "http_uri": uri[:200],
                "ja4h": ja4h,
            })

    return results
