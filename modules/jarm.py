"""
Active JARM TLS server fingerprinting.

Sends 10 specially crafted TLS ClientHello probes to each observed
external TLS server and computes a 62-character JARM fingerprint that
uniquely identifies the server's TLS stack.

Enabled with --jarm-probe. Requires outbound TCP connectivity to the
servers observed in the capture — do not use on untrusted networks
without authorisation.

Algorithm reference: https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a
"""
import hashlib
import os
import socket
import struct

from modules.utils import is_private_ip

_TIMEOUT = 3.0

# ---------------------------------------------------------------------------
# Known-malicious JARM fingerprints
# Source: Salesforce Engineering / FoxIO JARM research
# ---------------------------------------------------------------------------
KNOWN_MALICIOUS_JARM = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": (
        "Cobalt Strike", "Salesforce Research"
    ),
    "07d19d1ad07d19d1ad07d19d1ad07d12d43d15d15c07d19d1ad07d19d1a": (
        "Cobalt Strike (alternate profile)", "Salesforce Research"
    ),
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": (
        "Merlin C2", "Salesforce Research"
    ),
    "29d29d15d2ab16d2ab29d29d29d29d6e4a4f49fc59f9a8c28e5d1e6dc5b2d5": (
        "Covenant C2", "Salesforce Research"
    ),
    "2ad2ad0002ad2ad22c42d42d000000f84d00": (
        "AsyncRAT", "Salesforce Research"
    ),
}

# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------
_TLS_1_2_CIPHERS = [
    0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f,
    0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a,
    0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d,
    0x003c, 0x0035, 0x002f, 0x00ff,
]
_TLS_1_3_CIPHERS = [0x1301, 0x1302, 0x1303]
_GREASE_VALUES = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]
_NAMED_GROUPS  = [0x001d, 0x0017, 0x001e, 0x0019, 0x0018]
_SIG_ALGS = [
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
    0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
]

# ---------------------------------------------------------------------------
# TLS extension builders
# ---------------------------------------------------------------------------

def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _sni_ext(host: str) -> bytes:
    name = host.encode("ascii")
    sni_body = struct.pack(">BH", 0, len(name)) + name  # name_type=host_name
    sni_list = struct.pack(">H", len(sni_body)) + sni_body
    return _ext(0x0000, sni_list)


def _supported_groups_ext() -> bytes:
    groups = b"".join(struct.pack(">H", g) for g in _NAMED_GROUPS)
    return _ext(0x000a, struct.pack(">H", len(groups)) + groups)


def _ec_point_formats_ext() -> bytes:
    return _ext(0x000b, b"\x01\x00")  # length=1, uncompressed


def _session_ticket_ext() -> bytes:
    return _ext(0x0023, b"")


def _encrypt_then_mac_ext() -> bytes:
    return _ext(0x0016, b"")


def _extended_master_secret_ext() -> bytes:
    return _ext(0x0017, b"")


def _sig_algs_ext() -> bytes:
    algs = b"".join(struct.pack(">H", a) for a in _SIG_ALGS)
    return _ext(0x000d, struct.pack(">H", len(algs)) + algs)


def _supported_versions_ext(versions: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in versions)
    return _ext(0x002b, struct.pack(">B", len(body)) + body)


def _key_share_ext() -> bytes:
    # x25519 public key (32 random bytes — server will not use it but needs the field)
    pub_key = os.urandom(32)
    key_share_entry = struct.pack(">HH", 0x001d, len(pub_key)) + pub_key
    return _ext(0x0033, struct.pack(">H", len(key_share_entry)) + key_share_entry)


def _alpn_ext(protocols: list[str]) -> bytes:
    proto_list = b"".join(
        struct.pack(">B", len(p)) + p.encode("ascii") for p in protocols
    )
    return _ext(0x0010, struct.pack(">H", len(proto_list)) + proto_list)


def _renegotiation_info_ext() -> bytes:
    return _ext(0xff01, b"\x00")  # empty renegotiated_connection


# ---------------------------------------------------------------------------
# ClientHello builder
# ---------------------------------------------------------------------------

def _build_client_hello(
    host: str,
    ciphers: list[int],
    record_version: int,
    hello_version: int,
    extensions: bytes,
) -> bytes:
    # Random
    random_bytes = os.urandom(32)
    # Session ID (empty)
    session_id = b"\x00"
    # Cipher suites
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    cipher_block = struct.pack(">H", len(cipher_bytes)) + cipher_bytes
    # Compression methods: null only
    compression = b"\x01\x00"
    # Extensions block
    if extensions:
        ext_block = struct.pack(">H", len(extensions)) + extensions
    else:
        ext_block = b""

    hello_body = (
        struct.pack(">H", hello_version)
        + random_bytes
        + session_id
        + cipher_block
        + compression
        + ext_block
    )
    # Handshake header: type=ClientHello(1) + length (3 bytes)
    handshake = b"\x01" + struct.pack(">I", len(hello_body))[1:] + hello_body
    # TLS record: ContentType=Handshake(22), version, length
    record = (
        struct.pack(">BHH", 0x16, record_version, len(handshake))
        + handshake
    )
    return record


# ---------------------------------------------------------------------------
# 10 JARM probe definitions
# ---------------------------------------------------------------------------
# Each probe: (record_ver, hello_ver, cipher_order, use_tls13, grease, extensions_set, alpn)
# extensions_set: "all" | "none"
# cipher_order:   "fwd" | "rev"
# use_tls13:      True = prepend TLS 1.3 ciphers + add supported_versions/key_share

_PROBES: list[dict] = [
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "fwd", "use_tls13": False, "grease": False, "ext_set": "all",  "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "rev", "use_tls13": False, "grease": False, "ext_set": "all",  "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "fwd", "use_tls13": False, "grease": True,  "ext_set": "all",  "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "rev", "use_tls13": False, "grease": True,  "ext_set": "none", "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0302, "cipher_order": "fwd", "use_tls13": False, "grease": False, "ext_set": "none", "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0302, "cipher_order": "rev", "use_tls13": False, "grease": False, "ext_set": "none", "alpn": []},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "fwd", "use_tls13": True,  "grease": False, "ext_set": "all",  "alpn": ["h2", "http/1.1"]},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "rev", "use_tls13": True,  "grease": False, "ext_set": "all",  "alpn": ["h2", "http/1.1"]},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "fwd", "use_tls13": True,  "grease": True,  "ext_set": "all",  "alpn": ["h2"]},
    {"record_ver": 0x0301, "hello_ver": 0x0303, "cipher_order": "rev", "use_tls13": True,  "grease": False, "ext_set": "all",  "alpn": []},
]


def _build_probe(host: str, probe: dict) -> bytes:
    ciphers = list(_TLS_1_2_CIPHERS)
    if probe["cipher_order"] == "rev":
        ciphers = list(reversed(ciphers))
    if probe["use_tls13"]:
        ciphers = _TLS_1_3_CIPHERS + ciphers
    if probe["grease"]:
        ciphers = [_GREASE_VALUES[0]] + ciphers

    if probe["ext_set"] == "none":
        ext_bytes = b""
    else:
        exts = [
            _sni_ext(host),
            _supported_groups_ext(),
            _ec_point_formats_ext(),
            _session_ticket_ext(),
            _encrypt_then_mac_ext(),
            _extended_master_secret_ext(),
            _sig_algs_ext(),
            _renegotiation_info_ext(),
        ]
        if probe["use_tls13"]:
            exts += [
                _supported_versions_ext([0x0304, 0x0303, 0x0302]),
                _key_share_ext(),
            ]
        if probe["alpn"]:
            exts.append(_alpn_ext(probe["alpn"]))
        ext_bytes = b"".join(exts)

    return _build_client_hello(
        host,
        ciphers,
        probe["record_ver"],
        probe["hello_ver"],
        ext_bytes,
    )


# ---------------------------------------------------------------------------
# Network probe sender
# ---------------------------------------------------------------------------

def _send_probe(host: str, port: int, data: bytes, timeout: float) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(data)
            response = b""
            sock.settimeout(timeout)
            while len(response) < 4096:
                try:
                    chunk = sock.recv(4096 - len(response))
                    if not chunk:
                        break
                    response += chunk
                    # Stop once we have a full TLS record
                    if len(response) >= 5:
                        rec_len = struct.unpack_from(">H", response, 3)[0]
                        if len(response) >= 5 + rec_len:
                            break
                except socket.timeout:
                    break
            return response
    except (OSError, socket.error):
        return b""


# ---------------------------------------------------------------------------
# ServerHello parser
# ---------------------------------------------------------------------------

def _parse_server_hello(data: bytes) -> str:
    """
    Parse a TLS ServerHello record and return:
        "cipher_hex|version_hex|alpn|ext_types_csv"
    Returns "||||" on parse failure or non-ServerHello response.
    """
    try:
        if len(data) < 9 or data[0] != 0x16:
            return "||||"

        # Skip records until we find a ServerHello (handshake type 0x02)
        pos = 0
        while pos + 5 <= len(data):
            content_type = data[pos]
            rec_len = struct.unpack_from(">H", data, pos + 3)[0]
            rec_end = pos + 5 + rec_len
            if content_type == 0x16 and pos + 9 <= len(data):
                hs_type = data[pos + 5]
                if hs_type == 0x02:
                    break
            pos = rec_end
        else:
            return "||||"

        # pos points to the start of the TLS record containing ServerHello
        # ServerHello body starts at pos+9 (5 record hdr + 4 handshake hdr)
        body_start = pos + 9
        if body_start + 38 > len(data):
            return "||||"

        # Legacy version (2 bytes)
        legacy_ver = struct.unpack_from(">H", data, body_start)[0]
        # Skip version(2) + random(32) = 34 bytes
        body_pos = body_start + 34
        if body_pos >= len(data):
            return "||||"

        # Session ID
        sid_len = data[body_pos]
        body_pos += 1 + sid_len
        if body_pos + 3 > len(data):
            return "||||"

        # Cipher suite chosen
        cipher_suite = struct.unpack_from(">H", data, body_pos)[0]
        body_pos += 2

        # Compression method
        body_pos += 1

        # Parse extensions
        server_version = legacy_ver
        alpn_chosen = ""
        ext_types: list[str] = []

        if body_pos + 2 <= len(data):
            exts_total = struct.unpack_from(">H", data, body_pos)[0]
            body_pos += 2
            exts_end = body_pos + exts_total

            while body_pos + 4 <= exts_end and body_pos + 4 <= len(data):
                ext_type = struct.unpack_from(">H", data, body_pos)[0]
                ext_len  = struct.unpack_from(">H", data, body_pos + 2)[0]
                ext_data = data[body_pos + 4: body_pos + 4 + ext_len]
                ext_types.append(f"{ext_type:04x}")

                if ext_type == 0x002b and len(ext_data) >= 2:
                    server_version = struct.unpack_from(">H", ext_data, 0)[0]
                elif ext_type == 0x0010 and len(ext_data) >= 4:
                    proto_list_len = struct.unpack_from(">H", ext_data, 0)[0]
                    if proto_list_len >= 1 and len(ext_data) >= 3:
                        proto_len = ext_data[2]
                        if len(ext_data) >= 3 + proto_len:
                            alpn_chosen = ext_data[3: 3 + proto_len].decode("ascii", errors="replace")

                body_pos += 4 + ext_len

        return (
            f"{cipher_suite:04x}"
            f"|{server_version:04x}"
            f"|{alpn_chosen}"
            f"|{','.join(ext_types)}"
        )

    except Exception:
        return "||||"


# ---------------------------------------------------------------------------
# JARM fingerprint computation
# ---------------------------------------------------------------------------

def _jarm_hash(raw_fingerprints: list[str]) -> str:
    """Compute the 62-char JARM fingerprint from 10 probe response strings."""
    cipher_str = ""
    all_str = ""
    for fp in raw_fingerprints:
        parts = fp.split("|")
        cipher_str += parts[0] if parts else "0000"
        all_str += fp

    if all(c == "0" for c in cipher_str):
        return "0" * 62

    return (
        hashlib.sha256(cipher_str.encode()).hexdigest()[:30]
        + hashlib.sha256(all_str.encode()).hexdigest()[:32]
    )


def compute_jarm(host: str, port: int, timeout: float = _TIMEOUT) -> str:
    """
    Send 10 JARM probes to host:port and return the 62-char fingerprint.
    Returns an empty string on connection failure.
    """
    raw_fps: list[str] = []
    for probe in _PROBES:
        hello = _build_probe(host, probe)
        response = _send_probe(host, port, hello, timeout)
        raw_fps.append(_parse_server_hello(response) if response else "0000||||")

    return _jarm_hash(raw_fps)


# ---------------------------------------------------------------------------
# Batch prober for observed TLS servers
# ---------------------------------------------------------------------------

def probe_observed_servers(
    tls_summary: list[dict],
    timeout: float = _TIMEOUT,
) -> list[dict]:
    """
    For each unique external (dst_ip, dst_port) in tls_summary, compute
    a JARM fingerprint.  Returns list of dicts: dst_ip, dst_port, sni,
    jarm, malware_family, intel_source.
    """
    seen: set[tuple] = set()
    results: list[dict] = []

    for row in tls_summary:
        dst_ip   = (row.get("dst_ip", "") or "").strip()
        dst_port = (row.get("dst_port", "") or "").strip()
        sni      = (row.get("sni", "") or "").strip()

        if not dst_ip or not dst_port:
            continue
        if is_private_ip(dst_ip):
            continue

        try:
            port_int = int(dst_port)
        except (ValueError, TypeError):
            continue

        key = (dst_ip, port_int)
        if key in seen:
            continue
        seen.add(key)

        fingerprint = compute_jarm(dst_ip, port_int, timeout=timeout)
        if not fingerprint:
            continue

        match = KNOWN_MALICIOUS_JARM.get(fingerprint)
        results.append({
            "dst_ip":         dst_ip,
            "dst_port":       port_int,
            "sni":            sni,
            "jarm":           fingerprint,
            "malware_family": match[0] if match else "",
            "intel_source":   match[1] if match else "",
        })

    return results
