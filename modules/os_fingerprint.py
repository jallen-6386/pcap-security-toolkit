"""
Passive OS fingerprinting from TCP SYN packet characteristics.

Matches TTL, TCP window size, and MSS against known OS signatures
to produce a best-guess OS label for each observed source IP.
No active probing — entirely derived from SYN packets in the capture.
"""

# Signature format: (os_name, ttl_min, ttl_max, window_size, mss_or_0)
# mss_or_0 = 0 means any MSS is acceptable for this signature
_OS_SIGNATURES = [
    ("Windows 10/11",       120, 128, 64240, 1460),
    ("Windows 10/11",       120, 128, 65535, 1460),
    ("Windows 10/11",       120, 128, 65535,    0),
    ("Windows 7/8",         120, 128,  8192, 1460),
    ("Windows Server",      120, 128, 65535,    0),
    ("Linux 5.x",            60,  64, 64240, 1460),
    ("Linux 4.x",            60,  64, 29200, 1460),
    ("Linux 2.6.x",          60,  64,  5840, 1460),
    ("Linux 2.4.x",          60,  64, 32120, 1460),
    ("macOS / iOS",          60,  64, 65535, 1460),
    ("macOS / iOS",          60,  64, 65535,    0),
    ("FreeBSD",              60,  64, 65535, 1460),
    ("OpenBSD",              60,  64, 16384, 1460),
    ("Android",              60,  64, 65535, 1460),
    ("Cisco IOS",           251, 255,  4096,    0),
    ("Cisco IOS",           251, 255,  4128,  536),
    ("Solaris",             251, 255,  8760, 1460),
]


def _match_os(ttl: int, window: int, mss: int) -> str:
    exact = None
    partial = None
    for name, ttl_min, ttl_max, sig_win, sig_mss in _OS_SIGNATURES:
        if not (ttl_min <= ttl <= ttl_max and sig_win == window):
            continue
        if mss and sig_mss and sig_mss == mss:
            exact = name
            break
        if sig_mss == 0 and partial is None:
            partial = name
    return exact or partial or "Unknown"


def fingerprint_hosts(syn_rows: list[dict]) -> list[dict]:
    """
    Return one OS fingerprint record per observed source IP.
    Uses the first SYN seen from each source to avoid duplicates.
    """
    seen: dict[str, dict] = {}

    for row in syn_rows:
        src = (row.get("ip.src", "") or "").strip()
        if not src or src in seen:
            continue

        try:
            ttl    = int(row.get("ip.ttl", 0) or 0)
            window = int(row.get("tcp.window_size_value", 0) or 0)
        except (ValueError, TypeError):
            continue

        if not ttl or not window:
            continue

        try:
            mss    = int(row.get("tcp.options.mss_val", 0) or 0)
        except (ValueError, TypeError):
            mss = 0

        try:
            wscale = int(row.get("tcp.options.wscale.multiplier", 0) or 0)
        except (ValueError, TypeError):
            wscale = 0

        seen[src] = {
            "src_ip": src,
            "dst_ip": (row.get("ip.dst", "") or "").strip(),
            "os_guess": _match_os(ttl, window, mss),
            "ttl": ttl,
            "window_size": window,
            "mss": mss,
            "wscale": wscale,
            "timestamp": row.get("frame.time", ""),
        }

    return list(seen.values())
