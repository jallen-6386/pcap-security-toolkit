from ipaddress import ip_address, ip_network

PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

# Special-use ranges that are never real, attributable public hosts. Traffic to
# these should not become an IOC or count as an "external" target, but they are
# distinct from RFC1918 private space, so they are kept out of PRIVATE_NETS.
SPECIAL_USE_NETS = [
    ip_network("0.0.0.0/8"),         # "this host" / unspecified
    ip_network("100.64.0.0/10"),     # carrier-grade NAT (RFC 6598)
    ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ip_network("192.0.2.0/24"),      # TEST-NET-1 documentation (RFC 5737)
    ip_network("198.18.0.0/15"),     # benchmarking (RFC 2544)
    ip_network("198.51.100.0/24"),   # TEST-NET-2 documentation (RFC 5737)
    ip_network("203.0.113.0/24"),    # TEST-NET-3 documentation (RFC 5737)
    ip_network("224.0.0.0/4"),       # multicast
    ip_network("240.0.0.0/4"),       # reserved/future use (incl. 255.255.255.255)
    ip_network("::/128"),            # unspecified
    ip_network("2001:db8::/32"),     # documentation (RFC 3849)
    ip_network("ff00::/8"),          # IPv6 multicast
]

def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ip_address(ip_str)
        return any(ip_obj in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def is_special_use_ip(ip_str: str) -> bool:
    """True for multicast/broadcast/documentation/benchmarking/CGNAT/unspecified ranges."""
    try:
        ip_obj = ip_address(ip_str)
        return any(ip_obj in net for net in SPECIAL_USE_NETS)
    except ValueError:
        return False

def is_noise_ip(ip_str: str) -> bool:
    """
    True if the address should not be treated as a real, actionable external
    indicator — i.e. it is private (RFC1918/loopback/link-local/ULA) or a
    special-use range. Use this (rather than is_private_ip) when deciding
    whether an IP is a genuine external IOC or alert target.
    """
    return is_private_ip(ip_str) or is_special_use_ip(ip_str)

def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")

def human_readable_bytes(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num_bytes)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024