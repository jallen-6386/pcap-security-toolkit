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

def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ip_address(ip_str)
        return any(ip_obj in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")

def human_readable_bytes(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num_bytes)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024