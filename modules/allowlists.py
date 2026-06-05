"""
Benign-infrastructure allowlists for false-positive reduction.

These lists identify well-known, high-volume, generally-benign infrastructure
(public DNS resolvers, NTP, large CDN/cloud parents). Findings involving these
are downgraded and annotated rather than suppressed — nothing is hidden, so a
genuine detection that happens to traverse benign infrastructure is still
visible, just deprioritized.
"""

# Well-known public DNS resolver IPs (IPv4 + IPv6).
BENIGN_RESOLVER_IPS = {
    "8.8.8.8", "8.8.4.4",                       # Google
    "1.1.1.1", "1.0.0.1",                       # Cloudflare
    "9.9.9.9", "149.112.112.112",               # Quad9
    "208.67.222.222", "208.67.220.220",         # OpenDNS
    "64.6.64.6", "64.6.65.6",                   # Verisign
    "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google v6
    "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare v6
    "2620:fe::fe", "2620:fe::9",                # Quad9 v6
}

# NTP runs on this port; regular polling here is expected, not beaconing.
NTP_PORT = 123

# Parent domains for large CDN / cloud / first-party platforms. Hostnames under
# these legitimately look "anomalous" (long, hex-like, digit-heavy) and are
# queried at high volume, so they are exempted from those specific heuristics.
CDN_DOMAIN_SUFFIXES = (
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akadns.net",
    "edgekey.net", "edgesuite.net",
    "cloudfront.net", "amazonaws.com",
    "azureedge.net", "azurefd.net", "trafficmanager.net", "windows.net",
    "fastly.net", "fastlylb.net",
    "googlevideo.com", "gvt1.com", "gstatic.com", "ggpht.com",
    "googleusercontent.com", "1e100.net",
    "cloudflare.net", "cloudflare-dns.com",
    "fbcdn.net", "cdninstagram.com",
    "llnwd.net", "cdn77.org", "stackpathdns.com", "cachefly.net",
    "msedge.net", "microsoft.com", "office.com", "office365.com",
    "skype.com", "live.com", "windowsupdate.com",
    "apple.com", "mzstatic.com", "aaplimg.com", "icloud.com",
)


def is_benign_resolver(ip: str) -> bool:
    return (ip or "").strip() in BENIGN_RESOLVER_IPS


def is_benign_beacon_destination(dst_ip: str, dport) -> bool:
    """A beacon to a public resolver or to the NTP port is expected behavior."""
    if is_benign_resolver(dst_ip):
        return True
    try:
        return int(dport) == NTP_PORT
    except (TypeError, ValueError):
        return False


def is_cdn_or_cloud_domain(host: str) -> bool:
    """True if the hostname falls under a known CDN/cloud/first-party parent."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    return any(host == suffix or host.endswith("." + suffix) for suffix in CDN_DOMAIN_SUFFIXES)
