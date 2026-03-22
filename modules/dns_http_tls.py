from collections import Counter

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.packet import Raw

from modules.utils import safe_decode

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
)


def parse_http_payload(payload: bytes):
    text = safe_decode(payload[:8192])
    lines = text.splitlines()
    if not lines:
        return None

    first = lines[0]
    if not any(first.startswith(method.decode()) for method in HTTP_METHODS):
        return None

    result = {
        "request_line": first,
        "host": None,
        "user_agent": None,
        "authorization": None,
        "cookie": None,
    }

    for line in lines[1:50]:
        lower = line.lower()
        if lower.startswith("host:"):
            result["host"] = line.split(":", 1)[1].strip()
        elif lower.startswith("user-agent:"):
            result["user_agent"] = line.split(":", 1)[1].strip()
        elif lower.startswith("authorization:"):
            result["authorization"] = line.strip()
        elif lower.startswith("cookie:"):
            result["cookie"] = line.strip()

    return result


def analyze_dns_http_tls(packets):
    dns_queries = Counter()
    http_hosts = Counter()
    http_user_agents = Counter()
    notable_http = []

    for pkt in packets:
        if DNS in pkt and pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
            dns_queries[safe_decode(pkt[DNS].qd.qname).rstrip(".")] += 1

        if IP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            parsed = parse_http_payload(payload)
            if parsed:
                if parsed["host"]:
                    http_hosts[parsed["host"]] += 1
                if parsed["user_agent"]:
                    http_user_agents[parsed["user_agent"]] += 1

                notable_http.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "request_line": parsed["request_line"],
                    "host": parsed["host"],
                    "user_agent": parsed["user_agent"],
                    "has_authorization_header": bool(parsed["authorization"]),
                    "has_cookie_header": bool(parsed["cookie"]),
                })

    return {
        "dns_queries": dns_queries,
        "http_hosts": http_hosts,
        "http_user_agents": http_user_agents,
        "notable_http": notable_http,
    }