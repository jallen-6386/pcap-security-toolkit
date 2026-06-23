from collections import Counter, defaultdict

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

try:
    from scapy.layers.inet6 import IPv6
    _HAS_IPV6 = True
except ImportError:
    _HAS_IPV6 = False

from modules.dns_http_tls import parse_http_payload
from modules.utils import human_readable_bytes, safe_decode


def _new_flow_time_stat() -> dict:
    """Accumulator for a flow's inter-arrival timing (used by beaconing)."""
    return {
        "packets": 0,    # total packets in the flow
        "deltas": 0,     # number of positive inter-arrival gaps
        "sum": 0.0,      # sum of gaps (for mean)
        "sum_sq": 0.0,   # sum of gaps^2 (for variance/stdev)
        "last": None,    # last timestamp seen
        "min": None,     # earliest timestamp (for the timeline)
    }


def _update_flow_time_stat(stat: dict, timestamp: float) -> None:
    """Fold one packet timestamp into a flow's online timing statistics.

    Assumes packets arrive in capture (chronological) order within a flow,
    which holds for a single capture; gaps are computed against the prior
    timestamp rather than storing every timestamp.
    """
    stat["packets"] += 1
    if stat["min"] is None or timestamp < stat["min"]:
        stat["min"] = timestamp
    last = stat["last"]
    if last is not None and timestamp > last:
        gap = round(timestamp - last, 3)
        stat["deltas"] += 1
        stat["sum"] += gap
        stat["sum_sq"] += gap * gap
    if last is None or timestamp > last:
        stat["last"] = timestamp


def analyze_flows(packets):
    ip_counter = Counter()
    protocol_counter = Counter()
    conversation_counter = Counter()
    flow_bytes = defaultdict(int)
    flow_packets = defaultdict(int)
    flow_times = defaultdict(list)

    total_packets = 0
    total_bytes = 0

    for pkt in packets:
        total_packets += 1
        pkt_len = len(pkt)
        total_bytes += pkt_len

        src = None
        dst = None
        sport = None
        dport = None
        proto = "OTHER"

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif _HAS_IPV6 and IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            continue

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        ip_counter[src] += 1
        ip_counter[dst] += 1
        protocol_counter[proto] += 1

        conv = f"{src}:{sport} -> {dst}:{dport} ({proto})"
        conversation_counter[conv] += 1

        flow_key = (src, dst, sport, dport, proto)
        flow_bytes[flow_key] += pkt_len
        flow_packets[flow_key] += 1

        if hasattr(pkt, "time"):
            try:
                flow_times[flow_key].append(float(pkt.time))
            except Exception:
                pass

    return {
        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_size_human": human_readable_bytes(total_bytes),
            "unique_ips": len(ip_counter),
        },
        "ip_counter": ip_counter,
        "protocol_counter": protocol_counter,
        "conversation_counter": conversation_counter,
        "flow_bytes": flow_bytes,
        "flow_packets": flow_packets,
        "flow_times": flow_times,
    }


def analyze_packets(packets, max_packets=0):
    """
    Single-pass combined analysis: flow statistics plus DNS/HTTP summaries.

    *max_packets* (>0) stops after that many packets, for first-N-packet triage
    of very large captures.

    Replaces the previous two separate streaming passes (analyze_flows +
    analyze_dns_http_tls), halving Scapy dissection cost on large captures.
    Returns a dict with both a "flow" sub-dict (same shape as analyze_flows)
    and a "protocol" sub-dict (same shape as analyze_dns_http_tls).
    """
    ip_counter = Counter()
    protocol_counter = Counter()
    conversation_counter = Counter()
    flow_bytes = defaultdict(int)
    flow_packets = defaultdict(int)
    # Online inter-arrival statistics per flow (for beaconing) instead of a
    # timestamp per packet — keeps memory O(flows), not O(packets).
    flow_time_stats = defaultdict(_new_flow_time_stat)

    dns_queries = Counter()
    http_hosts = Counter()
    http_user_agents = Counter()
    notable_http = []

    total_packets = 0
    total_bytes = 0

    for pkt in packets:
        if max_packets and total_packets >= max_packets:
            break
        total_packets += 1
        pkt_len = len(pkt)
        total_bytes += pkt_len

        # --- DNS query summary (independent of IP layer presence checks below)
        if DNS in pkt and pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
            dns_queries[safe_decode(pkt[DNS].qd.qname).rstrip(".")] += 1

        src = None
        dst = None
        sport = None
        dport = None
        proto = "OTHER"

        has_ip = IP in pkt
        if has_ip:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif _HAS_IPV6 and IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            continue

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        ip_counter[src] += 1
        ip_counter[dst] += 1
        protocol_counter[proto] += 1

        conv = f"{src}:{sport} -> {dst}:{dport} ({proto})"
        conversation_counter[conv] += 1

        flow_key = (src, dst, sport, dport, proto)
        flow_bytes[flow_key] += pkt_len
        flow_packets[flow_key] += 1

        if hasattr(pkt, "time"):
            try:
                ts = float(pkt.time)
            except Exception:
                ts = None
            if ts is not None:
                _update_flow_time_stat(flow_time_stats[flow_key], ts)

        # --- HTTP request summary (plaintext payloads only)
        if has_ip and Raw in pkt:
            parsed = parse_http_payload(bytes(pkt[Raw].load))
            if parsed:
                if parsed["host"]:
                    http_hosts[parsed["host"]] += 1
                if parsed["user_agent"]:
                    http_user_agents[parsed["user_agent"]] += 1
                notable_http.append({
                    "src": src,
                    "dst": dst,
                    "request_line": parsed["request_line"],
                    "host": parsed["host"],
                    "user_agent": parsed["user_agent"],
                    "has_authorization_header": bool(parsed["authorization"]),
                    "has_cookie_header": bool(parsed["cookie"]),
                })

    return {
        "flow": {
            "summary": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "total_size_human": human_readable_bytes(total_bytes),
                "unique_ips": len(ip_counter),
            },
            "ip_counter": ip_counter,
            "protocol_counter": protocol_counter,
            "conversation_counter": conversation_counter,
            "flow_bytes": flow_bytes,
            "flow_packets": flow_packets,
            "flow_time_stats": flow_time_stats,
        },
        "protocol": {
            "dns_queries": dns_queries,
            "http_hosts": http_hosts,
            "http_user_agents": http_user_agents,
            "notable_http": notable_http,
        },
    }
