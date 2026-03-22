from collections import Counter, defaultdict

from scapy.layers.inet import IP, TCP, UDP

from modules.utils import human_readable_bytes


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

        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = None
        dport = None
        proto = "OTHER"

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