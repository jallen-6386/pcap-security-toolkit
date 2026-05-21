"""
ARP spoofing and adversary-in-the-middle detection.

Detects IP-MAC conflicts (same IP announced by different MACs) and
gratuitous ARP flooding. Maps to MITRE ATT&CK T1557.002 —
Adversary-in-the-Middle: ARP Cache Poisoning.
"""
from collections import defaultdict


_GRATUITOUS_FLOOD_THRESHOLD = 3   # > 3 gratuitous ARPs from same IP = suspicious


def detect_arp_spoofing(arp_rows: list[dict]) -> list[dict]:
    """
    Analyse pre-extracted ARP rows and return a list of anomaly dicts.

    Detects:
    1. IP–MAC conflicts: same sender IP seen with multiple distinct MACs in replies
    2. Gratuitous ARP flooding: same IP sends > N unsolicited ARP replies
    """
    if not arp_rows:
        return []

    # ip → set of MAC addresses seen in ARP replies
    ip_to_macs: dict[str, set] = defaultdict(set)
    # ip → list of (timestamp, mac) for replies
    reply_log: dict[str, list] = defaultdict(list)
    # ip → list of timestamps for gratuitous ARPs (sender_ip == target_ip)
    gratuitous_log: dict[str, list] = defaultdict(list)

    for row in arp_rows:
        try:
            opcode = int(row.get("arp.opcode", "") or 0)
        except (ValueError, TypeError):
            continue

        sender_ip  = (row.get("arp.src.proto_ipv4", "") or "").strip()
        sender_mac = (row.get("arp.src.hw_mac", "") or "").strip().lower()
        target_ip  = (row.get("arp.dst.proto_ipv4", "") or "").strip()
        ts = row.get("frame.time", "")

        if not sender_ip or not sender_mac:
            continue

        if opcode == 2:  # ARP reply
            ip_to_macs[sender_ip].add(sender_mac)
            reply_log[sender_ip].append((ts, sender_mac))
            if sender_ip == target_ip:
                gratuitous_log[sender_ip].append(ts)

    findings = []

    # 1. IP–MAC conflicts
    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        mac_list = ", ".join(sorted(macs))
        first_seen = reply_log[ip][0][0] if reply_log[ip] else ""
        findings.append({
            "detection_type": "IP_MAC_CONFLICT",
            "src_ip": ip,
            "dst_ip": "",
            "mac_addresses": mac_list,
            "reply_count": len(reply_log[ip]),
            "timestamp": first_seen,
            "severity": "HIGH",
            "mitre_technique_id": "T1557.002",
            "mitre_tactic": "Credential Access",
            "mitre_technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
            "reason": (
                f"IP {ip} announced by {len(macs)} different MAC addresses: {mac_list}"
            ),
        })

    # 2. Gratuitous ARP flooding
    for ip, timestamps in gratuitous_log.items():
        if len(timestamps) <= _GRATUITOUS_FLOOD_THRESHOLD:
            continue
        findings.append({
            "detection_type": "GRATUITOUS_ARP_FLOOD",
            "src_ip": ip,
            "dst_ip": "",
            "mac_addresses": reply_log[ip][0][1] if reply_log[ip] else "",
            "reply_count": len(timestamps),
            "timestamp": timestamps[0],
            "severity": "MEDIUM",
            "mitre_technique_id": "T1557.002",
            "mitre_tactic": "Credential Access",
            "mitre_technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
            "reason": (
                f"IP {ip} sent {len(timestamps)} gratuitous ARP replies "
                f"— possible MITM setup or device misconfiguration"
            ),
        })

    return findings
