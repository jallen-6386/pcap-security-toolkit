"""
ICMP tunnel and covert channel detection.

Detects ICMP-based covert channels via payload size analysis,
communication frequency, and non-standard ICMP type/code values.
Maps to MITRE ATT&CK T1095 — Non-Application Layer Protocol.
"""

_STANDARD_ICMP_TYPES = {0, 3, 4, 8, 11, 12, 13, 14, 17, 18}
_LARGE_PAYLOAD_THRESHOLD = 64    # standard ping payload is 8–56 bytes
_VOLUME_THRESHOLD = 100          # > 100 packets between same pair is suspicious
_LARGE_PAYLOAD_COUNT_MIN = 5     # need at least 5 oversized packets to flag


def detect_icmp_tunneling(icmp_rows: list[dict]) -> list[dict]:
    """
    Returns ICMP tunneling candidate dicts from pre-extracted ICMP field rows.

    Flags:
    - Large payloads: data.len > 64 bytes across multiple packets
    - High-frequency pairs: > 100 ICMP packets between the same host pair
    - Non-standard ICMP types: anything outside the common operational set
    """
    if not icmp_rows:
        return []

    pair_stats: dict[tuple, dict] = {}

    for row in icmp_rows:
        src = (row.get("ip.src", "") or "").strip()
        dst = (row.get("ip.dst", "") or "").strip()
        if not src or not dst:
            continue

        try:
            icmp_type = int(row.get("icmp.type", "") or -1)
        except (ValueError, TypeError):
            icmp_type = -1

        try:
            data_len = int(row.get("data.len", "") or 0)
        except (ValueError, TypeError):
            data_len = 0

        key = (src, dst)
        if key not in pair_stats:
            pair_stats[key] = {
                "count": 0,
                "max_payload": 0,
                "large_payload_count": 0,
                "non_standard_types": set(),
                "first_seen": row.get("frame.time", ""),
            }

        stats = pair_stats[key]
        stats["count"] += 1
        if data_len > stats["max_payload"]:
            stats["max_payload"] = data_len
        if data_len > _LARGE_PAYLOAD_THRESHOLD:
            stats["large_payload_count"] += 1
        if icmp_type >= 0 and icmp_type not in _STANDARD_ICMP_TYPES:
            stats["non_standard_types"].add(icmp_type)

    findings = []

    for (src, dst), stats in pair_stats.items():
        reasons = []

        if stats["large_payload_count"] >= _LARGE_PAYLOAD_COUNT_MIN:
            reasons.append(
                f"{stats['large_payload_count']} ICMP packets with payload "
                f"> {_LARGE_PAYLOAD_THRESHOLD}B (max {stats['max_payload']}B)"
            )

        if stats["count"] > _VOLUME_THRESHOLD:
            reasons.append(
                f"High-volume ICMP: {stats['count']} packets between host pair"
            )

        if stats["non_standard_types"]:
            type_str = ",".join(str(t) for t in sorted(stats["non_standard_types"]))
            reasons.append(f"Non-standard ICMP types observed: {type_str}")

        if reasons:
            findings.append({
                "src_ip": src,
                "dst_ip": dst,
                "packet_count": stats["count"],
                "max_payload_bytes": stats["max_payload"],
                "large_payload_count": stats["large_payload_count"],
                "non_standard_types": ",".join(
                    str(t) for t in sorted(stats["non_standard_types"])
                ),
                "first_seen": stats["first_seen"],
                "reason": "; ".join(reasons),
            })

    return findings
