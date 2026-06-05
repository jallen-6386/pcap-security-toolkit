"""
TCP stream triage scoring.

Ranks TCP streams by a composite "suspicion score" so an analyst can review
the most interesting sessions first. The score is driven primarily by content
signals (carved files, extracted payloads, credentials, high entropy) and
direction/volume, with TCP health flags (resets, retransmissions) contributing
only lightly — those are usually network conditions, not intrusion, and should
sharpen ranking rather than drive it.

This produces a navigational ranking, not new alerts: the underlying signals
(credentials, carved files, exfil) already raise their own alerts.
"""

import math

from modules.utils import is_noise_ip


def _is_true(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _is_set(value) -> bool:
    # tcp.analysis.* flag fields render as "1" when present, empty otherwise.
    return str(value).strip() not in {"", "0", "false"}


def _aggregate_streams(stat_rows: list[dict]) -> dict:
    """Fold per-packet rows into per-stream aggregates keyed by stream id."""
    streams: dict[str, dict] = {}
    for row in stat_rows:
        sid = (row.get("tcp.stream", "") or "").strip()
        if sid == "":
            continue

        agg = streams.get(sid)
        if agg is None:
            agg = {
                "tcp_stream": sid,
                "src_ip": row.get("ip.src", ""),       # first packet = client
                "src_port": row.get("tcp.srcport", ""),
                "dst_ip": row.get("ip.dst", ""),
                "dst_port": row.get("tcp.dstport", ""),
                "packet_count": 0,
                "total_bytes": 0,
                "client_bytes": 0,
                "server_bytes": 0,
                "resets": 0,
                "retransmissions": 0,
                "zero_windows": 0,
                "lost_segments": 0,
                "completeness": "",
                "_min_ts": None,
                "_max_ts": None,
                "_client_ip": row.get("ip.src", ""),
            }
            streams[sid] = agg

        try:
            length = int(row.get("frame.len", 0) or 0)
        except ValueError:
            length = 0

        agg["packet_count"] += 1
        agg["total_bytes"] += length
        if row.get("ip.src", "") == agg["_client_ip"]:
            agg["client_bytes"] += length
        else:
            agg["server_bytes"] += length

        if _is_true(row.get("tcp.flags.reset", "")):
            agg["resets"] += 1
        if _is_set(row.get("tcp.analysis.retransmission", "")):
            agg["retransmissions"] += 1
        if _is_set(row.get("tcp.analysis.zero_window", "")):
            agg["zero_windows"] += 1
        if _is_set(row.get("tcp.analysis.lost_segment", "")):
            agg["lost_segments"] += 1

        completeness = (row.get("tcp.completeness.str", "") or "").strip()
        if completeness:
            agg["completeness"] = completeness

        try:
            ts = float(row.get("frame.time_epoch", "") or 0)
            if ts:
                agg["_min_ts"] = ts if agg["_min_ts"] is None else min(agg["_min_ts"], ts)
                agg["_max_ts"] = ts if agg["_max_ts"] is None else max(agg["_max_ts"], ts)
        except ValueError:
            pass

    return streams


def score_streams(
    stat_rows: list[dict],
    extracted_payloads: list[dict] | None = None,
    carved_files: list[dict] | None = None,
    credential_findings: list[dict] | None = None,
) -> list[dict]:
    """Return per-stream triage rows sorted by descending suspicion score."""
    extracted_payloads = extracted_payloads or []
    carved_files = carved_files or []
    credential_findings = credential_findings or []

    streams = _aggregate_streams(stat_rows)
    if not streams:
        return []

    # Per-stream content signals from already-computed results.
    payload_streams: dict[str, float] = {}
    for row in extracted_payloads:
        sid = str(row.get("tcp_stream", "") or "").strip()
        if sid:
            try:
                entropy = float(row.get("entropy", 0) or 0)
            except ValueError:
                entropy = 0.0
            payload_streams[sid] = max(payload_streams.get(sid, 0.0), entropy)

    carved_streams = {str(r.get("tcp_stream", "") or "").strip() for r in carved_files}
    credential_streams = {
        str(r.get("tcp_stream", "") or "").strip() for r in credential_findings
    }

    results = []
    for sid, agg in streams.items():
        reasons = []
        score = 0.0

        dst_ip = agg["dst_ip"]
        external = bool(dst_ip) and not is_noise_ip(dst_ip)
        if external:
            score += 15
            reasons.append("external destination")

        # Volume (log-scaled, capped)
        vol_points = min(25.0, math.log10(agg["total_bytes"] + 1) * 6)
        score += vol_points

        if sid in carved_streams:
            score += 25
            reasons.append("file carved from stream")
        if sid in payload_streams:
            score += 10
            reasons.append("payload extracted")
            if payload_streams[sid] >= 7.2:
                score += 10
                reasons.append(f"high entropy ({payload_streams[sid]:.1f})")
        if sid in credential_streams:
            score += 30
            reasons.append("credential indicator in stream")

        # Upload-heavy to external host (possible exfil)
        if external and agg["server_bytes"] >= 0:
            total = agg["client_bytes"] + agg["server_bytes"]
            if total > 0 and agg["client_bytes"] / total >= 0.8 and agg["total_bytes"] >= 10000:
                score += 10
                reasons.append("upload-heavy to external host")

        # TCP health — light weight, ranking tiebreaker only
        if agg["resets"] or agg["retransmissions"] or agg["zero_windows"] or agg["lost_segments"]:
            score += min(5.0, agg["resets"] + agg["retransmissions"] * 0.5)
            reasons.append("tcp health anomalies")

        duration = 0.0
        if agg["_min_ts"] is not None and agg["_max_ts"] is not None:
            duration = round(agg["_max_ts"] - agg["_min_ts"], 3)

        results.append({
            "tcp_stream": sid,
            "src_ip": agg["src_ip"],
            "src_port": agg["src_port"],
            "dst_ip": dst_ip,
            "dst_port": agg["dst_port"],
            "packet_count": agg["packet_count"],
            "total_bytes": agg["total_bytes"],
            "client_bytes": agg["client_bytes"],
            "server_bytes": agg["server_bytes"],
            "duration_sec": duration,
            "resets": agg["resets"],
            "retransmissions": agg["retransmissions"],
            "zero_windows": agg["zero_windows"],
            "lost_segments": agg["lost_segments"],
            "completeness": agg["completeness"],
            "has_carved_file": sid in carved_streams,
            "has_payload": sid in payload_streams,
            "has_credential": sid in credential_streams,
            "suspicion_score": round(min(score, 100.0), 1),
            "reasons": " | ".join(reasons),
        })

    results.sort(key=lambda x: x["suspicion_score"], reverse=True)
    return results
