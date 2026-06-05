"""
Authentication-protocol analysis: NTLMSSP and LDAP.

Extends the existing Kerberos/SMB coverage with two more Windows-auth
protocols. The goal is forensic capture of who authenticated where, plus a
small set of low-false-positive detections:

  * NTLM authentication sent to an external host (possible NTLM relay/leak —
    NTLM should never traverse to the public internet)
  * Cleartext LDAP simple bind (the bind password is exposed on the wire)
  * High-volume LDAP search activity from one host (directory enumeration,
    e.g. BloodHound/SharpHound)

Normal NTLM and LDAP activity is recorded to CSV but not alerted on.
"""

from collections import defaultdict

from modules.utils import is_noise_ip

# LDAP searchRequest count from a single source above this is treated as
# possible directory enumeration. Set high to avoid flagging busy app servers.
_LDAP_ENUMERATION_THRESHOLD = 100

# NTLM message type 3 is AUTHENTICATE (carries the account identity).
_NTLM_AUTHENTICATE = "3"


def summarize_ntlm_events(rows: list[dict]) -> list[dict]:
    """Return deduplicated NTLM authentication records (forensic)."""
    events = []
    seen = set()
    for row in rows:
        user = (row.get("ntlmssp.auth.username", "") or "").strip()
        domain = (row.get("ntlmssp.auth.domain", "") or "").strip()
        host = (row.get("ntlmssp.auth.hostname", "") or "").strip()
        if not (user or domain or host):
            continue
        stream = row.get("tcp.stream", "")
        key = (user, domain, host, stream)
        if key in seen:
            continue
        seen.add(key)
        events.append({
            "timestamp": row.get("frame.time", ""),
            "src_ip": row.get("ip.src", ""),
            "dst_ip": row.get("ip.dst", ""),
            "tcp_stream": stream,
            "username": user,
            "domain": domain,
            "hostname": host,
            "has_server_challenge": bool(
                (row.get("ntlmssp.ntlmserverchallenge", "") or "").strip()
            ),
        })
    return events


def detect_ntlm_external(ntlm_events: list[dict]) -> list[dict]:
    """Flag NTLM authentication directed at an external (public) host."""
    findings = []
    for event in ntlm_events:
        dst = event.get("dst_ip", "")
        if dst and not is_noise_ip(dst):
            account = "\\".join(p for p in (event.get("domain"), event.get("username")) if p)
            findings.append({
                "src_ip": event.get("src_ip", ""),
                "dst_ip": dst,
                "tcp_stream": event.get("tcp_stream", ""),
                "reason": (
                    f"NTLM authentication ({account or 'unknown account'}) sent to "
                    f"external host {dst} — possible NTLM relay or credential leak"
                ),
            })
    return findings


def summarize_ldap_activity(rows: list[dict]) -> list[dict]:
    """Return LDAP bind/search records (forensic)."""
    activity = []
    for row in rows:
        op = (row.get("ldap.protocolOp", "") or "").strip()
        activity.append({
            "timestamp": row.get("frame.time", ""),
            "src_ip": row.get("ip.src", ""),
            "dst_ip": row.get("ip.dst", ""),
            "tcp_stream": row.get("tcp.stream", ""),
            "operation": op,
            "bind_dn": (row.get("ldap.name", "") or "").strip(),
            "auth_type": (row.get("ldap.authentication", "") or "").strip(),
            "base_object": (row.get("ldap.baseObject", "") or "").strip(),
            "result_code": (row.get("ldap.resultCode", "") or "").strip(),
        })
    return activity


def _is_search_op(op: str) -> bool:
    op = (op or "").strip().lower()
    return op == "3" or "search" in op


def detect_ldap_findings(rows: list[dict]) -> list[dict]:
    """Detect cleartext LDAP simple binds and directory-enumeration volume."""
    findings = []
    search_counts: dict[str, int] = defaultdict(int)
    seen_binds = set()

    for row in rows:
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")
        simple = (row.get("ldap.simple", "") or "").strip()
        name = (row.get("ldap.name", "") or "").strip()
        op = row.get("ldap.protocolOp", "")

        # Cleartext simple bind — the password is present in the packet.
        if simple:
            key = (src, name)
            if key not in seen_binds:
                seen_binds.add(key)
                findings.append({
                    "alert_type": "LDAP_CLEARTEXT_BIND",
                    "src_ip": src,
                    "dst_ip": dst,
                    "tcp_stream": row.get("tcp.stream", ""),
                    "reason": (
                        f"Cleartext LDAP simple bind as '{name or 'anonymous'}' — "
                        "bind password exposed on the wire (use LDAPS)"
                    ),
                })

        if _is_search_op(op):
            search_counts[src] += 1

    for src, count in search_counts.items():
        if count >= _LDAP_ENUMERATION_THRESHOLD:
            findings.append({
                "alert_type": "LDAP_ENUMERATION",
                "src_ip": src,
                "dst_ip": "",
                "tcp_stream": "",
                "reason": (
                    f"{count} LDAP search requests from {src} — possible directory "
                    "enumeration (e.g. BloodHound/SharpHound)"
                ),
            })

    return findings
