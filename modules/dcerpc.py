"""
DCERPC interface analysis for lateral-movement detection.

DCERPC requests reference a context id negotiated at BIND time, so the
interface a client is using is carried in the BIND PDU's interface UUID
(dcerpc.cn_bind_to_uuid). This module maps binds to well-known interfaces
and the techniques they are abused for.

Because DCERPC underpins a lot of normal Windows administration, alerting is
deliberately conservative: only the rare, strongly abuse-associated
interfaces (DCSync/DRSUAPI, PetitPotam/EFSR, remote task scheduling) raise
alerts. The common-but-abusable interfaces (svcctl, samr, lsarpc, winreg,
srvsvc, spoolss) are recorded to dcerpc_activity.csv with their technique
label for analyst review, but not alerted on.
"""

import re

# uuid (lowercase) -> (display name, mitre technique id, alert_type or None)
# alert_type None => recorded to CSV but not alerted (too common to flag).
DCERPC_INTERFACES = {
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": (
        "DRSUAPI (directory replication / DCSync)", "T1003.006", "DCERPC_DCSYNC"),
    "c681d488-d850-11d0-8c52-00c04fd90f7e": (
        "MS-EFSR EfsRpcOpenFileRaw (PetitPotam)", "T1187", "DCERPC_FORCED_AUTH"),
    "df1941c5-fe89-4e79-bf10-463657acf44d": (
        "MS-EFSR (PetitPotam)", "T1187", "DCERPC_FORCED_AUTH"),
    "1ff70682-0a51-30e8-076d-740be8cee98b": (
        "atsvc (task scheduler)", "T1053.005", "DCERPC_SCHEDULED_TASK"),
    "86d35949-83c9-4044-b424-db363231fd0c": (
        "ITaskSchedulerService (tsch)", "T1053.005", "DCERPC_SCHEDULED_TASK"),
    # Recorded but not alerted — heavily used by legitimate administration.
    "367abb81-9844-35f1-ad32-98f038001003": (
        "svcctl (service control / PsExec)", "T1543.003", None),
    "12345778-1234-abcd-ef00-0123456789ac": (
        "samr (account manager)", "T1087.002", None),
    "12345778-1234-abcd-ef00-0123456789ab": (
        "lsarpc", "T1482", None),
    "338cd001-2244-31f1-aaaa-900038001003": (
        "winreg (remote registry)", "T1112", None),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": (
        "srvsvc (server service)", "T1135", None),
    "12345678-1234-abcd-ef00-0123456789ab": (
        "spoolss (print spooler / PrinterBug)", "T1187", None),
}

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def _normalize_uuid(value: str) -> str:
    match = _UUID_RE.search((value or "").lower())
    return match.group(0) if match else ""


def summarize_dcerpc_binds(rows: list[dict]) -> list[dict]:
    """Return deduplicated binds to recognized DCERPC interfaces (forensic)."""
    results = []
    seen = set()
    for row in rows:
        uuid = _normalize_uuid(row.get("dcerpc.cn_bind_to_uuid", ""))
        if not uuid:
            continue
        info = DCERPC_INTERFACES.get(uuid)
        if not info:
            continue
        name, technique, alert_type = info
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")
        key = (src, dst, uuid)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "timestamp": row.get("frame.time", ""),
            "src_ip": src,
            "dst_ip": dst,
            "tcp_stream": row.get("tcp.stream", ""),
            "interface": name,
            "uuid": uuid,
            "interface_ver": (row.get("dcerpc.cn_bind_if_ver", "") or "").strip(),
            "mitre_technique_id": technique,
            "alert_worthy": alert_type is not None,
        })
    return results


def detect_dcerpc_abuse(bind_summary: list[dict]) -> list[dict]:
    """Return alert findings for binds to high-signal abuse interfaces."""
    findings = []
    for bind in bind_summary:
        info = DCERPC_INTERFACES.get(bind.get("uuid", ""))
        if not info:
            continue
        _name, _technique, alert_type = info
        if alert_type is None:
            continue
        findings.append({
            "alert_type": alert_type,
            "src_ip": bind.get("src_ip", ""),
            "dst_ip": bind.get("dst_ip", ""),
            "tcp_stream": bind.get("tcp_stream", ""),
            "reason": (
                f"DCERPC bind to {bind.get('interface', '')} "
                f"({bind.get('src_ip', '')} -> {bind.get('dst_ip', '')})"
            ),
        })
    return findings
