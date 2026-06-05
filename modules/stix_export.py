"""
STIX 2.1 IOC bundle export.

Converts the deduplicated IOC list produced by iocs.py into a
STIX 2.1 JSON bundle (Bundle + Identity + Indicator objects) that
can be imported directly into MISP, OpenCTI, or TheHive.

Pure Python — no external dependencies required.
"""
import json
import uuid
from datetime import datetime, timezone

# Deterministic UUID namespace for this tool's objects
_TOOL_NS = uuid.UUID("6ba7b814-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
_IDENTITY_UUID = str(uuid.uuid5(_TOOL_NS, "pcap-security-toolkit"))

_STIX_PATTERN: dict = {
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "user_agent": (
        lambda v:
        f"[network-traffic:extensions.'http-request-ext'"
        f".request_header.'User-Agent' = '{v}']"
    ),
    "ja3_fingerprint": (
        lambda v: f"[network-traffic:extensions.'tls-ext'.ja3_hash = '{v}']"
    ),
    "ja4_fingerprint": (
        lambda v: f"[network-traffic:extensions.'tls-ext'.ja4_hash = '{v}']"
    ),
    "ja4s_fingerprint": (
        lambda v: f"[network-traffic:extensions.'tls-ext'.ja4s_hash = '{v}']"
    ),
    "ja4h_fingerprint": (
        lambda v:
        f"[network-traffic:extensions.'http-request-ext'.ja4h_hash = '{v}']"
    ),
}

_CONFIDENCE_MAP = {"HIGH": 85, "MEDIUM": 60, "LOW": 35}

_INDICATOR_TYPES: dict = {
    "ipv4":             ["malicious-activity"],
    "domain":           ["malicious-activity"],
    "url":              ["malicious-activity"],
    "sha256":           ["malicious-activity"],
    "user_agent":       ["anomalous-activity"],
    "ja3_fingerprint":  ["malicious-activity"],
    "ja4_fingerprint":  ["malicious-activity"],
    "ja4s_fingerprint": ["anomalous-activity"],
    "ja4h_fingerprint": ["anomalous-activity"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _safe_ts(ts: str, fallback: str) -> str:
    """Return ts if it looks like an ISO timestamp, otherwise fallback."""
    ts = (ts or "").strip()
    if len(ts) >= 10 and ts[4] == "-":
        # Ensure it ends with Z or +00:00 for STIX compliance
        if ts.endswith("Z") or "+" in ts:
            return ts
        return ts[:19] + ".000Z"
    return fallback


def export_stix_bundle(iocs: list[dict], case_name: str = "") -> str:
    """
    Convert IOC list to a STIX 2.1 JSON bundle string.

    Returns a formatted JSON string ready to write to iocs.stix2.json.
    IOC types without a STIX pattern mapping are silently skipped.
    """
    now = _now_iso()
    identity_id = f"identity--{_IDENTITY_UUID}"

    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "PCAP Security Toolkit",
        "identity_class": "tool",
        "description": "Automated PCAP analysis and IOC extraction",
    }

    indicator_objects = []

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "")
        value    = (ioc.get("value", "") or "").strip()
        if not value:
            continue

        # A STIX Indicator asserts "this pattern indicates malicious activity",
        # so never emit known-benign endpoints (public resolvers) into the
        # bundle — they remain visible, annotated, in iocs.csv.
        if ioc.get("benign_infra"):
            continue

        pattern_fn = _STIX_PATTERN.get(ioc_type)
        if pattern_fn is None:
            continue

        try:
            pattern = pattern_fn(value)
        except Exception:
            continue

        # Deterministic indicator ID based on type+value
        indicator_uuid = str(uuid.uuid5(_TOOL_NS, f"{ioc_type}:{value}"))
        indicator_id   = f"indicator--{indicator_uuid}"

        first_seen = _safe_ts(ioc.get("first_seen", ""), now)
        confidence = _CONFIDENCE_MAP.get(ioc.get("confidence", "LOW"), 35)
        source     = ioc.get("source", "")

        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": first_seen,
            "modified": first_seen,
            "created_by_ref": identity_id,
            "name": f"{ioc_type}: {value[:120]}",
            "description": f"Observed in PCAP analysis. Source module: {source}",
            "indicator_types": _INDICATOR_TYPES.get(ioc_type, ["anomalous-activity"]),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": first_seen,
            "confidence": confidence,
        }

        # Optional: enrich with GeoIP labels as external references
        country = ioc.get("country_iso", "")
        asn_org = ioc.get("asn_org", "")
        if country or asn_org:
            obj["labels"] = [x for x in [country, asn_org] if x]

        indicator_objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [identity_obj] + indicator_objects,
    }

    return json.dumps(bundle, indent=2, ensure_ascii=False)
