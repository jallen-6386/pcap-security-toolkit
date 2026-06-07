"""
External threat-intelligence feed loader.

Known-malicious JA3/JA4/JARM fingerprints go stale quickly, so rather than
relying solely on the small built-in lists, this module merges fingerprints
from external feed files at runtime. Drop feed CSVs into the intel directory
(or point at one with --intel-dir) and they are added to the in-memory
detection tables before analysis.

Supported file naming (case-insensitive prefix):
    ja3*.csv   -> JA3 fingerprints
    ja4*.csv   -> JA4 fingerprints
    jarm*.csv  -> JARM fingerprints

Supported row formats (comment lines starting with # are ignored):
    abuse.ch:  <hash>,<first_seen>,<last_seen>,<reason>
    simple:    <fingerprint>,<label>[,<source>]
    bare:      <fingerprint>
"""

import re
from pathlib import Path

from modules import https_metadata, jarm

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

# Real fingerprints are long (JA3 md5 = 32, JA4 ~36, JARM = 62). This filters
# out header rows like "fingerprint" / "ja3_md5" without a brittle allowlist.
_MIN_FINGERPRINT_LEN = 16


def _parse_feed(path: Path) -> list[tuple[str, str]]:
    """Return (fingerprint, label) pairs parsed from a feed CSV."""
    entries = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in line.split(",")]
                fingerprint = parts[0].strip().lower()
                if len(fingerprint) < _MIN_FINGERPRINT_LEN:
                    continue

                label = ""
                if len(parts) >= 4 and _DATE_RE.match(parts[1]):
                    label = parts[3]            # abuse.ch reason column
                elif len(parts) >= 2:
                    label = parts[1]
                entries.append((fingerprint, label or "threat-intel feed"))
    except Exception:
        return []
    return entries


def load_intel_feeds(intel_dir) -> dict:
    """
    Merge fingerprint feeds from *intel_dir* into the detection tables.

    Existing built-in entries are never overwritten. Returns a dict of how many
    new fingerprints were added per type: {"ja3": N, "ja4": N, "jarm": N}.
    """
    counts = {"ja3": 0, "ja4": 0, "jarm": 0}
    intel_path = Path(intel_dir)
    if not intel_path.is_dir():
        return counts

    targets = {
        "ja3": https_metadata.KNOWN_MALICIOUS_JA3,
        "ja4": https_metadata.KNOWN_MALICIOUS_JA4,
        "jarm": jarm.KNOWN_MALICIOUS_JARM,
    }

    for path in sorted(intel_path.glob("*.csv")):
        name = path.name.lower()
        kind = next((k for k in ("ja3", "ja4", "jarm") if name.startswith(k)), None)
        if kind is None:
            continue
        table = targets[kind]
        for fingerprint, label in _parse_feed(path):
            if fingerprint not in table:
                table[fingerprint] = (label, path.name)
                counts[kind] += 1

    return counts
