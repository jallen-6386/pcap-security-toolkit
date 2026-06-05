"""
TShark statistics taps (-z) for first-pass triage.

Wraps two text-output statistics workflows and normalizes them into rows:
  * Protocol hierarchy   (-z io,phs)  -> per-protocol frame/byte counts
  * Expert Info          (-z expert)  -> dissector-recognized anomalies

Statistics taps emit plain text, so each parser is a small, defensive
state machine. The raw text is preserved as a sidecar artifact by the
caller; these functions return both the parsed rows and the raw output.
"""

import re
import subprocess

from modules.dependencies import find_tshark

# Known Wireshark Expert Info severity sections, mapped to our labels.
_EXPERT_SECTIONS = {
    "Errors":   "Error",
    "Warnings": "Warning",
    "Notes":    "Note",
    "Chats":    "Chat",
}

# Known Expert Info group names. Listed longest-first so multi-word groups
# ("Response Code") are matched before single-word ones during prefix matching.
_EXPERT_GROUPS = [
    "Response Code",
    "Request Code",
    "Decryption",
    "Reassemble",
    "Assumption",
    "Deprecated",
    "Malformed",
    "Undecoded",
    "Checksum",
    "Sequence",
    "Protocol",
    "Security",
    "Comment",
    "Debug",
]

_SECTION_RE = re.compile(r"^(Errors|Warnings|Notes|Chats)\s+\((\d+)\)\s*$")
_PHS_RE = re.compile(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)\s*$")

_CRED_COLUMNS = ["Packet", "Protocol", "Username", "Info"]


def run_protocol_hierarchy(pcap_path):
    """Return (rows, raw_text, err). Rows: protocol, depth, frames, bytes."""
    tshark = find_tshark()
    if not tshark:
        return [], "", "TShark not found"

    cmd = [tshark, "-n", "-q", "-r", str(pcap_path), "-z", "io,phs"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return [], "", str(exc)
    if result.returncode != 0:
        return [], result.stdout, result.stderr.strip()

    rows = []
    for line in result.stdout.splitlines():
        match = _PHS_RE.match(line)
        if not match:
            continue
        indent, proto, frames, byte_count = match.groups()
        rows.append({
            "protocol": proto,
            "depth": len(indent) // 2,
            "frames": int(frames),
            "bytes": int(byte_count),
        })
    return rows, result.stdout, None


def _split_expert_row(text: str):
    """Split a data row '<freq> <group> <protocol> <summary>' robustly."""
    text = text.rstrip()
    m = re.match(r"^\s*(\d+)\s+(.*)$", text)
    if not m:
        return None
    frequency = int(m.group(1))
    rest = m.group(2).strip()

    group = ""
    for candidate in _EXPERT_GROUPS:
        if rest == candidate or rest.startswith(candidate + " "):
            group = candidate
            rest = rest[len(candidate):].strip()
            break
    if not group:
        # Fallback: first whitespace token is the group.
        parts = rest.split(None, 1)
        group = parts[0] if parts else ""
        rest = parts[1].strip() if len(parts) > 1 else ""

    parts = rest.split(None, 1)
    protocol = parts[0] if parts else ""
    summary = parts[1].strip() if len(parts) > 1 else ""
    return frequency, group, protocol, summary


def run_expert_info(pcap_path):
    """Return (rows, raw_text, err). Rows: severity, frequency, group, protocol, summary."""
    tshark = find_tshark()
    if not tshark:
        return [], "", "TShark not found"

    cmd = [tshark, "-n", "-q", "-r", str(pcap_path), "-z", "expert"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return [], "", str(exc)
    if result.returncode != 0:
        return [], result.stdout, result.stderr.strip()

    rows = []
    current_severity = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        section = _SECTION_RE.match(stripped)
        if section:
            current_severity = _EXPERT_SECTIONS.get(section.group(1))
            continue

        if stripped.startswith("==="):
            continue
        # Skip the column header row of each section.
        if stripped.split()[:1] == ["Frequency"]:
            continue
        if current_severity is None:
            continue

        parsed = _split_expert_row(line)
        if not parsed:
            continue
        frequency, group, protocol, summary = parsed
        rows.append({
            "severity": current_severity,
            "frequency": frequency,
            "group": group,
            "protocol": protocol,
            "summary": summary,
        })
    return rows, result.stdout, None


def run_credentials(pcap_path):
    """
    Return (rows, raw_text, err) from TShark's -z credentials tap.

    The tap prints a fixed-width table whose Protocol column can contain
    spaces ("HTTP basic auth"), so rows are sliced by the header column
    positions rather than split on whitespace.
    """
    tshark = find_tshark()
    if not tshark:
        return [], "", "TShark not found"

    cmd = [tshark, "-n", "-q", "-r", str(pcap_path), "-z", "credentials"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return [], "", str(exc)
    if result.returncode != 0:
        return [], result.stdout, result.stderr.strip()

    lines = result.stdout.splitlines()
    header_idx = None
    bounds = None
    for i, line in enumerate(lines):
        if all(col in line for col in _CRED_COLUMNS):
            positions = [line.index(col) for col in _CRED_COLUMNS]
            bounds = list(zip(positions, positions[1:] + [None]))
            header_idx = i
            break
    if header_idx is None or bounds is None:
        return [], result.stdout, None

    rows = []
    for line in lines[header_idx + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("---") or stripped.startswith("==="):
            continue
        cells = [line[start:end].strip() for start, end in bounds]
        packet, protocol, username, info = cells
        if not packet.isdigit():
            continue
        rows.append({
            "packet": packet,
            "protocol": protocol,
            "username": username,
            "info": info,
        })
    return rows, result.stdout, None
