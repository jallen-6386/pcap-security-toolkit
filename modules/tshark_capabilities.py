"""
TShark capability discovery.

TShark's available display-filter fields vary by version (for example, the
JA4 family fields only exist in newer releases). Requesting a field the
installed TShark doesn't know about makes the entire extraction pass fail,
not just that one column. This module dumps the field registry once via
`tshark -G fields` and lets extractors drop unknown fields beforehand.

`get_available_fields()` returns a set of field names, or None when the
field list can't be determined — in which case callers should fall back to
requesting every field (the original, unfiltered behavior).
"""

import subprocess
from functools import lru_cache

from modules.dependencies import find_tshark


@lru_cache(maxsize=1)
def get_available_fields():
    """Return the set of known TShark field names, or None if undiscoverable."""
    tshark = find_tshark()
    if not tshark:
        return None
    try:
        result = subprocess.run(
            [tshark, "-G", "fields"], capture_output=True, text=True
        )
    except Exception:
        return None
    if result.returncode != 0 or not result.stdout:
        return None

    fields = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        # Field registration lines look like: F\t<name>\t<abbrev>\t<type>\t...
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2])
    return fields or None


def filter_available_fields(fields):
    """
    Return (usable_fields, dropped_fields).

    Drops any requested field the installed TShark doesn't recognize. If the
    field list can't be discovered, or filtering would remove everything,
    the original list is returned unchanged so behavior degrades gracefully.
    """
    available = get_available_fields()
    if available is None:
        return list(fields), []
    usable = [f for f in fields if f in available]
    dropped = [f for f in fields if f not in available]
    if not usable:
        return list(fields), []
    return usable, dropped
