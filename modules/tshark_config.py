"""
Shared runtime TShark configuration.

Holds the active "decode as" rules so every TShark invocation (field
extraction, statistics taps, JA4 handshake parsing) can force a dissector
for traffic on a non-standard port — e.g. HTTP or TLS C2 on tcp.port 8888.
Set once from the CLI/GUI before extraction begins.
"""

import re

_DECODE_AS_RULES: list[str] = []

# A decode-as rule looks like: tcp.port==8888,http  (selector==value,protocol)
_RULE_RE = re.compile(r"^[^=,\s]+==[^,\s]+,[^,\s]+$")


def is_valid_decode_as(rule: str) -> bool:
    return bool(_RULE_RE.match((rule or "").strip()))


def set_decode_as(rules) -> None:
    global _DECODE_AS_RULES
    _DECODE_AS_RULES = [r.strip() for r in (rules or []) if r and r.strip()]


def get_decode_as() -> list[str]:
    return list(_DECODE_AS_RULES)


def decode_as_args() -> list[str]:
    """Return the TShark argument list for the active decode-as rules."""
    args: list[str] = []
    for rule in _DECODE_AS_RULES:
        args.extend(["-d", rule])
    return args
