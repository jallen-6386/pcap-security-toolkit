"""
Shared runtime TShark configuration.

Holds runtime options that every TShark invocation (field extraction,
statistics taps, JA4 handshake parsing) must apply:

  * "decode as" rules — force a dissector for traffic on a non-standard
    port, e.g. HTTP or TLS C2 on tcp.port 8888.
  * a TLS key-log file — decrypt TLS sessions when the secrets are available
    (SSLKEYLOGFILE), so HTTPS content can be extracted like plaintext.

Set once from the CLI/GUI before extraction begins.
"""

import re

_DECODE_AS_RULES: list[str] = []
_TLS_KEYLOG_FILE: str = ""
_SESSION_RESET: int = 0

# A decode-as rule looks like: tcp.port==8888,http  (selector==value,protocol)
_RULE_RE = re.compile(r"^[^=,\s]+==[^,\s]+,[^,\s]+$")


def is_valid_decode_as(rule: str) -> bool:
    return bool(_RULE_RE.match((rule or "").strip()))


def set_decode_as(rules) -> None:
    global _DECODE_AS_RULES
    _DECODE_AS_RULES = [r.strip() for r in (rules or []) if r and r.strip()]


def get_decode_as() -> list[str]:
    return list(_DECODE_AS_RULES)


def set_tls_keylog(path) -> None:
    global _TLS_KEYLOG_FILE
    _TLS_KEYLOG_FILE = str(path).strip() if path else ""


def get_tls_keylog() -> str:
    return _TLS_KEYLOG_FILE


def set_session_reset(packet_count) -> None:
    """Set TShark's -M auto session reset interval (0 disables it)."""
    global _SESSION_RESET
    try:
        _SESSION_RESET = max(0, int(packet_count or 0))
    except (TypeError, ValueError):
        _SESSION_RESET = 0


def get_session_reset() -> int:
    return _SESSION_RESET


def runtime_args() -> list[str]:
    """Return the TShark args for all active runtime options.

    Covers decode-as rules, a TLS key-log file, and (for very large captures)
    a -M session-reset interval that bounds per-process memory growth.
    """
    args: list[str] = []
    for rule in _DECODE_AS_RULES:
        args.extend(["-d", rule])
    if _TLS_KEYLOG_FILE:
        args.extend(["-o", f"tls.keylog_file:{_TLS_KEYLOG_FILE}"])
    if _SESSION_RESET:
        args.extend(["-M", str(_SESSION_RESET)])
    return args


# Backwards-compatible alias — runtime_args() now covers decode-as plus keylog.
decode_as_args = runtime_args
