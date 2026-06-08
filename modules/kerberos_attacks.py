"""
Kerberos credential-attack detection.

Builds on the Kerberos field extraction with two well-known signatures:

  * Kerberoasting (T1558.003): a TGS-REQ requesting a service ticket with
    RC4 (etype 23). Modern AD issues AES tickets, so an RC4 service ticket is
    a crackable artifact attackers deliberately request.

  * AS-REP roasting (T1558.004): an account that receives an AS-REP without
    ever sending Kerberos pre-authentication (PA-ENC-TIMESTAMP). Such accounts
    have "do not require pre-authentication" set and their AS-REP is crackable
    offline.

Both are reported as MEDIUM candidates — legacy RC4 use and partial captures
can produce benign matches, so they are leads for review, not verdicts.
"""

from collections import defaultdict

# Kerberos message types
_AS_REQ = "10"
_AS_REP = "11"
_TGS_REQ = "12"

_RC4_ETYPE = "23"               # RC4-HMAC — crackable, attacker-preferred
_PA_ENC_TIMESTAMP = "2"         # padata type indicating pre-authentication


def _multi(value: str) -> set:
    """Split a possibly multi-valued TShark field into a set of tokens."""
    return {v.strip() for v in (value or "").split(",") if v.strip()}


def detect_kerberos_attacks(kerberos_rows: list[dict]) -> list[dict]:
    """Return Kerberoasting and AS-REP roasting candidate findings."""
    findings = []
    seen = set()

    # Per-client state for AS-REP roasting correlation.
    clients = defaultdict(lambda: {
        "as_req": 0, "as_rep": 0, "preauth": False,
        "src_ip": "", "dst_ip": "", "timestamp": "",
    })

    for row in kerberos_rows:
        msg_type = (row.get("kerberos.msg_type", "") or "").strip()
        cname = (row.get("kerberos.CNameString", "") or "").strip()
        src_ip = row.get("ip.src", "")
        dst_ip = row.get("ip.dst", "")

        # Kerberoasting: TGS-REQ offering RC4 for a service ticket.
        if msg_type == _TGS_REQ and _RC4_ETYPE in _multi(row.get("kerberos.etype", "")):
            spn = (row.get("kerberos.SNameString", "") or "").strip()
            key = ("roast", src_ip, spn)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "alert_type": "KERBEROASTING_CANDIDATE",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "tcp_stream": row.get("tcp.stream", ""),
                    "reason": (
                        f"TGS-REQ for SPN '{spn or 'unknown'}' using RC4 (etype 23) "
                        "— crackable service ticket (possible Kerberoasting)"
                    ),
                })

        # Collect AS-exchange state per client.
        if cname and msg_type in (_AS_REQ, _AS_REP):
            state = clients[cname]
            state["src_ip"] = state["src_ip"] or src_ip
            state["dst_ip"] = state["dst_ip"] or dst_ip
            state["timestamp"] = state["timestamp"] or row.get("frame.time", "")
            if msg_type == _AS_REQ:
                state["as_req"] += 1
                if _PA_ENC_TIMESTAMP in _multi(row.get("kerberos.padata_type", "")):
                    state["preauth"] = True
            else:  # AS-REP
                state["as_rep"] += 1

    # AS-REP roasting: client got an AS-REP but never sent pre-auth.
    for cname, state in clients.items():
        if state["as_rep"] > 0 and state["as_req"] > 0 and not state["preauth"]:
            findings.append({
                "alert_type": "ASREP_ROASTING_CANDIDATE",
                "src_ip": state["src_ip"],
                "dst_ip": state["dst_ip"],
                "tcp_stream": "",
                "reason": (
                    f"Account '{cname}' received an AS-REP without Kerberos "
                    "pre-authentication — AS-REP roastable"
                ),
            })

    return findings
