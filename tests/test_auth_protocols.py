"""NTLM / LDAP / DCERPC detection regression tests."""

import unittest

from modules.auth_protocols import (
    detect_ldap_findings,
    detect_ntlm_external,
    summarize_ntlm_events,
)
from modules.dcerpc import detect_dcerpc_abuse, summarize_dcerpc_binds
from modules.detections import build_alerts


class TestNTLM(unittest.TestCase):
    def test_external_ntlm_flagged_internal_not(self):
        rows = [
            {"ntlmssp.auth.username": "alice", "ntlmssp.auth.domain": "CORP",
             "ntlmssp.auth.hostname": "WS1", "ip.src": "10.0.0.5",
             "ip.dst": "45.1.2.3", "tcp.stream": "1"},
            {"ntlmssp.auth.username": "bob", "ntlmssp.auth.domain": "CORP",
             "ntlmssp.auth.hostname": "WS2", "ip.src": "10.0.0.6",
             "ip.dst": "10.0.0.1", "tcp.stream": "2"},
        ]
        findings = detect_ntlm_external(summarize_ntlm_events(rows))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["dst_ip"], "45.1.2.3")


class TestLDAP(unittest.TestCase):
    def test_cleartext_bind_flagged(self):
        rows = [{"ldap.protocolOp": "0", "ldap.name": "cn=svc",
                 "ldap.simple": "P@ss", "ip.src": "10.0.0.5", "ip.dst": "10.0.0.1"}]
        findings = detect_ldap_findings(rows)
        self.assertTrue(any(f["alert_type"] == "LDAP_CLEARTEXT_BIND" for f in findings))

    def test_enumeration_threshold(self):
        rows = [{"ldap.protocolOp": "3", "ip.src": "10.0.0.9", "ip.dst": "10.0.0.1"}
                for _ in range(120)]
        findings = detect_ldap_findings(rows)
        self.assertTrue(any(f["alert_type"] == "LDAP_ENUMERATION" for f in findings))

    def test_low_search_volume_not_flagged(self):
        rows = [{"ldap.protocolOp": "3", "ip.src": "10.0.0.8", "ip.dst": "10.0.0.1"}
                for _ in range(5)]
        findings = detect_ldap_findings(rows)
        self.assertFalse(any(f["alert_type"] == "LDAP_ENUMERATION" for f in findings))


class TestDCERPC(unittest.TestCase):
    def test_high_signal_alerts_common_recorded_only(self):
        rows = [
            {"dcerpc.cn_bind_to_uuid": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",  # DRSUAPI
             "ip.src": "10.0.0.9", "ip.dst": "10.0.0.1"},
            {"dcerpc.cn_bind_to_uuid": "367abb81-9844-35f1-ad32-98f038001003",  # svcctl
             "ip.src": "10.0.0.9", "ip.dst": "10.0.0.5"},
        ]
        binds = summarize_dcerpc_binds(rows)
        self.assertEqual(len(binds), 2)  # both recorded
        findings = detect_dcerpc_abuse(binds)
        types = {f["alert_type"] for f in findings}
        self.assertIn("DCERPC_DCSYNC", types)        # high-signal alerts
        self.assertNotIn("svcctl", str(findings))    # svcctl recorded, not alerted
        self.assertEqual(len(findings), 1)

    def test_uuid_normalization_and_dedup(self):
        rows = [
            {"dcerpc.cn_bind_to_uuid": "DRSUAPI: e3514235-4b06-11d1-ab04-00c04fc2dcd2",
             "ip.src": "10.0.0.9", "ip.dst": "10.0.0.1"},
            {"dcerpc.cn_bind_to_uuid": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
             "ip.src": "10.0.0.9", "ip.dst": "10.0.0.1"},
        ]
        self.assertEqual(len(summarize_dcerpc_binds(rows)), 1)  # deduped

    def test_unknown_uuid_ignored(self):
        rows = [{"dcerpc.cn_bind_to_uuid": "99999999-0000-0000-0000-000000000000",
                 "ip.src": "10.0.0.9", "ip.dst": "10.0.0.2"}]
        self.assertEqual(summarize_dcerpc_binds(rows), [])


class TestAuthAlertWiring(unittest.TestCase):
    def test_severities_and_mitre(self):
        ldap = detect_ldap_findings([
            {"ldap.protocolOp": "0", "ldap.name": "x", "ldap.simple": "p",
             "ip.src": "10.0.0.5", "ip.dst": "10.0.0.1"}])
        dce = detect_dcerpc_abuse(summarize_dcerpc_binds([
            {"dcerpc.cn_bind_to_uuid": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
             "ip.src": "10.0.0.9", "ip.dst": "10.0.0.1"}]))
        alerts = build_alerts({}, [], ldap_findings=ldap, dcerpc_findings=dce)
        by_type = {a["alert_type"]: a for a in alerts}
        self.assertEqual(by_type["LDAP_CLEARTEXT_BIND"]["severity"], "HIGH")
        self.assertEqual(by_type["LDAP_CLEARTEXT_BIND"]["mitre_technique_id"], "T1552")
        self.assertEqual(by_type["DCERPC_DCSYNC"]["severity"], "HIGH")
        self.assertEqual(by_type["DCERPC_DCSYNC"]["mitre_technique_id"], "T1003.006")


if __name__ == "__main__":
    unittest.main()
