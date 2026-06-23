"""Detection-logic and false-positive-tuning regression tests."""

import unittest

from modules.utils import is_private_ip, is_special_use_ip, is_noise_ip
from modules.flows import _new_flow_time_stat, _update_flow_time_stat
from modules.detections import (
    build_alerts,
    build_suspicious_downloads,
    detect_beaconing,
    detect_dns_tunneling,
    detect_suspicious_user_agents,
    detect_tls_sni_anomalies,
)


def _time_stats(timestamps):
    """Build a flow's online time-stats accumulator from a list of timestamps."""
    stat = _new_flow_time_stat()
    for ts in timestamps:
        _update_flow_time_stat(stat, float(ts))
    return stat


class TestIPClassification(unittest.TestCase):
    def test_public_ips_are_not_noise(self):
        for ip in ("8.8.8.8", "93.184.216.34"):
            self.assertFalse(is_noise_ip(ip), ip)

    def test_private_and_special_use_are_noise(self):
        cases = {
            "10.1.2.3": (True, False),
            "169.254.1.1": (True, False),
            "203.0.113.5": (False, True),    # TEST-NET-3
            "198.51.100.7": (False, True),   # TEST-NET-2
            "192.0.2.1": (False, True),      # TEST-NET-1
            "224.0.0.251": (False, True),    # mDNS multicast
            "255.255.255.255": (False, True),
            "0.0.0.0": (False, True),
            "100.64.0.1": (False, True),     # CGNAT
            "ff02::1": (False, True),
            "2001:db8::1": (False, True),
        }
        for ip, (priv, special) in cases.items():
            self.assertEqual(is_private_ip(ip), priv, ip)
            self.assertEqual(is_special_use_ip(ip), special, ip)
            self.assertTrue(is_noise_ip(ip), ip)


class TestDNSTunnelingTuning(unittest.TestCase):
    def _q(self, name, qtype="1"):
        return {"dns.qry.name": name, "dns.qry.type": qtype,
                "ip.src": "10.0.0.5", "ip.dst": "8.8.8.8", "frame.time": ""}

    def test_reverse_dns_not_flagged(self):
        self.assertEqual(detect_dns_tunneling([self._q("5.113.0.203.in-addr.arpa", "12")]), [])

    def test_plain_txt_not_flagged(self):
        self.assertEqual(detect_dns_tunneling([self._q("example.com", "16")]), [])

    def test_null_record_flagged(self):
        self.assertTrue(detect_dns_tunneling([self._q("data.tunnel.net", "10")]))

    def test_high_entropy_flagged(self):
        self.assertTrue(detect_dns_tunneling([self._q("a8f3kd9slxm20vncz01qpwoe88x.evil.net")]))

    def test_cdn_high_volume_skipped(self):
        rows = [self._q(f"x{i}.cloudfront.net") for i in range(60)]
        vol = [f for f in detect_dns_tunneling(rows) if "High query volume" in f["reason"]]
        self.assertEqual(vol, [])


class TestBeaconingDowngrade(unittest.TestCase):
    def test_benign_infra_downgraded_to_info(self):
        ft = {("10.0.0.5", "8.8.8.8", "5000", "53", "UDP"): _time_stats([0, 10, 20, 30, 40, 50])}
        alerts = build_alerts({}, [], beaconing_candidates=detect_beaconing(ft, {k: 1 for k in ft}))
        beacon = [a for a in alerts if a["alert_type"] == "BEACONING_CANDIDATE"][0]
        self.assertEqual(beacon["severity"], "INFO")

    def test_real_destination_stays_high(self):
        ft = {("10.0.0.5", "45.33.32.156", "5000", "443", "TCP"): _time_stats([0, 10, 20, 30, 40, 50])}
        alerts = build_alerts({}, [], beaconing_candidates=detect_beaconing(ft, {k: 1 for k in ft}))
        beacon = [a for a in alerts if a["alert_type"] == "BEACONING_CANDIDATE"][0]
        self.assertEqual(beacon["severity"], "HIGH")


class TestSuspiciousDownloadTiering(unittest.TestCase):
    def _http(self, uri):
        return {"http.request.method": "GET", "http.request.uri": uri,
                "ip.src": "10.0.0.5", "ip.dst": "1.2.3.4"}

    def test_executable_is_high(self):
        d = build_suspicious_downloads([self._http("/x.exe")], [])
        self.assertEqual(d[0]["severity"], "HIGH")

    def test_document_is_medium(self):
        for uri in ("/doc.pdf", "/a.zip"):
            d = build_suspicious_downloads([self._http(uri)], [])
            self.assertEqual(d[0]["severity"], "MEDIUM", uri)


class TestSNICDNSkip(unittest.TestCase):
    def test_cdn_morphology_skipped_evil_flagged(self):
        out = detect_tls_sni_anomalies([
            {"sni": "a1b2c3d4e5f6a7b8c9d0e1f2.cloudfront.net"},
            {"sni": "deadbeefdeadbeef1234567890abcdef.evil.com"},
        ])
        flagged = {f["sni"] for f in out}
        self.assertNotIn("a1b2c3d4e5f6a7b8c9d0e1f2.cloudfront.net", flagged)
        self.assertIn("deadbeefdeadbeef1234567890abcdef.evil.com", flagged)


class TestMultiUAThreshold(unittest.TestCase):
    def _rows(self, n):
        return [{"http.user_agent": f"UA-{i}", "ip.src": "10.0.0.5",
                 "ip.dst": "1.2.3.4", "http.host": "h"} for i in range(n)]

    def test_below_threshold_clean(self):
        hits = [x for x in detect_suspicious_user_agents(self._rows(10))
                if "distinct User-Agent" in x.get("reason", "")]
        self.assertEqual(hits, [])

    def test_at_threshold_flagged(self):
        hits = [x for x in detect_suspicious_user_agents(self._rows(15))
                if "distinct User-Agent" in x.get("reason", "")]
        self.assertTrue(hits)


if __name__ == "__main__":
    unittest.main()
