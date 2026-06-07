"""Stream-triage scoring and TShark text-parser tests."""

import unittest
from unittest import mock

from modules.stream_triage import score_streams
from modules import tshark_stats


class TestStreamTriage(unittest.TestCase):
    def _pkt(self, sid, dst, length, **kw):
        row = {"tcp.stream": sid, "ip.src": "10.0.0.5", "ip.dst": dst,
               "tcp.srcport": "40000", "tcp.dstport": "443",
               "frame.len": str(length), "frame.time_epoch": "1000.0"}
        row.update(kw)
        return row

    def test_content_signals_outrank_health_noise(self):
        rows = []
        rows += [self._pkt("0", "93.184.216.34", 60000) for _ in range(5)]
        rows += [self._pkt("1", "10.0.0.9", 100, **{"tcp.analysis.retransmission": "1"})
                 for _ in range(3)]
        result = score_streams(
            rows,
            carved_files=[{"tcp_stream": "0"}],
            credential_findings=[{"tcp_stream": "0"}],
        )
        # Stream 0 (carved + credential + external) must rank first.
        self.assertEqual(result[0]["tcp_stream"], "0")
        self.assertGreater(result[0]["suspicion_score"], result[-1]["suspicion_score"])

    def test_empty_input(self):
        self.assertEqual(score_streams([]), [])


_EXPERT_FIXTURE = """
Notes (6)
=============
   Frequency      Group           Protocol  Summary
           6   Sequence                TCP  This frame is a (suspected) retransmission

Errors (2)
=============
   Frequency      Group           Protocol  Summary
           2   Malformed               TCP  Malformed Packet
"""

_PHS_FIXTURE = """
===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:21 bytes:1881
  eth                                    frames:21 bytes:1881
    ip                                   frames:21 bytes:1881
      tcp                                frames:18 bytes:1668
===================================================================
"""

_CRED_FIXTURE = """===================================================================
Packet     Protocol         Username         Info
------     --------         --------         --------
3          HTTP basic auth  bob
===================================================================
"""


def _fake_run(stdout):
    return mock.Mock(returncode=0, stdout=stdout, stderr="")


class TestTsharkParsers(unittest.TestCase):
    def test_split_expert_row_multiword_group(self):
        self.assertEqual(
            tshark_stats._split_expert_row("    2   Response Code   HTTP  404 Not Found"),
            (2, "Response Code", "HTTP", "404 Not Found"),
        )

    def test_expert_parser(self):
        with mock.patch("modules.tshark_stats.find_tshark", return_value="tshark"), \
             mock.patch("modules.tshark_stats.subprocess.run", return_value=_fake_run(_EXPERT_FIXTURE)):
            rows, _raw, err = tshark_stats.run_expert_info("x.pcap")
        self.assertIsNone(err)
        sev = {r["severity"] for r in rows}
        self.assertEqual(sev, {"Note", "Error"})
        self.assertTrue(any(r["group"] == "Malformed" for r in rows))

    def test_protocol_hierarchy_parser(self):
        with mock.patch("modules.tshark_stats.find_tshark", return_value="tshark"), \
             mock.patch("modules.tshark_stats.subprocess.run", return_value=_fake_run(_PHS_FIXTURE)):
            rows, _raw, err = tshark_stats.run_protocol_hierarchy("x.pcap")
        self.assertIsNone(err)
        protos = {r["protocol"]: r for r in rows}
        self.assertEqual(protos["tcp"]["frames"], 18)
        self.assertEqual(protos["tcp"]["depth"], 3)

    def test_credentials_parser_multiword_protocol(self):
        with mock.patch("modules.tshark_stats.find_tshark", return_value="tshark"), \
             mock.patch("modules.tshark_stats.subprocess.run", return_value=_fake_run(_CRED_FIXTURE)):
            rows, _raw, err = tshark_stats.run_credentials("x.pcap")
        self.assertIsNone(err)
        self.assertEqual(rows[0]["protocol"], "HTTP basic auth")
        self.assertEqual(rows[0]["username"], "bob")


if __name__ == "__main__":
    unittest.main()
