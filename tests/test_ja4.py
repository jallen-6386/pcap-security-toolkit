"""JA4 (TLS client) fingerprint tests — validated against TShark 4.6 native."""

import unittest

from modules.ja4 import compute_ja4


class TestComputeJA4(unittest.TestCase):
    def test_basic_clienthello(self):
        # Raw fields exactly as TShark renders them (extension types in decimal,
        # everything else hex-prefixed). Expected value is TShark 4.6 native JA4.
        ja4 = compute_ja4(
            handshake_type="1",
            tls_version_hex="0x0303",
            supported_versions_raw="0x0304,0x0303",
            sni="example.com",
            ciphersuites_raw="0x1301,0x1302,0x1303,0xc02b,0xc02f,0x009e",
            extensions_raw="0,10,13,16,43",
            alpn_raw="h2,http/1.1",
            sig_algs_raw="0x0403,0x0804,0x0401",
        )
        self.assertEqual(ja4, "t13d0605h2_f5ef47b819b7_beb9f91c6f80")

    def test_grease_and_http11_alpn(self):
        # GREASE in ciphers/supported_versions must be ignored; ALPN "http/1.1"
        # contributes first+last char ("h1"). Expected = TShark 4.6 native.
        ja4 = compute_ja4(
            handshake_type="1",
            tls_version_hex="0x0303",
            supported_versions_raw="0x0a0a,0x0304,0x0303",
            sni="mail.example.org",
            ciphersuites_raw="0x0a0a,0x1301,0xc030,0xc02c,0x009f,0x006b",
            extensions_raw="0,10,13,16,43",
            alpn_raw="http/1.1,h2",
            sig_algs_raw="0x0804,0x0403",
        )
        self.assertEqual(ja4, "t13d0505h1_e28320c34f02_47b461364fc6")

    def test_non_clienthello_returns_empty(self):
        self.assertEqual(compute_ja4("2", "0x0303", "", "", "", "", "", ""), "")

    def test_extension_count_includes_sni_and_alpn(self):
        # 5 extension types (0=SNI,10,13,16=ALPN,43) -> count 05 in JA4_a.
        ja4 = compute_ja4(
            handshake_type="1", tls_version_hex="0x0303",
            supported_versions_raw="0x0304,0x0303", sni="x.com",
            ciphersuites_raw="0x1301,0x1302", extensions_raw="0,10,13,16,43",
            alpn_raw="h2", sig_algs_raw="0x0403",
        )
        self.assertEqual(ja4[:10], "t13d0205h2")  # 2 ciphers, 5 extensions


if __name__ == "__main__":
    unittest.main()
