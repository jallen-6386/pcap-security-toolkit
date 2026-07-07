"""JA4 (TLS client) fingerprint tests — validated against TShark 4.6 native."""

import unittest

from modules.ja4 import compute_ja4, _parse_num


class TestParseNum(unittest.TestCase):
    def test_hex_with_prefix(self):
        self.assertEqual(_parse_num("0x1301"), 0x1301)

    def test_decimal(self):
        self.assertEqual(_parse_num("16"), 16)

    def test_hex_without_prefix_fallback(self):
        # Older TShark omits 0x for BASE_HEX fields; c02b must not be dropped
        self.assertEqual(_parse_num("c02b"), 0xc02b)
        self.assertEqual(_parse_num("0a0a"), 0x0a0a)

    def test_empty_returns_none(self):
        self.assertIsNone(_parse_num(""))
        self.assertIsNone(_parse_num("  "))

    def test_garbage_returns_none(self):
        self.assertIsNone(_parse_num("notanumber"))


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

    def test_empty_ciphers_returns_empty(self):
        # Empty cipher list means TShark couldn't parse the packet; no degenerate JA4.
        self.assertEqual(
            compute_ja4("1", "0x0303", "0x0304", "example.com", "", "0,10,13", "h2", "0x0403"),
            "",
        )

    def test_ciphers_without_0x_prefix(self):
        # Older TShark may output cipher suites without 0x prefix.
        # c02b (0xc02b=49195) and c02f (0xc02f=49199) must parse via hex fallback.
        ja4_nopfx = compute_ja4(
            handshake_type="1",
            tls_version_hex="0x0303",
            supported_versions_raw="0x0304,0x0303",
            sni="example.com",
            ciphersuites_raw="1301,1302,1303,c02b,c02f,009e",
            extensions_raw="0,10,13,16,43",
            alpn_raw="h2,http/1.1",
            sig_algs_raw="0403,0804,0401",
        )
        # Cipher count and prefix should match the 0x-prefixed baseline
        self.assertEqual(ja4_nopfx[:4], "t13d")
        self.assertEqual(ja4_nopfx[4:6], "06")   # 6 ciphers parsed (not dropped)

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
