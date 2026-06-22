"""Multipart body parsing tests (Content-Transfer-Encoding + field names)."""

import unittest

from modules.payloads import (
    decode_transfer_encoding,
    extract_field_name_from_headers,
    extract_multipart_parts_from_ascii,
    parse_raw_follow_stream_bytes,
)


class TestRawFollowParsing(unittest.TestCase):
    def test_framing_lines_skipped(self):
        # "GET " = 47 45 54 20 ; framing lines (Node/Filter/ports) must NOT
        # contribute stray hex bytes to the front of the stream.
        raw = (
            "\n"
            "===================================================================\n"
            "Follow: tcp,raw\n"
            "Filter: tcp.stream eq 0\n"
            "Node 0: 10.0.0.5:40000\n"
            "Node 1: 1.2.3.4:80\n"
            "47455420\n"                 # "GET " payload (pure hex line)
            "\t485454502f312e31\n"        # server side, tab-indented "HTTP/1.1"
            "===================================================================\n"
        )
        data = parse_raw_follow_stream_bytes(raw)
        self.assertTrue(data.startswith(b"GET "), data[:8])
        self.assertIn(b"HTTP/1.1", data)


class TestMultipartParsing(unittest.TestCase):
    def _body(self):
        return (
            "--BND\r\n"
            'Content-Disposition: form-data; name="upload"; filename="secret.bin"\r\n'
            "Content-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "TVqQAAMAAAAEAAAA\r\n"            # base64 of a PE header
            "--BND\r\n"
            'Content-Disposition: form-data; name="password"\r\n'
            "\r\n"
            "hunter2\r\n"
            "--BND--\r\n"
        )

    def test_base64_part_decoded(self):
        parts = extract_multipart_parts_from_ascii(self._body(), "BND")
        self.assertTrue(parts[0]["body_bytes"].startswith(b"MZ"))
        self.assertEqual(parts[0]["transfer_encoding"], "base64")

    def test_field_names_captured(self):
        parts = extract_multipart_parts_from_ascii(self._body(), "BND")
        self.assertEqual(parts[0]["field_name"], "upload")
        self.assertEqual(parts[0]["filename"], "secret.bin")
        self.assertEqual(parts[1]["field_name"], "password")
        self.assertEqual(parts[1]["body_bytes"], b"hunter2")

    def test_field_name_not_confused_with_filename(self):
        self.assertIsNone(
            extract_field_name_from_headers('Content-Disposition: form-data; filename="x.txt"')
        )

    def test_quoted_printable_decoding(self):
        self.assertEqual(decode_transfer_encoding(b"a=3Db", "quoted-printable"), b"a=b")

    def test_unknown_encoding_passthrough(self):
        self.assertEqual(decode_transfer_encoding(b"raw", "7bit"), b"raw")


if __name__ == "__main__":
    unittest.main()
