"""Unit tests for modules/http2_metadata.py."""

import unittest

from modules.http2_metadata import (
    _decode_h2_bytes,
    _decompress,
    _entropy,
    _looks_text,
    build_http2_body_previews,
    build_http2_sessions,
    extract_http2_bodies,
    HTTP2_CSV_COLUMNS,
)


class TestDecodeH2Bytes(unittest.TestCase):
    def test_single_segment(self):
        # TShark colon-hex: "48:65:6c:6c:6f" → b"Hello"
        self.assertEqual(_decode_h2_bytes("48:65:6c:6c:6f"), b"Hello")

    def test_multi_segment_comma_joined(self):
        # Aggregator joins multiple DATA frames with comma
        self.assertEqual(_decode_h2_bytes("48:65:6c,6c:6f"), b"Hello")

    def test_empty_string(self):
        self.assertEqual(_decode_h2_bytes(""), b"")

    def test_invalid_segment_skipped(self):
        # Garbled segment is silently dropped; the two valid segments decode
        # to "Hel" (48:65:6c) and "lo" (6c:6f) → "Hello"
        result = _decode_h2_bytes("48:65:6c,NOTVALID,6c:6f")
        self.assertEqual(result, b"Hello")


class TestDecompress(unittest.TestCase):
    def test_identity_passthrough(self):
        data = b"hello world"
        self.assertEqual(_decompress(data, "identity"), data)

    def test_empty_data(self):
        self.assertEqual(_decompress(b"", "gzip"), b"")

    def test_no_encoding(self):
        data = b"plain"
        self.assertEqual(_decompress(data, ""), data)

    def test_gzip_roundtrip(self):
        import gzip as _gzip
        original = b"compressed payload"
        compressed = _gzip.compress(original)
        self.assertEqual(_decompress(compressed, "gzip"), original)

    def test_deflate_roundtrip(self):
        import zlib
        original = b"deflate payload"
        # zlib-wrapped deflate (most common)
        compressed = zlib.compress(original)
        self.assertEqual(_decompress(compressed, "deflate"), original)

    def test_unknown_encoding_passthrough(self):
        data = b"raw bytes"
        self.assertEqual(_decompress(data, "snappy"), data)


class TestHelpers(unittest.TestCase):
    def test_entropy_zero_for_uniform(self):
        # Single repeated byte has zero entropy
        self.assertAlmostEqual(_entropy(b"\x00" * 100), 0.0)

    def test_entropy_positive_for_random(self):
        # Mixed bytes have positive entropy
        data = bytes(range(256))
        self.assertGreater(_entropy(data), 7.0)

    def test_looks_text_ascii(self):
        self.assertTrue(_looks_text(b"GET / HTTP/1.1\r\nHost: example.com\r\n"))

    def test_looks_text_binary(self):
        # High bytes that are not valid UTF-8 and are not printable ASCII
        self.assertFalse(_looks_text(bytes([0x80, 0x81, 0x82, 0x83] * 50)))


class TestBuildHttp2Sessions(unittest.TestCase):
    """build_http2_sessions groups frames into request/response pairs."""

    def _make_headers_frame(self, tcp_stream, h2_sid, method=None, status=None,
                             path="/", authority="example.com", src_ip="10.0.0.1",
                             dst_ip="10.0.0.2"):
        return {
            "frame.number": "1",
            "frame.time_epoch": "1700000000.0",
            "ip.src": src_ip,
            "tcp.srcport": "54321",
            "ip.dst": dst_ip,
            "tcp.dstport": "443",
            "tcp.stream": str(tcp_stream),
            "http2.streamid": str(h2_sid),
            "http2.type": "1",  # HEADERS
            "http2.flags.end_stream": "0",
            "http2.headers.method": method or "",
            "http2.headers.path": path,
            "http2.headers.authority": authority,
            "http2.headers.scheme": "https",
            "http2.headers.status": status or "",
            "http2.headers.content_type": "application/json",
            "http2.headers.content_encoding": "",
            "http2.headers.content_length": "",
            "http2.headers.user_agent": "TestAgent/1.0",
            "http2.headers.authorization": "",
            "http2.headers.cookie": "",
            "http2.headers.location": "",
            "http2.headers.server": "nginx",
            "http2.data.data": "",
            "http2.body.reassembled.data": "",
        }

    def _make_data_frame(self, tcp_stream, h2_sid, hex_data, src_ip="10.0.0.2"):
        return {
            "frame.number": "2",
            "frame.time_epoch": "1700000001.0",
            "ip.src": src_ip,
            "tcp.srcport": "443",
            "ip.dst": "10.0.0.1",
            "tcp.dstport": "54321",
            "tcp.stream": str(tcp_stream),
            "http2.streamid": str(h2_sid),
            "http2.type": "0",  # DATA
            "http2.flags.end_stream": "1",
            "http2.headers.method": "",
            "http2.headers.path": "",
            "http2.headers.authority": "",
            "http2.headers.scheme": "",
            "http2.headers.status": "",
            "http2.headers.content_type": "",
            "http2.headers.content_encoding": "",
            "http2.headers.content_length": "",
            "http2.headers.user_agent": "",
            "http2.headers.authorization": "",
            "http2.headers.cookie": "",
            "http2.headers.location": "",
            "http2.headers.server": "",
            "http2.data.data": hex_data,
            "http2.body.reassembled.data": "",
        }

    def test_empty_input(self):
        self.assertEqual(build_http2_sessions([]), [])

    def test_skips_stream_zero(self):
        # h2.streamid == 0 is connection-level; must be ignored
        frame = self._make_headers_frame(0, 0, method="GET")
        self.assertEqual(build_http2_sessions([frame]), [])

    def test_basic_request_response_pair(self):
        req = self._make_headers_frame(1, 1, method="GET", path="/api/v1")
        resp = self._make_headers_frame(1, 1, status="200",
                                        src_ip="10.0.0.2", dst_ip="10.0.0.1")
        sessions = build_http2_sessions([req, resp])
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s["method"], "GET")
        self.assertEqual(s["path"], "/api/v1")
        self.assertEqual(s["status_code"], "200")
        self.assertEqual(s["authority"], "example.com")
        self.assertEqual(s["user_agent"], "TestAgent/1.0")

    def test_normalised_http1_keys_present(self):
        req = self._make_headers_frame(2, 3, method="POST", path="/login")
        sessions = build_http2_sessions([req])
        s = sessions[0]
        self.assertEqual(s["http.request.method"], "POST")
        self.assertEqual(s["http.request.uri"], "/login")
        self.assertEqual(s["http.host"], "example.com")
        self.assertEqual(s["http.user_agent"], "TestAgent/1.0")

    def test_two_independent_streams(self):
        req1 = self._make_headers_frame(1, 1, method="GET", path="/a")
        req2 = self._make_headers_frame(1, 3, method="POST", path="/b")
        sessions = build_http2_sessions([req1, req2])
        self.assertEqual(len(sessions), 2)
        paths = {s["path"] for s in sessions}
        self.assertEqual(paths, {"/a", "/b"})

    def test_data_frame_accumulated_as_response_body(self):
        # Server sends DATA back to client
        req = self._make_headers_frame(5, 1, method="GET", src_ip="10.0.0.1", dst_ip="10.0.0.2")
        # "Hello" in hex
        data = self._make_data_frame(5, 1, "48:65:6c:6c:6f", src_ip="10.0.0.2")
        sessions = build_http2_sessions([req, data])
        self.assertEqual(len(sessions), 1)
        body = sessions[0].get("_response_body")
        self.assertEqual(body, b"Hello")

    def test_csv_columns_are_subset_of_session_keys(self):
        # Every column in HTTP2_CSV_COLUMNS must be present in session output
        req = self._make_headers_frame(10, 1, method="GET")
        resp = self._make_headers_frame(10, 1, status="200",
                                        src_ip="10.0.0.2", dst_ip="10.0.0.1")
        sessions = build_http2_sessions([req, resp])
        self.assertEqual(len(sessions), 1)
        for col in HTTP2_CSV_COLUMNS:
            self.assertIn(col, sessions[0], f"Missing CSV column: {col}")


class TestBuildHttp2BodyPreviews(unittest.TestCase):
    def _session(self, method, body_bytes=None, path="/post", authority="host.example"):
        s = {
            "method": method,
            "path": path,
            "authority": authority,
            "req_content_type": "application/x-www-form-urlencoded",
            "resp_content_length": "",
            "src_ip": "10.0.0.1",
            "_req_body": body_bytes,
            "request_body_preview": body_bytes.decode("utf-8", errors="replace")[:500] if body_bytes else "",
        }
        return s

    def test_get_request_excluded(self):
        previews = build_http2_body_previews([self._session("GET")])
        self.assertEqual(previews, [])

    def test_post_with_body_included(self):
        body = b"username=admin&password=secret"
        previews = build_http2_body_previews([self._session("POST", body)])
        self.assertEqual(len(previews), 1)
        self.assertIn("secret", previews[0]["file_data"])
        self.assertEqual(previews[0]["host"], "host.example")

    def test_post_without_body_excluded(self):
        previews = build_http2_body_previews([self._session("POST", None)])
        self.assertEqual(previews, [])


class TestExtractHttp2Bodies(unittest.TestCase):
    def _session(self, method, req_body=None, resp_body=None):
        return {
            "tcp_stream": "1",
            "h2_stream_id": "3",
            "method": method,
            "path": "/upload",
            "authority": "host.test",
            "status_code": "200",
            "src_ip": "10.0.0.1", "src_port": "4321",
            "dst_ip": "10.0.0.2", "dst_port": "443",
            "req_content_type": "application/octet-stream",
            "resp_content_type": "text/plain",
            "resp_content_encoding": "",
            "req_content_encoding": "",
            "_request_body": req_body,
            "_response_body": resp_body,
        }

    def test_response_body_written(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            sessions = [self._session("GET", resp_body=b"Hello, world!")]
            rows = extract_http2_bodies(sessions, pathlib.Path(td))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["direction"], "response")
            self.assertTrue(pathlib.Path(rows[0]["output_file"]).read_bytes() == b"Hello, world!")

    def test_post_request_body_written(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            sessions = [self._session("POST", req_body=b"data=value")]
            rows = extract_http2_bodies(sessions, pathlib.Path(td))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["direction"], "request")

    def test_get_request_body_skipped(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            sessions = [self._session("GET", req_body=b"ignored")]
            rows = extract_http2_bodies(sessions, pathlib.Path(td))
            # GET request body should not be extracted
            req_rows = [r for r in rows if r["direction"] == "request"]
            self.assertEqual(req_rows, [])

    def test_sha256_populated(self):
        import tempfile, pathlib, hashlib
        with tempfile.TemporaryDirectory() as td:
            body = b"check hash"
            sessions = [self._session("GET", resp_body=body)]
            rows = extract_http2_bodies(sessions, pathlib.Path(td))
            self.assertEqual(rows[0]["sha256"], hashlib.sha256(body).hexdigest())

    def test_entropy_populated(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            sessions = [self._session("GET", resp_body=bytes(range(256)))]
            rows = extract_http2_bodies(sessions, pathlib.Path(td))
            self.assertGreater(rows[0]["entropy"], 7.0)


if __name__ == "__main__":
    unittest.main()
