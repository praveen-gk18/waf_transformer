"""Unit tests for HTTP request parsing and decoding."""

import unittest

from waf_transformer.data.http_request import (
    decode_layers,
    extract_group_id,
    parse_request_text,
    split_target,
)

REQ = (
    "POST /tienda1/autenticar?next=%2Fcart HTTP/1.1\n"
    "Host: shop.example.local\n"
    "Cookie: theme=dark; JSESSIONID=ABC123\n"
    "Content-Type: application/x-www-form-urlencoded\n"
    "\n"
    "username=alice&password=x"
)


class TestHttpRequest(unittest.TestCase):
    def test_parse_full_request(self):
        raw = parse_request_text(REQ)
        self.assertIsNotNone(raw)
        self.assertEqual(raw.method, "POST")
        self.assertEqual(raw.path, "/tienda1/autenticar")
        self.assertEqual(raw.query_string, "next=%2Fcart")
        self.assertEqual(raw.body, "username=alice&password=x")
        self.assertEqual(raw.header("host"), "shop.example.local")

    def test_null_body_is_empty(self):
        raw = parse_request_text("GET /a HTTP/1.1\nHost: h\n\nnull\n")
        self.assertEqual(raw.body, "")

    def test_absolute_form_target(self):
        path, query = split_target("http://localhost:8080/tienda1/p.jsp?idA=2")
        self.assertEqual(path, "/tienda1/p.jsp")
        self.assertEqual(query, "idA=2")

    def test_malformed_returns_none(self):
        self.assertIsNone(parse_request_text("NOT A REQUEST\nfoo: bar\n"))
        self.assertIsNone(parse_request_text(""))

    def test_spaces_in_url_survive(self):
        raw = parse_request_text(
            'GET /scripts/file.bat" & dir c:/ .exe? HTTP/1.0\nHost: x\n'
        )
        self.assertIsNotNone(raw)
        self.assertIn("file.bat", raw.path)

    def test_missing_http_version_survives(self):
        raw = parse_request_text("GET /some/long/path.pl\nHost: x\n")
        self.assertIsNotNone(raw)
        self.assertEqual(raw.http_version, "HTTP/1.1")  # default
        self.assertTrue(raw.path.endswith(".pl"))

    def test_control_bytes_in_target_survive(self):
        raw = parse_request_text("GET ..%5c../..\x1c../winnt/cmd.exe?/c+dir HTTP/1.1\nHost: x\n")
        self.assertIsNotNone(raw)
        self.assertIn("cmd.exe", raw.path)

    def test_decode_layers(self):
        self.assertEqual(decode_layers("S%45LECT"), "SELECT")
        self.assertEqual(decode_layers("S%2545LECT"), "SELECT")  # double-encoded
        self.assertEqual(decode_layers("%3Cscript%3E"), "<script>")
        self.assertEqual(decode_layers("&#x3c;script&#x3e;"), "<script>")
        self.assertEqual(decode_layers("plain text 100%"), "plain text 100%")

    def test_group_id_prefers_session_cookie(self):
        headers = [("Cookie", "theme=dark; JSESSIONID=ABC123"), ("Client-ip", "10.0.0.9")]
        gid = extract_group_id(headers, ("JSESSIONID",), fallback="id:1")
        self.assertEqual(gid, "sess:JSESSIONID=ABC123")

    def test_group_id_falls_back_to_client_ip(self):
        headers = [("Client-ip", "10.0.0.9")]
        self.assertEqual(extract_group_id(headers, ("JSESSIONID",), "id:1"), "ip:10.0.0.9")

    def test_group_id_last_resort_is_fallback(self):
        self.assertEqual(extract_group_id([], ("JSESSIONID",), "gen:sqli:0"), "gen:sqli:0")


if __name__ == "__main__":
    unittest.main()
