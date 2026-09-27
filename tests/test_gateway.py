"""Unit tests for the enforcement gateway (Step 12): status-code contract + audit."""

import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from waf_transformer.pipeline.gateway import DecisionEngine, make_handler

from .test_pipeline import FakeDetector

RAW_ATTACK = (
    "GET /x?q=<script>alert(1)</script> HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
)
RAW_BENIGN = "GET /x?q=shoes HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"


class TestGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        engine = DecisionEngine("unused.pt", Path(cls.tmp.name) / "decisions", detector=FakeDetector())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(engine))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def _call(self, method: str, path: str, body: str | None = None, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body or "", headers=headers or {})
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def test_health(self):
        status, _, body = self._call("GET", "/health")
        self.assertEqual(status, 200)
        j = json.loads(body)
        self.assertEqual(j["status"], "ok")
        self.assertEqual(j["policy"]["mode"], "shadow")

    def test_decision_status_codes_are_the_contract(self):
        # shadow mode: everything is 200 (allow), the would-be action travels in headers
        status, headers, body = self._call("POST", "/waf/decision", RAW_ATTACK)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-WAF-Action"], "allow")
        self.assertEqual(headers["X-WAF-Shadow-Action"], "block")
        j = json.loads(body)
        self.assertEqual(j["score"], 0.95)
        self.assertIsNotNone(j["request"])  # flagged decisions echo the request for audit

    def test_benign_has_no_echo_and_no_shadow(self):
        status, headers, body = self._call("POST", "/waf/decision", RAW_BENIGN)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-WAF-Action"], "allow")
        self.assertNotIn("X-WAF-Shadow-Action", headers)
        self.assertIsNone(json.loads(body).get("request"))

    def test_json_record_and_score_endpoint(self):
        from .test_pipeline import sample_request

        rec = sample_request(7, attack=True)
        status, headers, body = self._call(
            "POST", "/score", json.dumps(rec), headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)  # /score never enforces
        self.assertEqual(json.loads(body)["action"], "allow")

    def test_audit_log_written(self):
        self._call("POST", "/waf/decision", RAW_ATTACK)
        files = list(Path(self.tmp.name, "decisions").glob("decisions-*.jsonl"))
        self.assertTrue(files)
        last = json.loads(files[0].read_text().strip().splitlines()[-1])
        self.assertIn(last["action"], ("allow", "block", "challenge"))

    def test_stats(self):
        status, _, body = self._call("GET", "/stats")
        self.assertEqual(status, 200)
        j = json.loads(body)
        self.assertGreaterEqual(j["total"], 1)
        self.assertIn("latency_ms", j)


if __name__ == "__main__":
    unittest.main()
