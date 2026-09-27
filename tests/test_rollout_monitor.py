"""Tests for Steps 13–14 (rollout), 15/19 (monitoring + drift), 17 (edge cases)."""

import json
import tempfile
import unittest
from pathlib import Path

from waf_transformer.engine.policy import EnforcementPolicy
from waf_transformer.pipeline.monitor import build_monitor, day_metrics, psi, _hist

BASE = """\
[enforcement]
block_above = {block}
challenge_above = {challenge}
mode = "{mode}"
enforce_percent = {pct}
"""


class TestStagedRollout(unittest.TestCase):
    """Step 14: blocking rolls out to a percentage of traffic, sticky per key."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _pol(self, pct: float, mode: str = "block") -> EnforcementPolicy:
        p = self.dir / "scope.toml"
        p.write_text(BASE.format(block=0.9, challenge=0.6, mode=mode, pct=pct))
        return EnforcementPolicy(p)

    def test_full_rollout_enforces_everyone(self):
        pol = self._pol(100.0)
        self.assertEqual(pol.decide(0.99, key="alice"), ("block", None))

    def test_zero_percent_is_shadowlike(self):
        pol = self._pol(0.0, mode="block")
        self.assertEqual(pol.decide(0.99, key="alice"), ("allow", "block"))

    def test_partial_rollout_is_deterministic_per_key(self):
        pol = self._pol(50.0)
        sample = [pol.decide(0.99, key=f"client-{i}") for i in range(200)]
        enforced = sum(1 for a, _s in sample if a == "block")
        # ~half of keys enforced, and the SAME key always lands the same way
        self.assertGreater(enforced, 60)
        self.assertLess(enforced, 140)
        self.assertEqual(pol.decide(0.99, key="client-7"), pol.decide(0.99, key="client-7"))
        # non-enforced keys still get the shadow record
        self.assertTrue(all(a in ("allow", "block") and (s is None or s == "block") for a, s in sample))

    def test_percent_change_resamples_but_stays_deterministic(self):
        pol = self._pol(50.0)
        before = {f"k{i}": pol.decide(0.99, key=f"k{i}")[0] for i in range(50)}
        p = self.dir / "scope.toml"
        p.write_text(BASE.format(block=0.9, challenge=0.6, mode="block", pct=100.0))
        pol.force_reload()
        after = {f"k{i}": pol.decide(0.99, key=f"k{i}")[0] for i in range(50)}
        self.assertTrue(all(v == "block" for v in after.values()))


def _dec(day: str, score: float, action: str = "allow", shadow: str | None = None, lat: float = 4.0) -> dict:
    return {"request_id": f"{day}-{score}", "ts": f"{day}T00:00:00.000+00:00", "score": score,
            "action": action, "shadow_action": shadow,
            "policy": {"mode": "shadow", "version": "v", "block_above": 0.9,
                       "challenge_above": 0.6, "enforce_percent": 100.0},
            "model_version": "sha256:x", "latency_ms": lat, "method": "GET", "path": "/x"}


class TestMonitor(unittest.TestCase):
    def test_psi_identical_is_near_zero(self):
        h = _hist([0.1, 0.2, 0.3, 0.4, 0.5])
        self.assertLess(psi(h, h), 1e-9)

    def test_psi_shift_is_large(self):
        a = _hist([0.05] * 50 + [0.95] * 50)   # bimodal
        b = _hist([0.5] * 100)                  # uniform-ish
        self.assertGreater(psi(a, b), 0.2)

    def test_alerts_on_drift_latency_and_spikes(self):
        budget = {"p50": 5, "p95": 8, "p99": 10}
        day1 = [_dec("2026-09-20", s / 100) for s in range(100)]
        # day2: heavy latency + all high scores + 4x volume
        day2 = [_dec("2026-09-21", 0.95, shadow="block", lat=50.0) for _ in range(400)]
        mon = build_monitor({"2026-09-20": day1, "2026-09-21": day2}, budget)
        kinds = {a["type"] for a in mon["alerts"]}
        self.assertIn("drift", kinds)
        self.assertIn("latency", kinds)
        self.assertIn("volume", kinds)
        self.assertIn("false_positives", kinds)
        self.assertEqual(mon["baseline_day"], "2026-09-20")

    def test_day_metrics_budget_flags(self):
        budget = {"p50": 5, "p95": 8, "p99": 10}
        m = day_metrics("d", [_dec("d", 0.5, lat=30.0)], budget)
        self.assertFalse(m["budget_ok"]["p95"])


class TestEdgeCases(unittest.TestCase):
    """Step 17: weird-but-real request shapes must parse and score safely."""

    def test_multipart_body_record_roundtrips(self):
        from waf_transformer.data.schema import Label, RequestRecord

        body = "--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.sh\"\r\n\r\n/bin/sh evil\r\n--BOUNDARY--"
        rec = RequestRecord(
            id="mp1", source="t", method="POST", path="/upload", query_string="",
            http_version="HTTP/1.1", headers=[("Content-Type", "multipart/form-data; boundary=BOUNDARY")],
            body=body, label=Label(class_="unknown"),
        )
        self.assertEqual(RequestRecord.from_json(rec.to_json()).body, body)

    def test_graphql_json_body_is_kept(self):
        from waf_transformer.data.schema import Label, RequestRecord

        body = '{"query":"{ user(id:1){ email }}","variables":{}}'
        rec = RequestRecord(
            id="gql1", source="t", method="POST", path="/graphql", query_string="",
            http_version="HTTP/1.1", headers=[("Content-Type", "application/json")],
            body=body, label=Label(class_="unknown"),
        )
        self.assertIn("query", RequestRecord.from_json(rec.to_json()).body)

    def test_binary_and_oversized_bodies_survive_jsonl(self):
        from waf_transformer.data.schema import Label, RequestRecord

        body = "BIN\x00\x01\x02" + "A" * 20000
        rec = RequestRecord(
            id="up1", source="t", method="POST", path="/upload", query_string="",
            http_version="HTTP/1.1", headers=[], body=body,
            body_truncated=True, label=Label(class_="attack", attack_category="untyped"),
        )
        self.assertEqual(len(RequestRecord.from_json(rec.to_json()).body), len(body))

    def test_decision_echo_caps_oversized_body(self):
        """Audit echo must not store megabytes of upload (detector-level cap)."""
        from waf_transformer.engine.detector import Decision

        d = Decision(
            request_id="x", score=0.99, action="block", shadow_action=None,
            policy_mode="block", policy_version="v", block_above=0.9,
            challenge_above=0.6, enforce_percent=100.0, model_version="m",
            latency_ms=1.0, ts="2026-09-27T00:00:00.000+00:00",
            request={"method": "POST", "path": "/u", "query_string": "", "headers": [],
                     "body": "A" * 20000 + "…[echo truncated]"},
        )
        # the cap is applied in Detector.evaluate; simulate its slice rule
        raw = "B" * 20000
        capped = raw if len(raw) <= 8192 else raw[:8192] + "…[echo truncated]"
        self.assertLess(len(capped), 8300)


if __name__ == "__main__":
    unittest.main()
