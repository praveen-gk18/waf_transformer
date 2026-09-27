"""Unit tests for the broker + stream consumer + batch job (Steps 10–11)."""

import json
import tempfile
import unittest
from pathlib import Path

from waf_transformer.pipeline.batch import analyze, build_candidates, load_day
from waf_transformer.pipeline.broker import FileBroker, build_broker
from waf_transformer.pipeline.consumer import StreamConsumer


def sample_request(i: int, attack: bool = False) -> dict:
    return {
        "id": f"req:{i}",
        "source": "test",
        "source_file": "",
        "group_id": f"g{i}",
        "method": "GET",
        "path": "/item?id=1' OR '1'='1" if attack else "/item",
        "query_string": "q=<script>alert(1)</script>" if attack else "q=shoes",
        "http_version": "HTTP/1.1",
        "headers": [["Host", "x"]],
        "body": "",
        "body_truncated": False,
        "label": {"class": "unknown", "attack_category": None, "attack_technique": None,
                  "in_scope": True, "label_source": "unknown", "confidence": 0.0},
        "meta": {},
    }


class FakeDetector:
    """Scores attacks 0.95, benign 0.1 — no torch needed."""

    class _P:
        class _S:
            mode = "shadow"
            block_above = 0.9
            challenge_above = 0.6
            version = "fake"

        state = _S()

        def reload_if_changed(self):
            return False

        def decide(self, score):
            if score >= 0.9:
                return "allow", "block"
            if score >= 0.6:
                return "allow", "challenge"
            return "allow", None

    policy = _P()
    model_version = "sha256:fake"
    operating_threshold = 0.138

    def evaluate(self, rec):
        from waf_transformer.engine.detector import Decision

        score = 0.95 if "script" in rec.query_string or "OR" in rec.path else 0.1
        action, shadow = self.policy.decide(score)
        return Decision(
            request_id=rec.id, score=score, action=action, shadow_action=shadow,
            policy_mode="shadow", policy_version="fake", block_above=0.9,
            challenge_above=0.6, model_version="sha256:fake", latency_ms=1.5,
            ts="2026-09-27T00:00:00.000+00:00", method=rec.method, path=rec.path,
            request={"method": rec.method, "path": rec.path, "query_string": rec.query_string,
                     "headers": [[k, v] for k, v in rec.headers], "body": rec.body}
            if shadow or action != "allow" else None,
        )


class TestFileBroker(unittest.TestCase):
    def test_publish_consume_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            br = FileBroker(tmp)
            for i in range(5):
                br.publish("t", {"n": i})
            got = [m["n"] for m in br.consume("t", "g1")]
            self.assertEqual(got, [0, 1, 2, 3, 4])
            # second consumer group reads from scratch
            self.assertEqual(len(list(br.consume("t", "g2"))), 5)
            # first group resumes at its committed offset
            br.publish("t", {"n": 5})
            self.assertEqual([m["n"] for m in br.consume("t", "g1")], [5])

    def test_build_broker(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsInstance(build_broker("file", base_dir=tmp), FileBroker)
            with self.assertRaises(ValueError):
                build_broker("nats")


class TestStreamConsumer(unittest.TestCase):
    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            br = FileBroker(tmp / "stream")
            for i in range(4):
                br.publish("http.requests.raw", sample_request(i, attack=(i % 2 == 0)))
            consumer = StreamConsumer(
                br, FakeDetector(), decisions_dir=tmp / "decisions", group="test"
            )
            n = consumer.run_once()
            self.assertEqual(n, 4)
            self.assertEqual(consumer.stats["count"], 4)
            self.assertEqual(consumer.stats["shadow_would_block"], 2)  # 2 attacks in shadow mode

            # decisions landed on the out-topic AND the day file
            decisions = br.drain("http.requests.decisions")
            self.assertEqual(len(decisions), 4)
            day_files = list((tmp / "decisions").glob("decisions-*.jsonl"))
            self.assertEqual(len(day_files), 1)
            self.assertEqual(len(day_files[0].read_text().strip().splitlines()), 4)

            # offsets: a fresh consumer run processes nothing (idempotent)
            self.assertEqual(consumer.run_once(), 0)


class TestBatch(unittest.TestCase):
    def test_analyze_and_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            br = FileBroker(tmp / "stream")
            for i in range(6):
                br.publish("http.requests.raw", sample_request(i, attack=(i % 3 == 0)))
            consumer = StreamConsumer(br, FakeDetector(), decisions_dir=tmp / "decisions", group="b")
            consumer.run_once()

            decisions = load_day(tmp / "decisions", "2026-09-27")
            self.assertEqual(len(decisions), 6)
            analysis = analyze(decisions)
            self.assertEqual(analysis["requests"], 6)
            self.assertEqual(analysis["actions"].get("allow"), 6)  # shadow: all allow
            self.assertEqual(analysis["shadow_actions"].get("block"), 2)
            self.assertEqual(analysis["flagged_count"], 2)
            self.assertIn("score_histogram", analysis)

            candidates = build_candidates(decisions)
            self.assertEqual(len(candidates), 2)
            for c in candidates:
                self.assertEqual(c["source"], "live:batch_candidates")
                self.assertTrue(c["id"].startswith("batch:"))
            # attack candidates are heuristically typed (xss from the payload)
            cats = {c["label"]["attack_category"] for c in candidates}
            self.assertIn("xss", cats)


if __name__ == "__main__":
    unittest.main()
