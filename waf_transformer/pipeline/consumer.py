"""Step 10 — stream consumer: broker -> tokenizer+model -> decision -> audit.

Reads full HTTP requests from the input topic (JSONL RequestRecord messages,
the same schema the log shippers emit), scores each with the detector, applies
the enforcement policy, and publishes the decision to the output topic plus a
per-day decisions file (the audit log / batch-job input — Step 11).

All within the latency budget: decisions carry measured per-request latency so
the Step-15 dashboards can chart p50/p95/p99 against scope.toml.

Usage::

    # process everything currently in the topic, then exit (CI / demo)
    python3 -m waf_transformer.pipeline.consumer --once

    # follow the topic like a real consumer group (production)
    python3 -m waf_transformer.pipeline.consumer --follow
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

from ..engine.detector import Detector
from .broker import MessageBroker, build_broker


class StreamConsumer:
    """Idempotent request->decision consumer with running stats."""

    def __init__(self, broker: MessageBroker, detector, in_topic: str = "http.requests.raw",
                 out_topic: str = "http.requests.decisions", decisions_dir: Path | Path = Path("data/decisions"),
                 group: str = "waf-detector-v1"):
        self.broker = broker
        self.detector = detector
        self.in_topic = in_topic
        self.out_topic = out_topic
        self.decisions_dir = Path(decisions_dir)
        self.decisions_dir.mkdir(parents=True, exist_ok=True)
        self.group = group
        self.stats = {"count": 0, "allow": 0, "challenge": 0, "block": 0,
                      "shadow_would_block": 0, "shadow_would_challenge": 0, "latencies": []}

    def _record(self, message: dict) -> None:
        from ..data.schema import RequestRecord

        rec = RequestRecord.from_json(message)
        decision = self.detector.evaluate(rec)
        out = decision.to_json()
        self.broker.publish(self.out_topic, out)
        day = decision.ts[:10]
        with (self.decisions_dir / f"decisions-{day}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(out, ensure_ascii=False, sort_keys=True) + "\n")
        s = self.stats
        s["count"] += 1
        s[decision.action] = s.get(decision.action, 0) + 1
        if decision.shadow_action == "block":
            s["shadow_would_block"] += 1
        elif decision.shadow_action == "challenge":
            s["shadow_would_challenge"] += 1
        s["latencies"].append(decision.latency_ms)

    def run_once(self, timeout: float = 0.5, limit: int | None = None) -> int:
        """Consume everything currently available; returns messages processed."""
        n = 0
        for msg in self.broker.consume(self.in_topic, self.group, timeout):
            self._record(msg)
            n += 1
            if limit and n >= limit:
                break
        return n

    def run_follow(self, poll: float = 1.0, idle_exit_after: float | None = None) -> None:
        """Keep consuming (production loop). idle_exit_after is for demos."""
        idle_since = time.time()
        while True:
            n = self.run_once()
            if n:
                idle_since = time.time()
                self.print_stats()
            elif idle_exit_after and (time.time() - idle_since) > idle_exit_after:
                self.print_stats()
                return
            time.sleep(poll)

    def print_stats(self) -> None:
        from ..modeling.metrics import percentile

        s = self.stats
        lat = s["latencies"]
        print(json.dumps({
            "processed": s["count"],
            "allow": s.get("allow", 0),
            "challenge": s.get("challenge", 0),
            "block": s.get("block", 0),
            "shadow_would_block": s["shadow_would_block"],
            "shadow_would_challenge": s["shadow_would_challenge"],
            "latency_ms": {
                "p50": round(percentile(lat, 50), 3),
                "p95": round(percentile(lat, 95), 3),
                "p99": round(percentile(lat, 99), 3),
            } if lat else None,
        }, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="WAF stream consumer (request -> decision)")
    ap.add_argument("--broker", choices=["file", "kafka"], default="file")
    ap.add_argument("--broker-dir", default="data/stream")
    ap.add_argument("--kafka-servers", default="localhost:9092")
    ap.add_argument("--in-topic", default="http.requests.raw")
    ap.add_argument("--out-topic", default="http.requests.decisions")
    ap.add_argument("--decisions-dir", default="data/decisions")
    ap.add_argument("--checkpoint", default="artifacts/run1/best.pt")
    ap.add_argument("--once", action="store_true", help="drain current backlog and exit")
    ap.add_argument("--follow", action="store_true", help="keep consuming (production)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--idle-exit", type=float, default=None, help="with --follow: exit after N idle seconds (demo)")
    args = ap.parse_args(argv)

    if not (args.once or args.follow):
        args.once = True

    broker = build_broker(
        args.broker,
        base_dir=args.broker_dir,
        bootstrap_servers=args.kafka_servers,
    )
    detector = Detector(args.checkpoint)
    consumer = StreamConsumer(
        broker, detector, args.in_topic, args.out_topic, Path(args.decisions_dir)
    )
    print(f"consumer up: broker={args.broker} in={args.in_topic} out={args.out_topic} "
          f"policy_mode={detector.policy.state.mode} model={args.checkpoint}")
    if args.once:
        n = consumer.run_once(limit=args.limit)
        print(f"processed {n} messages")
        consumer.print_stats()
    else:
        consumer.run_follow(idle_exit_after=args.idle_exit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
