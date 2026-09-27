"""Step 10 — message-broker abstraction.

Two backends behind one tiny interface:

* :class:`FileBroker` — dependency-free JSONL topics with consumer offsets,
  so the whole streaming path runs and is testable anywhere (this sandbox,
  CI, a laptop). Semantics match Kafka for our purposes: append-only topics,
  at-least-once delivery, per-group offsets, restart-safe.
* :class:`KafkaBroker` — the production backend (Step 10's "industry
  standard"). Requires ``kafka-python`` (optional dependency, imported
  lazily) and a reachable cluster (``infra/docker-compose.yml`` runs one).

Message format is plain JSON dicts; request messages are
``RequestRecord.to_json()`` and decision messages are ``Decision.to_json()``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator


class MessageBroker:
    """Minimal publish/consume interface shared by both backends."""

    def publish(self, topic: str, message: dict) -> None:  # pragma: no cover
        raise NotImplementedError

    def consume(self, topic: str, group: str, timeout: float = 0.5) -> Iterator[dict]:
        """Yield messages from `topic` after the group's committed offset."""
        raise NotImplementedError  # pragma: no cover

    def commit(self, topic: str, group: str, offset: int) -> None:  # pragma: no cover
        raise NotImplementedError


class FileBroker(MessageBroker):
    """JSONL-file topics with per-group offsets (append-only, restart-safe)."""

    def __init__(self, base_dir: str | Path = "data/stream"):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def _topic_path(self, topic: str) -> Path:
        return self.base / f"{topic}.jsonl"

    def _offset_path(self, group: str) -> Path:
        return self.base / f".offsets-{group}.json"

    def publish(self, topic: str, message: dict) -> None:
        with self._topic_path(topic).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(message, ensure_ascii=False, sort_keys=True) + "\n")

    def _read_offsets(self, group: str) -> dict[str, int]:
        p = self._offset_path(group)
        if p.exists():
            return json.loads(p.read_text())
        return {}

    def commit(self, topic: str, group: str, offset: int) -> None:
        offsets = self._read_offsets(group)
        offsets[topic] = offset
        self._offset_path(group).write_text(json.dumps(offsets))

    def consume(self, topic: str, group: str, timeout: float = 0.5) -> Iterator[dict]:
        path = self._topic_path(topic)
        offsets = self._read_offsets(group)
        offset = offsets.get(topic, 0)
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if i < offset:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    offset = i + 1
                    self.commit(topic, group, offset)
                    yield json.loads(line)

    def drain(self, topic: str) -> list[dict]:
        """Read a whole topic ignoring offsets (analysis tools)."""
        path = self._topic_path(topic)
        if not path.exists():
            return []
        out = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return out


class KafkaBroker(MessageBroker):
    """Production backend — Apache Kafka (Step 10). Optional dependency."""

    def __init__(self, bootstrap_servers: str = "localhost:9092", client_id: str = "waf-transformer"):
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "KafkaBroker requires kafka-python: pip install kafka-python"
            ) from exc
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            client_id=client_id,
            value_serializer=lambda m: json.dumps(m).encode("utf-8"),
            acks=1,
            linger_ms=5,
        )
        self._servers = bootstrap_servers
        self._client_id = client_id

    def publish(self, topic: str, message: dict) -> None:
        self._producer.send(topic, message)

    def consume(self, topic: str, group: str, timeout: float = 0.5) -> Iterator[dict]:
        from kafka import KafkaConsumer  # type: ignore

        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=self._servers,
            group_id=group,
            client_id=self._client_id,
            enable_auto_commit=True,
            auto_offset_reset="earliest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            consumer_timeout_ms=int(timeout * 1000),
        )
        try:
            for msg in consumer:
                yield msg.value
        finally:
            consumer.close()
            self._producer.flush()

    def commit(self, topic: str, group: str, offset: int) -> None:
        pass  # kafka auto-commit


def build_broker(kind: str = "file", **kwargs) -> MessageBroker:
    if kind == "file":
        return FileBroker(kwargs.get("base_dir", "data/stream"))
    if kind == "kafka":
        return KafkaBroker(kwargs.get("bootstrap_servers", "localhost:9092"))
    raise ValueError(f"unknown broker kind: {kind}")
