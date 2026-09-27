"""Detector: request -> p(malicious) -> enforcement decision.

Loads the Phase-3 checkpoint ONCE and scores whole HTTP requests with the
same byte-level tokenizer the model was trained with. Every decision carries
its latency (Step 9/10 budget tracking) and audit metadata (model + policy
versions).

Usage (library)::

    det = Detector("artifacts/run1/best.pt")
    decision = det.evaluate(record)

Torch is imported lazily so the surrounding pipeline (brokers, policy, batch
job) stays importable on dependency-free boxes.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import DEFAULT_CONFIG_PATH
from .policy import EnforcementPolicy


@dataclass
class Decision:
    """One enforcement decision — the audit record (Step 10)."""

    request_id: str
    score: float
    action: str                     # allow | challenge | block
    shadow_action: str | None       # what would happen outside shadow mode
    policy_mode: str
    policy_version: str
    block_above: float
    challenge_above: float
    model_version: str
    latency_ms: float
    ts: str
    method: str = ""
    path: str = ""
    request: dict | None = field(default=None)  # echoed only when flagged

    def to_json(self) -> dict:
        out = {
            "request_id": self.request_id,
            "ts": self.ts,
            "score": round(self.score, 5),
            "action": self.action,
            "shadow_action": self.shadow_action,
            "policy": {
                "mode": self.policy_mode,
                "version": self.policy_version,
                "block_above": self.block_above,
                "challenge_above": self.challenge_above,
            },
            "model_version": self.model_version,
            "latency_ms": round(self.latency_ms, 3),
            "method": self.method,
            "path": self.path,
        }
        if self.request is not None:
            out["request"] = self.request
        return out


class Detector:
    """Model + policy scoring facade."""

    def __init__(self, checkpoint: str | Path = "artifacts/run1/best.pt",
                 config_path=None, policy: EnforcementPolicy | None = None):
        self.checkpoint_path = Path(checkpoint)
        self.policy = policy or EnforcementPolicy(config_path or DEFAULT_CONFIG_PATH)
        self.model_version = "unloaded"
        self._model = None
        self._tokenizer = None
        self._torch = None

    # -- lazy load -------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        import torch

        from ..config import load_config
        from ..modeling.evaluate import load_checkpoint
        from ..modeling.tokenizer import HttpByteTokenizer

        self._torch = torch
        cfg = load_config(self.policy._path)
        self._tokenizer = HttpByteTokenizer(cfg.tokenizer)
        self._model, self._ckpt = load_checkpoint(self.checkpoint_path, torch.device("cpu"))
        self._operating_threshold = float(self._ckpt.get("operating_threshold", 0.5))
        h = hashlib.sha256(self.checkpoint_path.read_bytes()).hexdigest()[:12]
        self.model_version = f"sha256:{h}"

    @property
    def operating_threshold(self) -> float:
        self._ensure_loaded()
        return self._operating_threshold

    # -- scoring ---------------------------------------------------------
    def score(self, rec) -> float:
        """p(malicious) for one RequestRecord-like object."""
        self._ensure_loaded()
        torch = self._torch
        enc = self._tokenizer.encode_record(rec)
        ids = torch.tensor([enc.ids], dtype=torch.long)
        mask = (ids != 0).long()
        with torch.no_grad():
            logit = self._model(ids, mask)
        return float(torch.sigmoid(logit))

    def evaluate(self, rec) -> Decision:
        """Score + policy decision + latency, with thresholds hot-reloaded."""
        t0 = time.perf_counter()
        self.policy.reload_if_changed()
        score = self.score(rec)
        action, shadow_action = self.policy.decide(score)
        latency = (time.perf_counter() - t0) * 1000.0
        st = self.policy.state
        import datetime as dt

        flagged = action != "allow" or shadow_action not in (None, "allow")
        return Decision(
            request_id=rec.id,
            score=score,
            action=action,
            shadow_action=shadow_action,
            policy_mode=st.mode,
            policy_version=st.version,
            block_above=st.block_above,
            challenge_above=st.challenge_above,
            model_version=self.model_version,
            latency_ms=latency,
            ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
            method=rec.method,
            path=rec.path,
            request={
                "method": rec.method,
                "path": rec.path,
                "query_string": rec.query_string,
                "headers": [[k, v] for k, v in rec.headers],
                "body": rec.body,
            }
            if flagged
            else None,
        )
