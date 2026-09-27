"""Typed loader for config/scope.toml (the Phase-1 scope contract).

Stdlib-only: TOML is read with ``tomllib`` (Python 3.11+). Every data-pipeline
entry point takes a ``--config`` path defaulting to ``config/scope.toml``.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "scope.toml"


class ConfigError(ValueError):
    """Raised when config/scope.toml is missing required fields or is invalid."""


@dataclass(frozen=True)
class LatencyBudget:
    """End-to-end per-request latency budget in milliseconds (Step 1)."""

    p50: float
    p95: float
    p99: float
    hard_cap: float
    breakdown: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class DatasetRules:
    """Dataset construction rules (Step 5, Step 8, Step 17)."""

    train_fraction: float
    val_fraction: float
    test_fraction: float
    seed: int
    min_attack_ratio: float
    target_attack_ratio: float
    max_attack_ratio: float
    oversample: str
    val_test_ratio: str
    holdout_techniques: tuple[str, ...]
    group_key_priority: tuple[str, ...]
    session_cookie_names: tuple[str, ...]
    body_max_bytes: int
    body_overflow: str
    header_max_count: int
    header_value_max_bytes: int

    def validate(self) -> None:
        total = self.train_fraction + self.val_fraction + self.test_fraction
        if abs(total - 1.0) > 1e-6:
            raise ConfigError(f"split fractions must sum to 1.0, got {total}")
        if not 0.0 < self.min_attack_ratio <= self.target_attack_ratio < 1.0:
            raise ConfigError("require 0 < min_attack_ratio <= target_attack_ratio < 1")
        if self.body_overflow not in ("truncate", "drop"):
            raise ConfigError("body_overflow must be 'truncate' or 'drop'")


@dataclass(frozen=True)
class TokenizerSpec:
    """Step 6: byte-level tokenizer with HTTP field structure."""

    kind: str
    vocab_size: int
    max_len: int
    field_budgets: dict[str, int]
    special_tokens: tuple[str, ...]


@dataclass(frozen=True)
class ModelSpec:
    """Step 7: small encoder-only transformer."""

    architecture: str
    d_model: int
    nhead: int
    num_layers: int
    dim_feedforward: int
    dropout: float
    pooling: str


@dataclass(frozen=True)
class TrainingSpec:
    """Step 8: optimization + class-balance policy."""

    loss: str
    focal_gamma: float
    focal_alpha: float
    pos_weight: str
    epochs: int
    batch_size: int
    learning_rate: float
    weight_decay: float
    warmup_fraction: float
    early_stop_patience: int
    seed: int
    max_train_records: int


@dataclass(frozen=True)
class EvaluationSpec:
    """Step 9: reporting threshold, operating point, adversarial eval."""

    probability_threshold: float
    operating_recall_target: float
    adversarial_extra_encoding_layers: int


@dataclass(frozen=True)
class ScopeConfig:
    """Full scope contract: detection scope, normal profile, budgets, dataset."""

    raw: dict[str, Any]
    path: Path
    in_scope_categories: tuple[str, ...]
    out_of_scope_categories: tuple[str, ...]
    objective: str
    normal_profile: dict[str, Any]
    latency: LatencyBudget
    dataset: DatasetRules
    labeling_priority: tuple[str, ...]
    enforcement: dict[str, Any]
    tokenizer: TokenizerSpec | None = None
    model: ModelSpec | None = None
    training: TrainingSpec | None = None
    evaluation: EvaluationSpec | None = None

    @property
    def all_attack_categories(self) -> tuple[str, ...]:
        return self.in_scope_categories + self.out_of_scope_categories


def _require(table: dict[str, Any], dotted: str) -> Any:
    node: Any = table
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            raise ConfigError(f"missing required config key: {dotted}")
        node = node[key]
    return node


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> ScopeConfig:
    """Load and validate the scope contract. Raises ConfigError on bad input."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"scope config not found: {path}")
    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    dataset_raw = _require(raw, "dataset")
    dataset = DatasetRules(
        train_fraction=float(dataset_raw["train_fraction"]),
        val_fraction=float(dataset_raw["val_fraction"]),
        test_fraction=float(dataset_raw["test_fraction"]),
        seed=int(dataset_raw["seed"]),
        min_attack_ratio=float(dataset_raw["min_attack_ratio"]),
        target_attack_ratio=float(dataset_raw["target_attack_ratio"]),
        max_attack_ratio=float(dataset_raw["max_attack_ratio"]),
        oversample=str(dataset_raw["oversample"]),
        val_test_ratio=str(dataset_raw["val_test_ratio"]),
        holdout_techniques=tuple(dataset_raw.get("holdout_techniques", ())),
        group_key_priority=tuple(dataset_raw["group_key_priority"]),
        session_cookie_names=tuple(dataset_raw["session_cookie_names"]),
        body_max_bytes=int(dataset_raw["body_max_bytes"]),
        body_overflow=str(dataset_raw["body_overflow"]),
        header_max_count=int(dataset_raw["header_max_count"]),
        header_value_max_bytes=int(dataset_raw["header_value_max_bytes"]),
    )
    dataset.validate()

    latency_raw = _require(raw, "latency_budget")
    latency = LatencyBudget(
        p50=float(latency_raw["p50"]),
        p95=float(latency_raw["p95"]),
        p99=float(latency_raw["p99"]),
        hard_cap=float(latency_raw["hard_cap"]),
        breakdown={k: float(v) for k, v in latency_raw.get("breakdown", {}).items()},
    )

    detection = _require(raw, "scope.detection")
    cfg_kwargs: dict[str, Any] = dict(
        raw=raw,
        path=path,
        in_scope_categories=tuple(detection["in_scope_categories"]),
        out_of_scope_categories=tuple(detection["out_of_scope_categories"]),
        objective=str(detection["objective"]),
        normal_profile=dict(_require(raw, "scope.normal_profile")),
        latency=latency,
        dataset=dataset,
        labeling_priority=tuple(_require(raw, "labeling.priority")),
        enforcement=dict(raw.get("enforcement", {})),
    )

    # Phase-3 sections (optional; present in the current scope contract).
    if "tokenizer" in raw:
        tok = raw["tokenizer"]
        cfg_kwargs["tokenizer"] = TokenizerSpec(
            kind=str(tok["kind"]),
            vocab_size=int(tok["vocab_size"]),
            max_len=int(tok["max_len"]),
            field_budgets={k: int(v) for k, v in tok["field_budgets"].items()},
            special_tokens=tuple(tok["special_tokens"]),
        )
    if "model" in raw:
        m = raw["model"]
        cfg_kwargs["model"] = ModelSpec(
            architecture=str(m["architecture"]),
            d_model=int(m["d_model"]),
            nhead=int(m["nhead"]),
            num_layers=int(m["num_layers"]),
            dim_feedforward=int(m["dim_feedforward"]),
            dropout=float(m["dropout"]),
            pooling=str(m["pooling"]),
        )
    if "training" in raw:
        t = raw["training"]
        cfg_kwargs["training"] = TrainingSpec(
            loss=str(t["loss"]),
            focal_gamma=float(t["focal_gamma"]),
            focal_alpha=float(t["focal_alpha"]),
            pos_weight=str(t["pos_weight"]),
            epochs=int(t["epochs"]),
            batch_size=int(t["batch_size"]),
            learning_rate=float(t["learning_rate"]),
            weight_decay=float(t["weight_decay"]),
            warmup_fraction=float(t["warmup_fraction"]),
            early_stop_patience=int(t["early_stop_patience"]),
            seed=int(t["seed"]),
            max_train_records=int(t["max_train_records"]),
        )
    if "evaluation" in raw:
        e = raw["evaluation"]
        cfg_kwargs["evaluation"] = EvaluationSpec(
            probability_threshold=float(e["probability_threshold"]),
            operating_recall_target=float(e["operating_recall_target"]),
            adversarial_extra_encoding_layers=int(e["adversarial_extra_encoding_layers"]),
        )

    cfg = ScopeConfig(**cfg_kwargs)

    # Cross-checks between the taxonomy and the scope list.
    taxonomy = _require(raw, "taxonomy")
    if tuple(taxonomy["in_scope_attack"]) != cfg.in_scope_categories:
        raise ConfigError("taxonomy.in_scope_attack must match scope.detection.in_scope_categories")
    if tuple(taxonomy["out_of_scope_attack"]) != cfg.out_of_scope_categories:
        raise ConfigError(
            "taxonomy.out_of_scope_attack must match scope.detection.out_of_scope_categories"
        )
    return cfg
