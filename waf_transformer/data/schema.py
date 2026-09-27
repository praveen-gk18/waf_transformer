"""Canonical request-record schema shared by every stage of the data pipeline.

One record = one HTTP request + its label. JSONL serialization is the interchange
format on disk (data/interim, data/processed). Field names are a stability
contract: later phases (tokenizer, model, serving) depend on them.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator, Literal

LabelClass = Literal["benign", "attack", "unknown"]

# ---------------------------------------------------------------------------
# Dataset class-string -> (class, attack_category) mapping.
# Covers every public corpus we ingest plus synthetic sources. Categories use
# the taxonomy in config/scope.toml; "untyped" = known attack, family unknown.
# ---------------------------------------------------------------------------
DATASET_CLASS_MAP: dict[str, tuple[LabelClass, str | None]] = {
    # CSIC 2010 (binary labels only)
    "valid": ("benign", None),
    "attack": ("attack", "untyped"),
    # ECML/PKDD 2007 (7 attack families)
    "sqlinjection": ("attack", "sql_injection"),
    "xss": ("attack", "xss"),
    "ldapinjection": ("attack", "ldap_injection"),
    "xpathinjection": ("attack", "xpath_injection"),
    "pathtransversal": ("attack", "path_traversal"),
    "oscommanding": ("attack", "command_injection"),
    "ssi": ("attack", "ssi"),
    # Conventional aliases seen in WAF exports
    "benign": ("benign", None),
    "normal": ("benign", None),
    "anomalous": ("attack", "untyped"),
}

# Categories considered "in scope" for v1 acceptance (kept in sync with
# config/scope.toml; validated in tests).
IN_SCOPE_CATEGORIES = ("sql_injection", "xss")
UNSCOPED_OK = ("sql_injection", "xss", "untyped")  # + benign (not an attack)
KNOWN_CATEGORIES = (
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
    "ldap_injection",
    "xpath_injection",
    "ssi",
    "xxe",
    "ssrf",
    "open_redirect",
    "untyped",
)


def category_in_scope(label_class: "LabelClass", category: str | None) -> bool:
    """v1 scope check: benign is always fine; attacks count when SQLi/XSS/untyped."""
    if label_class != "attack":
        return True
    return category is None or category in UNSCOPED_OK


@dataclass
class Label:
    """Ground-truth-ish label with provenance (Step 5 of the plan)."""

    class_: LabelClass                       # "class" in JSON; keyword-safe here
    attack_category: str | None = None
    attack_technique: str | None = None
    in_scope: bool = True
    label_source: str = "unknown"            # manual|waf_export|dataset|heuristic|unknown
    confidence: float = 1.0

    def to_json(self) -> dict[str, Any]:
        return {
            "class": self.class_,
            "attack_category": self.attack_category,
            "attack_technique": self.attack_technique,
            "in_scope": self.in_scope,
            "label_source": self.label_source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "Label":
        return cls(
            class_=obj["class"],
            attack_category=obj.get("attack_category"),
            attack_technique=obj.get("attack_technique"),
            in_scope=bool(obj.get("in_scope", True)),
            label_source=str(obj.get("label_source", "unknown")),
            confidence=float(obj.get("confidence", 1.0)),
        )


@dataclass
class RequestRecord:
    """One full HTTP request with label and grouping metadata."""

    id: str
    source: str                              # csic_2010 | ecml_pkdd_2007 | synthetic:* | waf_export | live
    method: str
    path: str
    query_string: str
    http_version: str
    headers: list[tuple[str, str]]
    body: str
    label: Label
    group_id: str = ""
    source_file: str = ""
    body_truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.group_id:
            self.group_id = f"id:{self.id}"

    # -- JSONL ------------------------------------------------------------
    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "source_file": self.source_file,
            "group_id": self.group_id,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "http_version": self.http_version,
            "headers": [[k, v] for k, v in self.headers],
            "body": self.body,
            "body_truncated": self.body_truncated,
            "label": self.label.to_json(),
            "meta": self.meta,
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "RequestRecord":
        return cls(
            id=obj["id"],
            source=obj["source"],
            method=obj["method"],
            path=obj["path"],
            query_string=obj.get("query_string", ""),
            http_version=obj.get("http_version", "HTTP/1.1"),
            headers=[(k, v) for k, v in obj.get("headers", [])],
            body=obj.get("body", ""),
            label=Label.from_json(obj["label"]),
            group_id=obj.get("group_id", ""),
            source_file=obj.get("source_file", ""),
            body_truncated=bool(obj.get("body_truncated", False)),
            meta=dict(obj.get("meta", {})),
        )

    def request_target(self) -> str:
        """The request target as sent (path + '?' + query)."""
        return f"{self.path}?{self.query_string}" if self.query_string else self.path

    def blob(self) -> str:
        """Flattened text of everything an analyzer should look at.

        Order mirrors how the tokenizer will later treat separate fields:
        method, path, query, header values, body.
        """
        parts = [self.method, self.path, self.query_string]
        parts.extend(f"{k}: {v}" for k, v in self.headers)
        parts.append(self.body)
        return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# JSONL IO helpers
# ---------------------------------------------------------------------------
def write_jsonl(path, records: "list[RequestRecord] | Iterator[RequestRecord]") -> int:
    """Write records to JSONL (optionally .gz by extension). Returns count."""
    import gzip

    n = 0
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "wt", encoding="utf-8") as fh:  # type: ignore[operator]
        for rec in records:
            fh.write(json.dumps(rec.to_json(), ensure_ascii=False, sort_keys=True))
            fh.write("\n")
            n += 1
    return n


def read_jsonl(path) -> Iterator[RequestRecord]:
    """Stream RequestRecord objects from JSONL (optionally .gz)."""
    import gzip

    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:  # type: ignore[operator]
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield RequestRecord.from_json(json.loads(line))
