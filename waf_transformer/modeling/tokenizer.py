"""Step 6 — HTTP-structured byte-level tokenizer.

Design (docs/06_tokenizer.md):

* **Byte-level tokens** (256 values) — char-level obfuscation robustness
  (`S%45LECT`, `%u0027`, unicode tricks) with zero OOV; any input is a
  sequence of bytes, full stop.
* **Field structure as special tokens** — the plan's "understand HTTP
  structure": ``[CLS] [METH] method [PATH] path [QUERY] query [HDR] headers
  [BODY] body [SEP]``, so the model knows *where* something appears, not just
  *what* it is. A ``[TRUNC]`` marker flags any field cut by its budget.
* **Per-field budgets** (scope.toml) keep the sequence bounded and protect
  the model from 2 MB upload bodies (Step 17 truncation policy).

Pure Python — no torch import; the model code consumes the id lists.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import TokenizerSpec

PAD, CLS, SEP, TRUNC, METH, PATH, QUERY, HDR, BODY, UNK = range(10)
BYTE_OFFSET = 10  # byte value b -> token id BYTE_OFFSET + b
N_SPECIAL = 10
VOCAB_SIZE = N_SPECIAL + 256

SPECIAL_NAMES = ["[PAD]", "[CLS]", "[SEP]", "[TRUNC]", "[METH]", "[PATH]", "[QUERY]", "[HDR]", "[BODY]", "[UNK]"]


@dataclass
class EncodedRequest:
    """Token ids + bookkeeping for one request."""

    ids: list[int]
    truncated_fields: list[str]


class HttpByteTokenizer:
    """Byte-level tokenizer with HTTP field separators."""

    def __init__(self, spec: TokenizerSpec | None = None):
        budgets = {"method": 8, "path": 96, "query": 160, "headers": 96, "body": 128}
        self.max_len = 512
        if spec is not None:
            budgets = dict(spec.field_budgets)
            self.max_len = spec.max_len
        self.budgets = budgets

    # -- encode ----------------------------------------------------------
    def encode(
        self,
        method: str,
        path: str,
        query: str,
        headers: list[tuple[str, str]],
        body: str,
    ) -> EncodedRequest:
        ids: list[int] = [CLS]
        truncated: list[str] = []

        def field(tag: int, raw: bytes, budget: int, name: str) -> None:
            ids.append(tag)
            ids.extend(BYTE_OFFSET + b for b in raw[:budget])
            if len(raw) > budget:
                ids.append(TRUNC)
                truncated.append(name)

        field(METH, method.encode("utf-8", "replace"), self.budgets["method"], "method")
        field(PATH, path.encode("utf-8", "replace"), self.budgets["path"], "path")
        field(QUERY, query.encode("utf-8", "replace"), self.budgets["query"], "query")
        hdr_blob = "\n".join(f"{k}:{v}" for k, v in headers).encode("utf-8", "replace")
        field(HDR, hdr_blob, self.budgets["headers"], "headers")
        field(BODY, body.encode("utf-8", "replace"), self.budgets["body"], "body")
        ids.append(SEP)
        return EncodedRequest(ids=ids[: self.max_len], truncated_fields=truncated)

    def encode_record(self, rec) -> EncodedRequest:
        """Encode a RequestRecord-like object (duck-typed for tests)."""
        return self.encode(rec.method, rec.path, rec.query_string, rec.headers, rec.body)

    # -- decode (debug/inspection) ---------------------------------------
    def decode(self, ids: list[int]) -> str:
        out: list[str] = []
        for tid in ids:
            if tid < N_SPECIAL:
                out.append(SPECIAL_NAMES[tid])
            elif N_SPECIAL <= tid < VOCAB_SIZE:
                out.append(chr(tid - BYTE_OFFSET))
            else:
                out.append("[UNK]")
        return "".join(out)


def batch_encode(tokenizer: HttpByteTokenizer, records: list, pad_to: int | None = None):
    """Encode records -> (ids_batch, mask_batch) as lists of equal-length lists.

    Pads with PAD=0; mask is 1 for real tokens. ``pad_to`` pads to a fixed
    length (used by the latency benchmark for realistic fixed shapes).
    """
    encoded = [tokenizer.encode_record(r) for r in records]
    width = max(len(e.ids) for e in encoded) if encoded else 0
    if pad_to is not None:
        width = max(width, pad_to)
    width = min(width, tokenizer.max_len)
    ids_batch, mask_batch = [], []
    for e in encoded:
        ids = (e.ids + [PAD] * width)[:width]
        mask = [1 if tid != PAD else 0 for tid in ids]
        ids_batch.append(ids)
        mask_batch.append(mask)
    return ids_batch, mask_batch
