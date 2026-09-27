# Step 6 — Tokenizer Design

**Status: implemented** (`waf_transformer/modeling/tokenizer.py`,
`tests/test_tokenizer.py`). Config: `[tokenizer]` in `config/scope.toml`.

## The choice: character vs sub-word vs bytes

The plan offers character-level ("good at catching obfuscated attacks like
`S%45LECT` but long sequences") or sub-word BPE ("more efficient and still
catches most obfuscation"). I picked the third option that gives character
robustness without BPE's training machinery:

| Option | Obfuscation | Length | OOV | Build cost |
|---|---|---|---|---|
| Character | excellent | long | unicode/control gaps | none |
| BPE (plan option) | good | short | rare | vocab training |
| **Byte-level (chosen)** | **excellent** | **medium-long** | **zero** | **none** |

Rationale for byte-level:

1. **Zero OOV by construction** — `%u0027`, UTF-8 tricks, null bytes, and the
   garbage URLs that literally appear in ECML attacks (spaces in paths,
   control bytes) all encode losslessly. A vocabulary can't have holes if its
   tokens *are* the byte values.
2. **No tokenizer to go stale** — BPE merges learned on 2010-era corpora are
   exactly the thing attackers evade; retraining a vocab is a data-migration
   problem we don't need.
3. Sequence length is capped by design: per-field budgets (below) keep input
   ≤ 384 tokens — p100 of real corpora is 365.

Tradeoff accepted: ~2x sequence length vs BPE → more compute per request.
Mitigated by field budgets and the small model; reevaluate with BPE only if
the Phase-4 latency numbers demand it.

## HTTP structure as tokens (the plan's key requirement)

"Consider treating the method, path, query string, headers, and body as
separate fields and adding special separator tokens between them. This helps
the model understand *where* something appears, not just *what* it is."

```
[CLS] [METH] GET [PATH] /tienda1/publico/caracteristicas.jsp [QUERY] idA=2'...
      [HDR] User-Agent: ...\nCookie: ... [BODY] username=admin'... [SEP]
```

* 10 special tokens: `[PAD] [CLS] [SEP] [TRUNC] [METH] [PATH] [QUERY] [HDR] [BODY] [UNK]`;
  byte tokens occupy ids 10..265.
* `[TRUNC]` marks any field cut by its budget — truncation is visible to the
  model, not silent (Step 17).
* A `WHERE`-sensitivity test locks this in: identical bytes in `[QUERY]` vs
  `[BODY]` produce different id sequences (`tests/test_tokenizer.py`).

## Field budgets (bytes)

| Field | Budget | Why |
|---|---|---|
| method | 8 | `DELETE` is the longest verb |
| path | 88 | covers real paths incl. traversal strings |
| query | 128 | main attack surface |
| headers | 72 | `User-Agent`/`Cookie` carry attacks; rest is boilerplate |
| body | 72 | POST/JSON payloads; huge uploads truncate (Step 17 policy) |

Worst case = 376 tokens ≤ `max_len=384`. Padding is `[PAD]` + attention mask;
padding invariance is unit-tested.

## Vocabulary

`vocab_size = 266` (10 specials + 256 bytes). Decoding is lossless for bytes
(`decode()` is for debugging/inspection only).
