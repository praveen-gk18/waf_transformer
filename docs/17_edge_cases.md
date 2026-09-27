# Step 17 — Edge Cases

The plan: *"Handle the edge cases: websockets, file uploads, GraphQL, and any
other non-standard HTTP traffic your app uses."*

The classifier scores **HTTP requests**; anything that isn't one needs a
defined behavior, not a crash. Policy per shape:

| shape | behavior | why |
|---|---|---|
| **file uploads** (multipart/form-data) | score method/path/query + headers + **truncated body**; audit echo caps body at 8 KB | token budget is fixed (384); the first bytes of an upload carry filenames, content-disposition, script stubs. `body_truncated` + `[TRUNC]` tokens make the cap explicit |
| **GraphQL** (JSON body with `query`/`variables`) | scored as ordinary body text — injections live in query text and variables | byte-level tokenizer needs no schema; `type_attack` can still type findings |
| **binary bodies** (protobuf, images) | safe: every byte is a token; scores fall to the body-agnostic path (headers + URL dominate) | no decode failures by construction |
| **websockets / gRPC streams** | out of scope for v1 — the *upgrade request* is scored like any HTTP request; the stream itself is not | scope contract (`docs/01_scope.md`); route around or terminate TLS at the WAF to inspect frames later |
| **chunked / compressed bodies** | forward the *decoded* body to the bridge (the gateway does this); if only raw is available, the truncated raw bytes still tokenize | garbage-in lowers recall but never errors |
| **oversized URLs / header floods** | `max_len` (384) + `[TRUNC]` flags; header count kept in the record | worst case is a low-confidence score → shadow/challenge, never a 500 |

## Implemented guarantees (tests in `tests/test_rollout_monitor.py`)

- multipart and GraphQL bodies round-trip JSONL unchanged;
- binary bodies with NUL/control bytes survive storage;
- oversized bodies are **capped in audit echoes** (score sees the record; the
  audit log stays bounded);
- unparseable raw requests at the gateway return `400` JSON — never 5xx.

## Adding a new shape

1. Extend `data/http_request.parse_request_text` if a new raw syntax must be
   parsed (then it flows to everything).
2. Give the shape a row in the table above — a documented *policy* is part of
   correctness.
3. If the shape needs model attention (recall is poor), add it to the attack
   simulator (`data/generate_attacks.py`) and retrain (Step 16).
