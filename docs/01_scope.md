# Step 1 — Scope Definition

**Status: decided.** Machine-readable form: [`config/scope.toml`](../config/scope.toml)
(this document explains *why*; the TOML is what code consumes).

## 1. What attacks we detect first (v1)

| Decision | Value | Rationale |
|---|---|---|
| Objective | Binary: `p(malicious)` per request | The enforcement question is allow/block; per-family scores come later |
| In-scope families | **SQL Injection, XSS** | Highest-prevalence, best public data, clearest labels |
| Out-of-scope (labelled only) | path traversal, command injection, LDAP/XPath injection, SSI, XXE, SSRF, open redirect | Labelled and retained as metadata so v2 models grow without a data migration |
| Untyped attacks | Kept as `attack/untyped` | e.g. CSIC's binary "Attack" rows — real attacks, unknown family |

The model's **acceptance criteria** are defined on the in-scope families;
out-of-scope families must at minimum *not* be labelled benign.

## 2. What "normal" looks like

Normal is application-specific. Our target profile (mirrored in
`[scope.normal_profile]`):

- **E-commerce storefront + JSON API backend** — browsing, search, cart,
  checkout, reviews, account management, `/api/v1/*`.
- Auth: cookie sessions (storefront) and bearer tokens (API).
- Traffic shape: diurnal, bursty at campaign hours.
- **Weird-but-benign tripwires** — the profile explicitly protects:
  apostrophes (`O'Reilly`), SQL words in review prose, `*`/`%` in searches,
  unicode product names, empty/repeated parameters. These become the
  false-positive watchlist in manual review (Step 5) and the false-positive
  budget in Phase 5.

When live traffic is ingested, this profile is *re-validated against reality*
before model training — a mismatch here is a data bug, not a model bug.

## 3. Latency budget

| Metric | Budget |
|---|---|
| p50 | ≤ 5 ms |
| p95 | ≤ 8 ms |
| **p99 (hard cap)** | **≤ 10 ms** |
| Tokenize | 1.5 ms |
| Inference | 5.0 ms |
| Decision + I/O | 1.0 ms |
| Headroom | 2.5 ms |

The p99 hard cap is what the user experience can afford (plan: "under 10
milliseconds"). The breakdown sizes the Phase-3 model: a 4–6 layer encoder
fits the 5 ms inference slice; if benchmarks miss it, the plan's remedies
(quantization, distillation, ONNX Runtime) apply — see `docs/02_tech_stack.md`.

## 4. Explicitly out of scope for v1

- WebSocket / gRPC-streaming payloads (decided as "not supported in v1" —
  front them with a rule-based policy until v2).
- Anything requiring TLS interception of *clients we don't terminate for*.
- Response-side analysis (status codes, reflected payloads in responses).

## Open questions (tracked, not blocking)

- Is a "challenge" verdict (CAPTCHA / rate-limit) enforceable in our gateway?
  Phase 4/5 question; thresholds are pre-declared in `[enforcement]`.
- Per-customer normal profiles (multi-tenant)? v1 assumes one app profile.
