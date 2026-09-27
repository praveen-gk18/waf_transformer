# Step 14 — Staged Blocking Rollout

## The mechanism

The plan: *"roll out actual blocking gradually — a percentage of traffic or
specific routes first"*. Two config knobs, zero code changes:

```toml
[enforcement]
mode = "challenge"      # or "block" for hard enforcement
enforce_percent = 10    # Step 14: only 10% of traffic gets enforced
```

`enforce_percent` is **deterministic traffic sampling**: each request is
hashed (`meta.client_key` if the gateway sets one, else the request id) into
0–99; only keys below `enforce_percent` are enforced. The rest are treated as
shadow (allowed, with `shadow_action` recorded). The same client key always
lands on the same side while the percentage is stable — no flicker between
blocked and allowed.

## The rollout ladder

| stage | config | effect |
|---|---|---|
| 1. observe | `mode = "shadow"` | nothing enforced, everything recorded |
| 2. soft | `mode = "challenge"` | CAPTCHAs/rate-limits only — no hard 403s ever (`block` maps to `challenge`) |
| 3. canary | `mode = "block"`, `enforce_percent = 5` | 5% of traffic fully enforced |
| 4. ramp | `enforce_percent` 25 → 50 → 100 | watch `monitor` alerts at each step |
| 5. full | `mode = "block"`, `enforce_percent = 100` | steady state |

Each rung is one edit of `config/scope.toml` — the file is hot-reloaded on the
next request (`POST /reload` to force it). Roll **back** the same way: lower
the percentage or drop to `shadow`. The `X-WAF-Shadow-Action` header and the
nightly watchlist keep working throughout, so you can see what the unenforced
portion is missing.

## Sticky sampling (client keys)

For per-client consistency (a given user shouldn't flip-flop mid-session),
have the integration pass a stable key — e.g. set `meta.client_key` on the
JSON record (cookie/session id, or client IP). Without it, sampling is per
request, which is fine for load-based canaries.

## Verifying the stage

```bash
curl -s -D- --data-binary @sample.raw http://127.0.0.1:8089/waf/decision | grep -i x-waf
# enforced key:  X-WAF-Action: block   (403)
# sampled-out key: X-WAF-Action: allow + X-WAF-Shadow-Action: block (200)
python3 -m waf_transformer.pipeline.monitor   # alerts while ramping
```
