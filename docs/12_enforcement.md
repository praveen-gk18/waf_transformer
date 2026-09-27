# Step 12 — Enforcement Bridge

## The contract

The plan:

> *"Define exactly how a score maps to a decision: > 0.9 → block (403);
> 0.6–0.9 → challenge (CAPTCHA or rate limit); < 0.6 → allow. But make these
> thresholds configurable without redeploying the model — store them in a
> config file or feature flag system. Integrate with your reverse proxy or
> API gateway (Nginx, Kong, Envoy) to actually enforce the block/allow
> decisions. The model decides; the gateway enforces."*

Two pieces:

1. **Policy** (`waf_transformer/engine/policy.py`) — thresholds from
   `config/scope.toml [enforcement]`, **hot-reloaded on file change** (mtime
   checked per decision). No model redeploy, no restart. Every decision
   records the policy version (content hash) for audit.
2. **Gateway bridge** (`waf_transformer/pipeline/gateway.py`) — an HTTP
   service the proxy calls per request. The **status code is the decision**:

| policy action | bridge status | nginx `auth_request` result |
|---|---|---|
| allow | 200 | request proceeds |
| block | 403 | `error_page 403 = @waf_block` |
| challenge | 429 | `error_page 429 = @waf_challenge` |

Extra headers for debugging/audit: `X-WAF-Score`, `X-WAF-Action`,
`X-WAF-Shadow-Action`.

## Configuration (no redeploy)

```toml
[enforcement]
mode = "shadow"          # shadow | challenge | block
block_above = 0.9
challenge_above = 0.6
```

- `mode = "shadow"` — **never** blocks; records `shadow_action` (what would
  have happened). This is the Phase-5 (Step 13) rollout mode and the default.
- `mode = "challenge"` — everything at/above `block_above` is also challenged
  (rate-limit first, no hard blocks).
- `mode = "block"` — full enforcement.

Edit the file → next decision picks it up. `POST /reload` forces it.

## Nginx wiring

See **`infra/nginx/waf_enforcement.conf`** — `auth_request /_waf` →
`proxy_pass http://waf-gateway:8089/waf/decision` with the request body
forwarded. Kong/Envoy equivalents are the same shape (ext-authz service that
answers 2xx/4xx).

## Endpoints

| endpoint | purpose |
|---|---|
| `POST /waf/decision` | enforcement decision (raw HTTP request or JSON record in) |
| `POST /score` | score only — never enforces (tooling/analyst UI) |
| `GET /` | interactive demo page |
| `GET /health` | model/policy versions + thresholds |
| `GET /stats` | counters + latency percentiles |
| `POST /reload` | force policy reload |

Every decision is appended to `data/decisions/decisions-YYYY-MM-DD.jsonl` —
the same audit trail the stream consumer writes, so the nightly batch (Step
11) sees both paths.

## Design decisions

- **The model decides, the gateway enforces** — the detector never writes
  403s itself; it only answers questions. Swapping Nginx for Kong/Envoy or
  changing thresholds is configuration, not code.
- **Thresholds live outside the model** — the checkpoint carries
  `operating_threshold` as *recall-oriented* guidance (Step 9); enforcement
  thresholds are a separate, policy-owned concern. The 0.9/0.6 defaults come
  from the plan; the model's measured operating point (~0.14) would be a
  `challenge_above` tuning input in shadow review, not something baked in.
- **Echo only what's flagged** — benign requests keep no payload copies in the
  audit log (privacy + size); flagged requests carry the full request for the
  analyst queue.
