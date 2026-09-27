# Step 13 — Shadow Mode Rollout

## Why shadow first

The plan: *"Run the model in shadow mode first — log what it would do without
actually blocking anything."* Blocking is irreversible (false positives cost
real users); shadowing is free.

Shadow mode is not a bolt-on — it is the **default**:
`config/scope.toml [enforcement] mode = "shadow"`. In shadow mode every
request is allowed, and each decision records `shadow_action` — what the
thresholds *would* have done (`block`, `challenge`, or nothing).

## The rollout procedure

1. **Deploy in shadow.** Start the gateway (`make gateway-serve`) wired to
   Nginx (`infra/nginx/waf_enforcement.conf`) or run the stream consumer over
   a mirror of production traffic. Keep your existing WAF in charge.
2. **Watch the watchlist.** The nightly reports (`make batch-run`,
   `make monitor-run`) list `shadow would-block / would-challenge`. Every entry
   is a request the model would have hurt. Sample them:
   ```bash
   python3 -m waf_transformer.pipeline.batch            # candidates.jsonl
   make model-retrain                                   # review queue for analysts
   ```
3. **Triage false positives.** For each would-block that looks legitimate:
   decide — is it genuinely benign (false positive → adjust thresholds, add it
   to training via the review workflow), or an attack your old WAF missed
   (true positive → note the win)?
4. **Promote when clean.** Go-live criterion (plan): *a full week of shadow
   traffic with no unacceptable false positives on the watchlist*. Then move
   to Step 14 — staged blocking.

## Commands

```bash
# what would have happened today:
python3 -m waf_transformer.pipeline.monitor         # watchlist + drift + alerts

# flip modes WITHOUT redeploying anything (hot-reloaded per request):
#   config/scope.toml -> [enforcement] mode = "shadow" | "challenge" | "block"
```

The policy version hash recorded on every decision tells you exactly which
thresholds produced it — audits survive config changes.
