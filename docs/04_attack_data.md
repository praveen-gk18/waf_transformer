# Step 4 — Attack Data

**Status: automated.** `python3 -m waf_transformer.data.fetch_datasets` pulls
both public corpora into `data/raw/`; `generate_attacks.py` produces targeted
attack simulation. All of it lands in the same record schema.

## 4a. Public datasets (downloaded by the fetcher)

| Dataset | Content | Labels | Size |
|---|---|---|---|
| **HTTP DATASET CSIC 2010** | Full requests (headers + body) against an e-commerce app; attacks generated with Paros/w3af + typos in benign params | `Valid` (72,000) / `Attack` (25,065, **untyped**) | ~60 MB |
| **ECML/PKDD 2007 Discovery Challenge** | Real traffic, anonymized (URLs/params masked); 7 attack families | `Valid` (35,006), `SqlInjection` (2,274), `XSS` (1,825), `LdapInjection`, `OsCommanding`, `PathTransversal`, `SSI`, `XPathInjection` (15,110 total) | ~80 MB |

Both are the rare public corpora that include **whole requests** — request
line, headers and body — which is why they're the right starting point
(we classify requests, not just URLs).

**Fetch strategy** (all handled by `fetch_datasets.py`, in order):

1. **Canonical**: GSI GitLab mirror tarballs
   (`gitlab.fing.edu.uy/gsi/web-application-attacks-datasets`) — the community
   reference copy of the two datasets.
2. **Fallback**: GitHub mirror of the same converted files
   (`rashimo/ChCNN`), fetched as raw files.
3. **Last resort**: shallow `git clone` of that mirror, copy files out.

Every file's sha256 is recorded in `data/raw/MANIFEST.json`. The corpus files
themselves are **not** committed to Git (see `data/README.md`); the fetch is
one command and fully reproducible.

## 4b. Attack simulation (targeted, reproducible)

Public corpora are 2007/2010-era. `generate_attacks.py` (stand-in for
SQLMap/ZAP runs against staging — same idea, deterministic and dependency-free)
emits modern SQLi/XSS requests across three axes:

- **Techniques** — SQLi: union / boolean-blind / error-based / time-based /
  stacked; XSS: reflected / stored / DOM (`javascript:` URIs, `data:` URIs,
  event handlers, svg/img sinks).
- **Placements** — query value, query key, path segment, form body, JSON body,
  request header (attacks hide in `User-Agent`/`Referer` too).
- **Obfuscation mutators** — URL-encoding (single/double), case mixing,
  `/**/` keyword splitting, encoded whitespace (`%09`/`%0a`/`+`), null bytes,
  `%uXXXX` unicode escapes, HTML entities. This is cheap **adversarial
  training data** before adversarial training is a Phase-3 problem (Step 9).

All mutations of one base payload template share a `group_id`, so the builder
keeps template families inside a single split — the model can't memorize one
split's `UNION SELECT` and ace the test set.

## 4c. Existing-WAF block logs (your real attacks)

If any rule-based WAF sits in front of the app, export its block logs as JSONL
(`{"id": ..., "attack_category": optional}`) and pass `--waf-log` to the label
stage. **Anything a real WAF blocked is labelled malicious** (automated
labeling, Step 5) — these are attacks that actually targeted *your* systems.

## 4d. In-scope filtering

The v1 model scope is SQLi + XSS (see `docs/01_scope.md`). Out-of-scope
families from ECML are still labelled and typed (taxonomy completeness) but
excluded from `train/val/test` unless `--include-out-of-scope` is set. CSIC's
untyped `Attack` rows **are** kept in the binary task: they are real attacks
and the objective is maliciousness, with family typing as metadata.

## Known limitations (accepted for Phase 1–2)

- CSIC attacks are untyped; heuristic typing enriches them where confident,
  and manual review samples cover them.
- ECML is heavily anonymized — its "normal" vocabulary is random strings, so
  models trained on it must be re-validated on real traffic (Phase 5 shadow
  mode exists exactly for this).
