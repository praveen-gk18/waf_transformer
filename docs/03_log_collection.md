# Step 3 — Raw Web Traffic Collection

**Status: configured.** Configs live in [`infra/`](../infra/); they describe
exactly what gets logged and where it flows. Production deployment is a
Phase-4 activity, but the *contract* is fixed now because training data must
be collected from day one.

## The contract: what each log record must contain

Not "IP + timestamp" — the full request:

- method, full request target (path **and** query string)
- all headers (esp. `User-Agent`, `Cookie`, `Referer`, `Content-Type`)
- request body (truncated at `body_max_bytes` = 8192 with a truncation flag)
- timestamp, upstream status, request id (for joining with WAF decisions)

This matches the schema the parsers already produce
(`waf_transformer/data/schema.py`), so live logs and public corpora flow into
the *same* pipeline.

## Pipeline shape (configs provided)

```
[OpenResty/Nginx] --json access+body log--> [Filebeat] --> [Kafka topic: http.requests.raw]
       |                                                                |
       +-- ModSecurity audit log (block export) --> Kafka: http.waf.blocks
                                                                        v
                                          [MinIO: raw archive] + [detection engine (Phase 4)]
                                                                        v
                                                          [PostgreSQL: decisions + labels]
```

- `infra/nginx/nginx.conf` + `waf_request_logging.conf` — JSON access log with
  full request line/headers; OpenResty `access_by_lua` snippet captures body
  (Nginx core cannot log bodies). ModSecurity's audit log is the natural
  source for **WAF block exports** (Step 4's third attack source).
- `infra/filebeat/filebeat.yml` — tails the JSON log, ships to Kafka with
  at-least-once semantics, dead-letters bad lines to MinIO.
- `infra/docker-compose.yml` — local Kafka (KRaft), MinIO, Postgres, OpenResty,
  Filebeat.

## Retention and access

- Raw full requests are **sensitive** (cookies, credentials in bodies). MinIO
  bucket policy: private, SSE enabled, 30–90 day retention, access audited.
  Mask `Cookie`/`Authorization` values in any exported training sample.
- Collect **at least a few weeks** of real traffic before Phase-3 training on
  live data. Until then the pipeline is exercised on public corpora + the
  synthetic normal generator (`synthesize_normal.py`), which emits the
  Phase-1 normal profile including weird-but-benign tripwires.

## What we deliberately don't log

- TLS secrets, bodies above the cap, response bodies.
- WebSocket frames / gRPC streams (v1 out of scope — see `01_scope.md`).
