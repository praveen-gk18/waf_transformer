# infra/ — log collection & local stack (Steps 2–3)

This directory holds the **production-shaped** collection path declared in
`docs/02_tech_stack.md` and `docs/03_log_collection.md`. Nothing here is
required to build the Phase-2 dataset (that pipeline is pure Python); this is
the contract for how *real* traffic will be captured once deployed.

| File | Role |
|---|---|
| `docker-compose.yml` | Local Kafka (KRaft) + MinIO + Postgres + OpenResty + Filebeat |
| `nginx/nginx.conf` | JSON access log with full request line/headers/status |
| `nginx/waf_request_logging.conf` | OpenResty lua: request-body capture (8 KiB cap, matches `scope.toml`) |
| `filebeat/filebeat.yml` | JSON logs → Kafka topic `http.requests.raw` |

## Quick start

```bash
cd infra && docker compose up -d
curl -s localhost:8080/tienda1/publico/productos.jsp?idA=2
docker compose exec kafka kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 --topic http.requests.raw --from-beginning
```

## Notes

- **Full request detail is the contract**: method, target, headers, body. If a
  component drops any of these, downstream labels silently degrade — see
  `docs/03_log_collection.md`.
- Cookie values are logged (session grouping needs them) — the MinIO archive
  is private + encrypted; mask secrets before any sample leaves the VPC.
- ModSecurity (or any rule WAF) audit logs feed the `--waf-log` labeling input
  — that's the "existing WAF block logs" attack source from Step 4.
- Phase 4 adds the Kafka consumer, decision writer, and enforcement bridge;
  thresholds already live in `config/scope.toml [enforcement]`.
