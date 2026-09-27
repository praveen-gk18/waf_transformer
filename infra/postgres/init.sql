-- Optional audit store for WAF decisions (Step 10 "another topic or database
-- for audit"; the default deployment uses append-only JSONL and needs none of
-- this). docker-compose: `psql -f infra/postgres/init.sql` at first boot.

CREATE TABLE IF NOT EXISTS waf_decisions (
    request_id     text        PRIMARY KEY,
    ts             timestamptz NOT NULL,
    score          real        NOT NULL,
    action         text        NOT NULL CHECK (action IN ('allow', 'challenge', 'block')),
    shadow_action  text,
    policy_mode    text        NOT NULL,
    policy_version text        NOT NULL,
    model_version  text        NOT NULL,
    latency_ms     real        NOT NULL,
    method         text,
    path           text,
    request        jsonb                 -- echoed only for flagged requests
);

CREATE INDEX IF NOT EXISTS waf_decisions_ts_idx     ON waf_decisions (ts);
CREATE INDEX IF NOT EXISTS waf_decisions_score_idx  ON waf_decisions (score DESC);
CREATE INDEX IF NOT EXISTS waf_decisions_path_idx   ON waf_decisions (path);
