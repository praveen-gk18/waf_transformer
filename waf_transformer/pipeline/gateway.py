"""Step 12 — enforcement bridge: the gateway calls US, we decide.

The plan: *"Integrate with your reverse proxy or API gateway (Nginx, Kong,
Envoy) to actually enforce the block/allow decisions. The model decides; the
gateway enforces."*

This service is that integration point. Nginx (or Kong/Envoy) forwards each
request's metadata here via ``auth_request``/ext-authz; the status code IS the
decision (2xx allow, 403 block, 429 challenge) — see
``infra/nginx/waf_enforcement.conf`` for the wiring.

Routes:

* ``POST /waf/decision`` — enforcement endpoint (raw HTTP request text or
  JSON record in, status-code decision + JSON detail out).
* ``POST /score``      — score without enforcement mapping (tooling).
* ``GET  /``           — interactive demo page.
* ``GET  /health``     — liveness, model/policy versions.
* ``GET  /stats``      — running counters + latency percentiles.
* ``POST /reload``     — force policy (thresholds) reload.

Every decision is appended to the audit log (``data/decisions/``) exactly like
the stream consumer — one enforcement story, two entry points.

Thresholds come from config/scope.toml ``[enforcement]`` and hot-reload; with
``mode = "shadow"`` nothing is ever blocked (Phase 5 rollout mode).
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..engine.detector import Detector
from ..modeling.metrics import percentile

DEMO_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>waf_transformer — decision engine</title>
<style>
 body{font-family:ui-monospace,monospace;margin:2rem auto;max-width:860px;background:#0f1216;color:#d7dde4}
 h1{font-size:1.2rem} textarea{width:100%;height:170px;background:#1a2027;color:#d7dde4;border:1px solid #333;border-radius:6px;padding:10px}
 button{background:#2b7cff;color:#fff;border:0;border-radius:6px;padding:10px 18px;margin:10px 6px 10px 0;cursor:pointer}
 pre{background:#1a2027;padding:14px;border-radius:6px;overflow:auto}
 .allow{color:#3ddc84}.block{color:#ff5555}.challenge{color:#ffb020}
 a{color:#7fb4ff} small{color:#8a97a5}
</style></head><body>
<h1>waf_transformer — WAF decision engine <small>Phase 4 / Step 12 · <a href="/dashboard">dashboard</a></small></h1>
<p>Paste a raw HTTP request below. The engine scores it and returns the
enforcement decision from <code>config/scope.toml [enforcement]</code>
(hot-reloaded; currently shadow-mode safe).</p>
<textarea id="req">GET /tienda1/publico/caracteristicas.jsp?idA=2'+UNION+SELECT+password+FROM+users-- HTTP/1.1
Host: shop.example.local
Cookie: JSESSIONID=DEMO
Connection: close</textarea>
<br><button onclick="score()">decide</button>
<button onclick="document.getElementById('req').value=benign">load benign sample</button>
<button onclick="health()">health</button>
<button onclick="stats()">stats</button>
<pre id="out">ready.</pre>
<script>
const benign = `GET /tienda1/imagenes/nuestratierra.jpg HTTP/1.1
Host: shop.example.local
Cookie: JSESSIONID=DEMO
Connection: close`;
async function score(){
  const r = await fetch('/waf/decision',{method:'POST',body:document.getElementById('req').value});
  const j = await r.json();
  const cls = j.action || 'allow';
  document.getElementById('out').innerHTML =
    '<span class="'+cls+'">'+ (j.shadow_action ? 'SHADOW '+j.action+' (would '+j.shadow_action+')' : j.action.toUpperCase()) +'</span>\\n'
    + JSON.stringify(j, null, 2);
}
async function health(){ const r = await fetch('/health'); document.getElementById('out').textContent = JSON.stringify(await r.json(),null,2); }
async function stats(){ const r = await fetch('/stats'); document.getElementById('out').textContent = JSON.stringify(await r.json(),null,2); }
</script></body></html>"""


class DecisionEngine:
    """Shared state for the HTTP handlers: detector + audit log + counters."""

    def __init__(self, checkpoint: str, decisions_dir: Path, detector=None,
                 reports_dir: Path = Path("data/reports")):
        self.detector = detector or Detector(checkpoint)
        if hasattr(self.detector, "_ensure_loaded"):
            self.detector._ensure_loaded()
        self.decisions_dir = Path(decisions_dir)
        self.reports_dir = Path(reports_dir)
        self.decisions_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.counters = {"total": 0, "allow": 0, "challenge": 0, "block": 0,
                         "shadow_would_block": 0, "shadow_would_challenge": 0}
        self.latencies: list[float] = []

    def handle_raw_request(self, raw_text: str):
        from ..data.http_request import parse_request_text
        from ..data.schema import Label, RequestRecord

        raw = parse_request_text(raw_text.strip("\n"))
        if raw is None:
            return None, "unparseable request"
        rec = RequestRecord(
            id=f"gw:{id(raw)}", source="gateway",
            method=raw.method, path=raw.path, query_string=raw.query_string,
            http_version=raw.http_version, headers=raw.headers, body=raw.body,
            label=Label(class_="unknown", label_source="unknown"),
        )
        decision = self.detector.evaluate(rec)
        self._audit(decision)
        return decision, None

    def handle_json_record(self, obj: dict):
        from ..data.schema import RequestRecord

        rec = RequestRecord.from_json(obj)
        decision = self.detector.evaluate(rec)
        self._audit(decision)
        return decision

    def _audit(self, decision) -> None:
        with self.lock:
            c = self.counters
            c["total"] += 1
            c[decision.action] = c.get(decision.action, 0) + 1
            if decision.shadow_action == "block":
                c["shadow_would_block"] += 1
            elif decision.shadow_action == "challenge":
                c["shadow_would_challenge"] += 1
            self.latencies.append(decision.latency_ms)
            day = decision.ts[:10]
            with (self.decisions_dir / f"decisions-{day}.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(decision.to_json(), ensure_ascii=False, sort_keys=True) + "\n")

    def stats_json(self) -> dict:
        with self.lock:
            lat = list(self.latencies)
            c = dict(self.counters)
        c["latency_ms"] = {
            "p50": round(percentile(lat, 50), 3),
            "p95": round(percentile(lat, 95), 3),
            "p99": round(percentile(lat, 99), 3),
        } if lat else None
        c["model_version"] = self.detector.model_version
        c["policy"] = {
            "mode": self.detector.policy.state.mode,
            "version": self.detector.policy.state.version,
            "block_above": self.detector.policy.state.block_above,
            "challenge_above": self.detector.policy.state.challenge_above,
        }
        return c


def make_handler(engine: DecisionEngine):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # quiet
            pass

        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, DEMO_PAGE.encode(), "text/html; charset=utf-8")
            elif self.path == "/dashboard":
                self._send(200, self._dashboard_page().encode(), "text/html; charset=utf-8")
            elif self.path == "/monitor.json":
                p = engine.reports_dir / "monitor.json"
                body = p.read_bytes() if p.exists() else b'{"error": "run: python3 -m waf_transformer.pipeline.monitor"}'
                self._send(200 if p.exists() else 404, body)
            elif self.path == "/health":
                st = engine.detector.policy.state
                self._send(200, json.dumps({
                    "status": "ok",
                    "model_version": engine.detector.model_version,
                    "operating_threshold": engine.detector.operating_threshold,
                    "policy": {"mode": st.mode, "version": st.version,
                               "block_above": st.block_above, "challenge_above": st.challenge_above},
                }, indent=2).encode())
            elif self.path == "/stats":
                self._send(200, json.dumps(engine.stats_json(), indent=2).encode())
            else:
                self._send(404, b'{"error": "not found"}')

        def _dashboard_page(self) -> str:
            """Step 15 dashboard: live counters + the latest monitor.json."""
            stats = engine.stats_json()
            p = engine.reports_dir / "monitor.json"
            mon = json.loads(p.read_text()) if p.exists() else {"alerts": [], "drift": [], "days": []}
            return DASHBOARD_PAGE.replace("__STATS__", json.dumps(stats, indent=2)).replace(
                "__MONITOR__", json.dumps(mon, indent=2)
            )

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            if self.path == "/reload":
                engine.detector.policy.force_reload()
                st = engine.detector.policy.state
                self._send(200, json.dumps({"reloaded": True, "mode": st.mode, "version": st.version}).encode())
                return
            if self.path not in ("/waf/decision", "/score"):
                self._send(404, b'{"error": "not found"}')
                return

            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            decision, err = (None, None)
            if ct == "application/json":
                try:
                    decision = engine.handle_json_record(json.loads(body))
                except Exception as exc:  # noqa: BLE001
                    err = f"bad record: {exc}"
            else:
                decision, err = engine.handle_raw_request(body)
            if decision is None:
                self._send(400, json.dumps({"error": err or "bad request"}).encode())
                return

            out = decision.to_json()
            # Enforcement mapping (nginx auth_request reads the status code):
            #   200 allow | 403 block | 429 challenge
            status = {"allow": 200, "block": 403, "challenge": 429}[decision.action]
            if self.path == "/score":
                status = 200  # scoring-only endpoint never enforces
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            payload = json.dumps(out, indent=2).encode()
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-WAF-Score", f"{decision.score:.5f}")
            self.send_header("X-WAF-Action", decision.action)
            if decision.shadow_action:
                self.send_header("X-WAF-Shadow-Action", decision.shadow_action)
            self.end_headers()
            self.wfile.write(payload)

    return Handler


DASHBOARD_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>waf_transformer — dashboard</title>
<style>
 body{font-family:ui-monospace,monospace;margin:2rem auto;max-width:980px;background:#0f1216;color:#d7dde4}
 h1{font-size:1.2rem} h2{font-size:1rem;color:#8a97a5}
 pre{background:#1a2027;padding:14px;border-radius:6px;overflow:auto}
 a{color:#7fb4ff} small{color:#8a97a5}
</style></head><body>
<h1>waf_transformer — monitoring dashboard <small>Steps 15 &amp; 19 · <a href="/">demo</a></small></h1>
<h2>Live engine stats</h2><pre>__STATS__</pre>
<h2>Aggregated metrics &amp; drift (data/reports/monitor.json)</h2><pre>__MONITOR__</pre>
<p><small>regenerate: <code>python3 -m waf_transformer.pipeline.monitor</code> (cron via scripts/run_nightly.sh)</small></p>
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="WAF enforcement gateway bridge")
    ap.add_argument("--checkpoint", default="artifacts/run1/best.pt")
    ap.add_argument("--decisions-dir", default="data/decisions")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8089)
    args = ap.parse_args(argv)

    engine = DecisionEngine(args.checkpoint, Path(args.decisions_dir))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(engine))
    print(f"WAF gateway listening on http://{args.host}:{args.port}  "
          f"policy_mode={engine.detector.policy.state.mode}  model={engine.detector.model_version}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
