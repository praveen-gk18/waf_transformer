"""Synthetic normal-traffic generation (dev/CI stand-in for live logs, Step 3).

Real traffic collection (Nginx -> shipper -> storage, see infra/) is the
production source of benign data — this generator exists so the pipeline is
runnable and testable BEFORE weeks of logs exist, and so tests have a benign
corpus with the shape of the Phase-1 normal profile (e-commerce storefront +
JSON API). It intentionally emits "weird but benign" requests (apostrophes,
SQL words in prose, unicode) — the false-positive tripwires from scope.toml.

Usage::

    python3 -m waf_transformer.data.synthesize_normal \
        --out data/raw/synthetic/normal.jsonl --count 3000 --seed 20260927
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.parse
from pathlib import Path

from .schema import Label, RequestRecord

PRODUCTS = [
    ("101", "O'Reilly T-Shirt"),
    ("102", "SELECT Coffee Mug"),
    ("103", "Drop Table Hoodie"),
    ("104", "C++ Primer"),
    ("105", "100% Cotton Socks"),
    ("106", "Núcleo USB-C Hub"),
    ("107", "JavaScript: The Good Parts"),
    ("108", "Wide * Angle Lens"),
]
SEARCH_TERMS = [
    "t-shirt", "o'reilly mug", "select * from catalog gifts", "100% cotton",
    "núcleo", "drop table hoodie (real product)", "*sale*", "c++ book",
    "a" * 180, "", "  ", "sony wh-1000xm5",
]
REVIEW_TEXTS = [
    "Great product! I'd buy again — 5 stars.",
    "Does SELECT work with my setup? I mean the SQL book.",
    "fast shipping, no complaints", "love it", "why did my order DROP? TABLE for two?",
]
COUPONS = ["WELCOME10", "", "SAVE--2026", "SUMMER*"]
USERNAMES = ["alice", "bob", "carol", "dave", "erin"]
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"


def _headers(rng: random.Random, session: str, content_type: str | None = None) -> list[tuple[str, str]]:
    h = [
        ("User-Agent", UA),
        ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Host", "shop.example.local"),
        ("Cookie", f"JSESSIONID={session}"),
        ("Connection", "keep-alive"),
    ]
    if content_type:
        h.append(("Content-Type", content_type))
    return h


def make_normal_records(count: int, seed: int) -> list[RequestRecord]:
    """Generate `count` benign RequestRecords grouped into simulated sessions."""
    rng = random.Random(seed)
    records: list[RequestRecord] = []
    session_seq = 0
    while len(records) < count:
        session = f"{rng.getrandbits(128):032X}"
        session_seq += 1
        steps = rng.randint(4, 12)
        for _ in range(steps):
            if len(records) >= count:
                break
            kind = rng.choice(
                ["browse", "browse", "product", "search", "login", "cart", "checkout", "review", "api", "static", "weird"]
            )
            method, path, query, body, ctype = "GET", "/", "", "", None
            if kind == "browse":
                path = rng.choice(["/", "/catalog", "/tienda1/publico/productos.jsp", "/catalog/electronics"])
                query = rng.choice(["", "page=2", "sort=price", "category=apparel", "lang=es"])
            elif kind == "product":
                pid, _ = rng.choice(PRODUCTS)
                path = rng.choice(["/tienda1/publico/caracteristicas.jsp", f"/product/{pid}", f"/api/v1/products/{pid}"])
                query = f"id={pid}" if "caracteristicas" in path else ""
            elif kind == "search":
                path = rng.choice(["/search", "/tienda1/publico/buscar.jsp", "/api/v1/search"])
                query = "q=" + urllib.parse.quote(rng.choice(SEARCH_TERMS), safe="")
            elif kind == "login":
                method, path = "POST", "/tienda1/autenticar"
                ctype = "application/x-www-form-urlencoded"
                body = f"username={rng.choice(USERNAMES)}&password={rng.randrange(10**8)}"
            elif kind == "cart":
                method, path = "POST", "/cart/add"
                ctype = "application/x-www-form-urlencoded"
                pid, _ = rng.choice(PRODUCTS)
                body = f"idP={pid}&qty={rng.randint(1, 5)}"
            elif kind == "checkout":
                method, path = "POST", "/checkout"
                ctype = "application/x-www-form-urlencoded"
                addr = rng.choice(["1 Main St", "2 O'Brien Ave", "3 Ünicode Rd"])
                body = (
                    f"address={urllib.parse.quote(addr)}"
                    f"&coupon={urllib.parse.quote(rng.choice(COUPONS), safe='')}"
                )
            elif kind == "review":
                method, path = "POST", "/product/review"
                ctype = "application/json"
                body = json.dumps({"rating": rng.randint(1, 5), "comment": rng.choice(REVIEW_TEXTS)})
            elif kind == "api":
                method = rng.choice(["GET", "GET", "PUT", "DELETE"])
                path = rng.choice([f"/api/v1/cart", f"/api/v1/orders/{rng.randint(1000, 9999)}", "/api/v1/account"])
                if method == "PUT":
                    ctype = "application/json"
                    body = json.dumps({"qty": rng.randint(1, 3)})
            elif kind == "static":
                path = rng.choice(["/static/app.js", "/tienda1/imagenes/nuestratierra.jpg", "/static/main.css"])
            else:  # weird-but-benign tripwires
                path = rng.choice(["/search", "/product/104"])
                query = rng.choice([
                    "q=" + urllib.parse.quote("'; DROP TABLE students; -- homework help"),
                    "q=%25%2A%25&sort=-id",
                    "id=101&color=green&color=blue",
                    "q=" + urllib.parse.quote("日本語 サーチ"),
                ])
            records.append(
                RequestRecord(
                    id=f"synthetic-normal:{len(records):06d}",
                    source="synthetic:normal_profile",
                    method=method,
                    path=path,
                    query_string=query,
                    http_version="HTTP/1.1",
                    headers=_headers(rng, session, ctype),
                    body=body,
                    label=Label(
                        class_="benign",
                        attack_category=None,
                        in_scope=True,
                        label_source="synthetic",
                        confidence=1.0,
                    ),
                    group_id=f"sess:{session}",
                    source_file="synthesize_normal.py",
                    meta={"generator": "synthesize_normal", "session_seq": session_seq, "kind": kind},
                )
            )
    return records


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic normal e-commerce traffic")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--count", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=20260927)
    args = ap.parse_args(argv)

    records = make_normal_records(args.count, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_json(), ensure_ascii=False, sort_keys=True) + "\n")
    print(f"wrote {len(records)} synthetic normal records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
