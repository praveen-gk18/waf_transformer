"""HTTP request parsing: raw text -> structured fields, plus decoding helpers.

The model sees requests AFTER maximal-effort decoding (so `S%45LECT` and
`%53ELECT` collapse toward the same shape) — obfuscation handling is a data
problem first and a model problem second. Parsing is defensive: malformed
requests must never crash the pipeline (Step 17 edge cases).
"""

from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass, field

# Liberal on purpose: real attack traffic contains spaces in URLs, missing
# HTTP versions, and control bytes. The target is "everything except a
# trailing HTTP/x.y version token" — never reject a request line we can split.
REQUEST_LINE_RE = re.compile(
    r"^(?P<method>[A-Z]{3,10})\s+(?P<target>.+?)(?:\s+(?P<version>HTTP/\d\.\d))?\s*$"
)
_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


@dataclass
class RawRequest:
    """A parsed HTTP request. Headers keep original order and casing."""

    method: str
    target: str
    http_version: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    @property
    def path(self) -> str:
        return split_target(self.target)[0]

    @property
    def query_string(self) -> str:
        return split_target(self.target)[1]

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return None


def split_target(target: str) -> tuple[str, str]:
    """Split a request target into (path, query_string).

    Handles absolute-form targets (`GET http://host/path?q=1`) used by CSIC.
    Fragments never appear on the wire but are stripped defensively.
    """
    target = target.split("#", 1)[0]
    if target.startswith(("http://", "https://")):
        parts = urllib.parse.urlsplit(target)
        return parts.path or "/", parts.query
    if "?" in target:
        path, query = target.split("?", 1)
        return path or "/", query
    return target or "/", ""


def parse_request_text(text: str) -> RawRequest | None:
    """Parse raw request text (request line + headers + body). None if hopeless.

    Body begins after the first blank line; everything after it is the body
    (verbatim, minus a single trailing newline). Header folding is ignored —
    folded headers are treated as continuation values (appended).
    """
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    if not lines:
        return None

    m = REQUEST_LINE_RE.match(lines[0].strip())
    if not m or m.group("method") not in _METHODS:
        return None

    headers: list[tuple[str, str]] = []
    body_start = len(lines)
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
        elif headers and line.startswith((" ", "\t")):  # obs-fold
            k, v = headers[-1]
            headers[-1] = (k, f"{v} {line.strip()}")
        # else: drop malformed header line silently

    body = "\n".join(lines[body_start:]).rstrip("\n")

    return RawRequest(
        method=m.group("method"),
        target=m.group("target"),
        http_version=m.group("version") or "HTTP/1.1",
        headers=headers,
        body="" if body == "null" else body,  # CSIC writes literal "null" for empty bodies
    )


# ---------------------------------------------------------------------------
# Decoding helpers — normalize obfuscation before heuristic typing / modeling.
# ---------------------------------------------------------------------------
_PCT_RE = re.compile(r"%([0-9a-fA-F]{2})")
_PCT_U_RE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)


def _unquote_once(s: str) -> str:
    s = _PCT_U_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = s.replace("+", " ") if "%" in s else s
    prev = s
    s = _PCT_RE.sub(lambda m: chr(int(m.group(1), 16)) if int(m.group(1), 16) < 256 else m.group(0), s)
    return s if s != prev else prev


def decode_layers(s: str, max_rounds: int = 3) -> str:
    """Peel URL-encoding layers, then HTML-entity decoding.

    `S%2545LECT` -> `S%45LECT` -> `SELECT`. Stops early on fixpoint so normal
    text with stray percent signs is not mangled.
    """
    out = s
    for _ in range(max_rounds):
        nxt = _unquote_once(out)
        if nxt == out:
            break
        out = nxt
    return html.unescape(out)


def header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    """First value for a header name (case-insensitive), or None."""
    lname = name.lower()
    for k, v in headers:
        if k.lower() == lname:
            return v
    return None


def extract_group_id(
    headers: list[tuple[str, str]],
    session_cookie_names: tuple[str, ...],
    fallback: str,
) -> str:
    """Leak-free grouping key (config dataset.group_key_priority).

    1. session cookie (same browser session -> one group),
    2. client IP header (same source -> one group),
    3. caller-provided fallback (generator family or record id).
    """
    cookie = header_value(headers, "cookie") or ""
    pairs = [p.split("=", 1) for p in cookie.split(";") if "=" in p]
    wanted = {n.lower() for n in session_cookie_names}
    for pair in pairs:
        name, value = pair[0].strip(), pair[1].strip()
        if name.lower() in wanted and value:
            return f"sess:{name}={value}"
    client_ip = header_value(headers, "client-ip") or header_value(headers, "x-forwarded-for")
    if client_ip:
        return f"ip:{client_ip.split(',')[0].strip()}"
    return fallback


def normalized_blob(method: str, path: str, query: str, headers: list[tuple[str, str]], body: str) -> str:
    """Decoded, lowercased-collapsed blob for heuristic inspection.

    Includes header values (attacks hide in User-Agent/Referer/Cookie too).
    """
    parts = [method, path, query, body]
    parts.extend(f"{k}:{v}" for k, v in headers)
    return decode_layers("\n".join(parts))
