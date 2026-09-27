"""Parsers for the public HTTP attack corpora (Step 4).

Two on-disk formats appear across mirrors — both are handled:

1. ``annotated``  — the GSI "train/test" conversion used by both CSIC 2010 and
   ECML/PKDD 2007 (also what the GitHub mirror ships)::

       Start - Id: 11044
       class: Attack
       GET http://localhost:8080/tienda1/... HTTP/1.1
       ...headers...

       body text or "null"

       End - Id: 11044

2. ``csic_original`` — the raw CSIC 2010 distribution (no markers, no class
   lines): request blocks separated by blank lines, class given by the file
   the block came from.

Both produce :class:`~waf_transformer.data.schema.RequestRecord` with
``label_source="dataset"``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .http_request import extract_group_id, parse_request_text, split_target
from .schema import DATASET_CLASS_MAP, Label, RequestRecord, category_in_scope

_START_RE = re.compile(r"^Start\s*-\s*Id:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_END_RE = re.compile(r"^End\s*-\s*Id:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_CLASS_RE = re.compile(r"^class:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+\S", re.MULTILINE)


class ParseError(ValueError):
    """Raised when a corpus file cannot be parsed at all (not per-record)."""


def dataset_label(class_str: str) -> Label:
    """Map a dataset class string ('Valid', 'SqlInjection', ...) to a Label."""
    key = re.sub(r"[\s_-]+", "", class_str.strip().lower())
    if key in DATASET_CLASS_MAP:
        cls, category = DATASET_CLASS_MAP[key]
    else:
        cls, category = "unknown", None
    return Label(
        class_=cls,
        attack_category=category,
        in_scope=category_in_scope(cls, category),
        label_source="dataset",
        confidence=1.0,
    )


def _make_record(
    source: str,
    source_file: str,
    rec_id: str,
    class_str: str,
    request_text: str,
    session_cookie_names: tuple[str, ...],
    body_max_bytes: int,
    meta: dict | None = None,
) -> RequestRecord | None:
    raw = parse_request_text(request_text)
    if raw is None:
        return None
    body, truncated = raw.body, False
    if len(body.encode("utf-8", "replace")) > body_max_bytes:
        body = body.encode("utf-8", "replace")[:body_max_bytes].decode("utf-8", "replace")
        truncated = True
    path, query = split_target(raw.target)
    label = dataset_label(class_str)
    group = extract_group_id(raw.headers, session_cookie_names, fallback=f"id:{rec_id}")
    meta_out = dict(meta or {})
    meta_out["source_record_id"] = rec_id
    return RequestRecord(
        id=f"{source}:{Path(source_file).stem}:{rec_id}",
        source=source,
        method=raw.method,
        path=path,
        query_string=query,
        http_version=raw.http_version,
        headers=raw.headers,
        body=body,
        label=label,
        group_id=group,
        source_file=source_file,
        body_truncated=truncated,
        meta=meta_out,
    )


def parse_annotated_text(
    text: str,
    source: str,
    source_file: str,
    session_cookie_names: tuple[str, ...],
    body_max_bytes: int = 8192,
) -> Iterator[RequestRecord]:
    """Parse the GSI annotated block format (see module docstring)."""
    lines = text.replace("\r\n", "\n").split("\n")
    i, n = 0, len(lines)
    while i < n:
        m = _START_RE.match(lines[i])
        if not m:
            i += 1
            continue
        block_id = m.group(1)
        i += 1
        class_str = ""
        block_lines: list[str] = []
        while i < n and not _END_RE.match(lines[i]):
            cm = _CLASS_RE.match(lines[i])
            if cm and not block_lines:
                class_str = cm.group(1)
            else:
                block_lines.append(lines[i])
            i += 1
        i += 1  # skip End marker
        if not class_str:
            class_str = "Unknown"
        # Trim structural blank padding around the request text.
        while block_lines and not block_lines[0].strip():
            block_lines.pop(0)
        while block_lines and not block_lines[-1].strip():
            block_lines.pop()
        rec = _make_record(
            source=source,
            source_file=source_file,
            rec_id=block_id,
            class_str=class_str,
            request_text="\n".join(block_lines),
            session_cookie_names=session_cookie_names,
            body_max_bytes=body_max_bytes,
        )
        if rec is not None:
            yield rec


def parse_csic_original_text(
    text: str,
    source: str,
    source_file: str,
    default_class: str,
    session_cookie_names: tuple[str, ...],
    body_max_bytes: int = 8192,
) -> Iterator[RequestRecord]:
    """Parse the raw CSIC 2010 files (no markers; class comes from the file).

    A block starts at a request line and ends at the blank line after its body.
    CSIC bodies are single-line (`null` or form params); multi-line bodies with
    internal blank lines are handled conservatively (first paragraph wins).
    """
    lines = text.replace("\r\n", "\n").split("\n")
    i, n, seq = 0, len(lines), 0
    while i < n:
        if not _REQUEST_LINE_RE.match(lines[i]):
            i += 1
            continue
        block = [lines[i]]
        i += 1
        seen_blank = False
        while i < n:
            if lines[i].strip() == "" and seen_blank:
                break  # end of block
            if lines[i].strip() == "":
                seen_blank = True
            elif seen_blank and _REQUEST_LINE_RE.match(lines[i]):
                break  # next block started without separator
            block.append(lines[i])
            i += 1
        seq += 1
        rec = _make_record(
            source=source,
            source_file=source_file,
            rec_id=f"{Path(source_file).stem}-{seq}",
            class_str=default_class,
            request_text="\n".join(block),
            session_cookie_names=session_cookie_names,
            body_max_bytes=body_max_bytes,
        )
        if rec is not None:
            yield rec


def detect_format(text: str) -> str:
    head = text.lstrip()[:2000]
    if _START_RE.search(head):
        return "annotated"
    if _REQUEST_LINE_RE.search(head):
        return "csic_original"
    return "unknown"


def parse_corpus_file(
    path: Path,
    source: str,
    session_cookie_names: tuple[str, ...],
    body_max_bytes: int = 8192,
) -> Iterator[RequestRecord]:
    """Parse one corpus file, auto-detecting its format.

    ``default_class`` for original-format files is inferred from the file name
    (CSIC ships separate normal/anomalous files).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    fmt = detect_format(text)
    name = path.name.lower()
    if fmt == "annotated":
        yield from parse_annotated_text(
            text, source, path.name, session_cookie_names, body_max_bytes
        )
    elif fmt == "csic_original":
        default_class = "Attack" if "anomal" in name or "attack" in name else "Valid"
        yield from parse_csic_original_text(
            text, source, path.name, default_class, session_cookie_names, body_max_bytes
        )
    else:
        raise ParseError(f"{path}: unrecognized corpus format")
