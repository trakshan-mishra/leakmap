"""Turn one outgoing request into an Event with findings.

This module knows nothing about mitmproxy so it can be tested directly and
reused by other capture paths (OTLP receiver, client hooks).
"""

import json
import re
import time
from functools import lru_cache
from importlib import resources
from urllib.parse import parse_qsl

import yaml

from . import protobuf
from .model import CONFIDENCE_RANK, Event, Finding, mask
from .validators import VALIDATORS

MAX_BODY = 5 * 1024 * 1024
MAX_JSON_DEPTH = 4  # JSON encoded inside JSON strings, common in tracing SDKs
MAX_STRING = 200_000


class Detector:
    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.category = spec.get("category", spec["id"])
        self.label = spec["label"]
        self.regex = re.compile(spec["pattern"])
        self.validator = VALIDATORS[spec["validator"]] if spec.get("validator") else None
        self.confidence = spec["confidence"]
        opt = lambda name: re.compile(spec[name]) if spec.get(name) else None  # noqa: E731
        self.hint = opt("hint")  # field name that confirms the match
        self.context = opt("context")  # words just before the match that confirm it
        self.negative_key = opt("negative_key")  # field name that rules it out
        self.negative_context = opt("negative_context")  # words just before that rule it out
        self.exclude = opt("exclude")  # matched text that is usually something else

    def judge(self, matched: str, before: str, key: str) -> str | None:
        """Confidence for this match, or None to drop it. Confirming context wins over negative."""
        if (self.hint and self.hint.search(key)) or (self.context and self.context.search(before)):
            return "high"
        if self.negative_key and self.negative_key.search(key):
            return None
        if self.negative_context and self.negative_context.search(before):
            return None
        if self.exclude and self.exclude.search(matched):
            return None
        return self.confidence


CONTEXT_WINDOW = 40


class FieldRule:
    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.category = spec.get("category", spec["id"])
        self.label = spec["label"]
        self.key = re.compile(spec["key"])
        self.confidence = spec["confidence"]


@lru_cache(maxsize=1)
def load_rules() -> tuple[list[Detector], list[FieldRule]]:
    text = resources.files("leakmap.data").joinpath("detectors.yaml").read_text()
    data = yaml.safe_load(text)
    return [Detector(d) for d in data["detectors"]], [FieldRule(f) for f in data["fields"]]


def labels() -> dict[str, str]:
    detectors, fields = load_rules()
    return {r.category: r.label for r in [*detectors, *fields]}


def scan_value(value: str, key: str) -> list[tuple[str, str, str]]:
    """Return (category, matched_text, confidence) for one string value."""
    detectors, fields = load_rules()
    out = []
    for rule in fields:
        if rule.key.search(key) and value.strip():
            out.append((rule.category, value, rule.confidence))
    if len(value) < 5:
        return out
    value = value[:MAX_STRING]
    claimed: list[tuple[int, int]] = []
    for det in detectors:
        for m in det.regex.finditer(value):
            start, end = m.span()
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            if det.validator and not det.validator(m.group()):
                continue
            confidence = det.judge(m.group(), value[max(0, start - CONTEXT_WINDOW):start], key)
            if confidence is None:
                continue
            claimed.append((start, end))
            out.append((det.category, m.group(), confidence))
    return out


def walk(obj, path: str = "", key: str = "", depth: int = 0):
    """Yield (path, key, string_value) for every leaf, normalising list indexes to []."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            k = str(k)
            yield from walk(v, f"{path}.{k}" if path else k, k, depth)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v, f"{path}[]", key, depth)
    elif isinstance(obj, str):
        s = obj.strip()
        if depth < MAX_JSON_DEPTH and s[:1] in "{[" and s[-1:] in "}]":
            try:
                yield from walk(json.loads(s), path, key, depth + 1)
                return
            except ValueError:
                pass
        yield path, key, obj
    elif isinstance(obj, bool) or obj is None:
        return
    elif isinstance(obj, (int, float)):
        yield path, key, str(obj)


def _parse_body(body: bytes, content_type: str, form_fields):
    """Return (inspected_kind, iterator of leaves)."""
    if form_fields is not None:
        leaves = []
        for name, value in form_fields:
            text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
            leaves.extend(walk_text(text, f"form.{name}", name))
        return "multipart", leaves
    if not body:
        return "empty", []
    if len(body) > MAX_BODY:
        return "too_large", []
    ct = content_type.lower()
    if "protobuf" in ct or "grpc" in ct:
        frames = list(protobuf.grpc_payloads(body)) if "grpc" in ct else [body]
        if not any(protobuf.parses(f) for f in frames):
            return "binary", []
        leaves = []
        for frame in frames:
            for leaf in protobuf.strings(frame):
                path, key, text = leaf
                leaves.extend(walk_text(text, path, key))
        return "protobuf", leaves
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", []
    stripped = text.strip()
    # Body shape wins over the header: urllib labels every POST as a form.
    if "x-www-form-urlencoded" in ct and stripped[:1] not in "{[":
        leaves = []
        for k, v in parse_qsl(text, keep_blank_values=False):
            leaves.extend(walk_text(v, f"form.{k}", k))
        return "form", leaves
    if "json" in ct or stripped[:1] in "{[":
        try:
            return "json", list(walk(json.loads(stripped)))
        except ValueError:
            pass
        # NDJSON and Sentry envelopes: one JSON document per line.
        lines = [ln for ln in stripped.splitlines() if ln.strip()]
        parsed = []
        for ln in lines:
            try:
                parsed.append(json.loads(ln))
            except ValueError:
                parsed = None
                break
        if parsed:
            return "ndjson", [leaf for doc in parsed for leaf in walk(doc)]
    return "text", [("body", "", text)]


def walk_text(text: str, path: str, key: str):
    s = text.strip()
    if s[:1] in "{[":
        try:
            return list(walk(json.loads(s), path, key))
        except ValueError:
            pass
    return [(path, key, text)]


def scan_body(body: bytes, content_type: str, query=(), form_fields=None):
    """Return (inspected_kind, [(field_path, category, raw_match, confidence)]).

    Raw matches never leave this process; inspect_request masks them. The
    benchmark uses this directly to score exact values.
    """
    kind, leaves = _parse_body(body, content_type, form_fields)
    leaves = [(f"query.{k}", k, v) for k, v in query] + list(leaves)
    return kind, [
        (field_path, category, matched, confidence)
        for field_path, key, value in leaves
        for category, matched, confidence in scan_value(value, key)
    ]


def inspect_request(
    method: str,
    host: str,
    path: str,
    query: list[tuple[str, str]],
    content_type: str,
    body: bytes,
    form_fields=None,
    ts: float | None = None,
) -> Event:
    kind, matches = scan_body(body, content_type, query, form_fields)
    found: dict[tuple[str, str], Finding] = {}
    for field_path, category, matched, confidence in matches:
        slot = (category, field_path)
        if slot in found:
            f = found[slot]
            f.count += 1
            if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[f.confidence]:
                f.confidence = confidence
        else:
            found[slot] = Finding(category, field_path, mask(matched), confidence)
    return Event(
        ts=ts if ts is not None else time.time(),
        method=method,
        host=host.lower(),
        path=path.split("?", 1)[0],
        inspected=kind,
        findings=list(found.values()),
    )
