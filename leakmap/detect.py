"""Turn one outgoing request into an Event with findings.

This module knows nothing about mitmproxy so it can be tested directly and
reused by other capture paths (OTLP receiver, client hooks).
"""

import base64
import binascii
import json
import re
import time
from functools import lru_cache
from importlib import resources
from urllib.parse import parse_qsl, unquote

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
        self.requires_context = bool(spec.get("requires_context"))

    def judge(self, matched: str, before: str, key: str) -> str | None:
        """Confidence for this match, or None to drop it. Confirming context wins over negative."""
        if self.requires_context:
            # The label is the only evidence here, so anything against it wins.
            if (self.exclude and self.exclude.search(matched)) or (
                    self.negative_context and self.negative_context.search(before)):
                return None
        if (self.hint and self.hint.search(key)) or (self.context and self.context.search(before)):
            return "high"
        if self.requires_context:
            return None
        if self.negative_key and self.negative_key.search(key):
            return None
        if self.negative_context and self.negative_context.search(before):
            return None
        if self.exclude and self.exclude.search(matched):
            return None
        return self.confidence


CONTEXT_WINDOW = 40


# Empty form fields: "None", "N/A", "[Checkboxes]", "____".
PLACEHOLDER = re.compile(r"(?i)^(?:none|nil|null|n/?a|na|not applicable|unknown|tbd|pending|-+|_+|\[[^\]]*\]|<[^>]*>|\{[^}]*\}|\([^)]*\))\.?$")

# A schema in a prompt ("address: Address", "zip_code: str") names types, not values.
TYPE_NAME = re.compile(r"(?i)^(?:str|string|int|integer|float|number|bool|boolean|list|dict|object|array|any|date|datetime|optional|list\[.*|dict\[.*|optional\[.*)[,;]?$")


class FieldRule:
    def __init__(self, spec: dict):
        self.id = spec["id"]
        self.category = spec.get("category", spec["id"])
        self.label = spec["label"]
        self.key = re.compile(spec["key"])
        self.confidence = spec["confidence"]
        self.value = re.compile(spec["value"]) if spec.get("value") else None
        self.exclude = re.compile(spec["exclude"]) if spec.get("exclude") else None
        self.labelled_only = bool(spec.get("labelled"))

    def matches(self, key: str, value: str, labelled: bool) -> bool:
        value = value.strip()
        if not value or (self.labelled_only and not labelled) or not self.key.search(key):
            return False
        if labelled and (not re.search(r"[A-Za-z0-9]", value) or PLACEHOLDER.match(value)
                         or TYPE_NAME.match(value) or label_key(value) == key):
            return False
        if self.value and not self.value.search(value):
            return False
        return not (self.exclude and self.exclude.search(value))


@lru_cache(maxsize=1)
def load_rules() -> tuple[list[Detector], list[FieldRule]]:
    text = resources.files("leakmap.data").joinpath("detectors.yaml").read_text()
    data = yaml.safe_load(text)
    return [Detector(d) for d in data["detectors"]], [FieldRule(f) for f in data["fields"]]


def labels() -> dict[str, str]:
    detectors, fields = load_rules()
    rules: list[Detector | FieldRule] = [*detectors, *fields]
    return {r.category: r.label for r in rules}


# "First Name: Rahul", "**DOB:** 1990-01-01", "- Address = 12 MG Road"
LABEL_LINE = re.compile(r"^[ \t>*_#|-]*([A-Za-z][A-Za-z0-9 ./()'_-]{0,40}?)[ \t*_]*[:=][ \t*_]*(\S[^\n]*?)[ \t*_]*$", re.M)


def label_key(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def labelled_pairs(text: str):
    """(key, value) pairs from form lines and markdown tables inside free text."""
    if ":" in text or "=" in text:
        for m in LABEL_LINE.finditer(text):
            yield label_key(m.group(1)), m.group(2)
    rows = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("|")]
    header = None
    for row in rows:
        cells = [c.strip(" *_") for c in row.strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue
        if header is None or len(cells) != len(header):
            header = [label_key(c) for c in cells]
            continue
        yield from zip(header, cells)


_ner = None
NER_MIN_WORDS = 3


def enable_ner():
    """Load the optional model (leakmap[ner]) for names and addresses in free text."""
    global _ner
    from .ner import NER
    _ner = NER()


def scan_value(value: str, key: str) -> list[tuple[str, str, str]]:
    """Return (category, matched_text, confidence) for one string value."""
    detectors, fields = load_rules()
    out = []
    if _ner and len(value.split()) >= NER_MIN_WORDS:
        out.extend(_ner.find(value[:MAX_STRING]))
    whole = set()  # categories already reported for the whole value by its field name
    for rule in fields:
        if rule.matches(key, value, labelled=False):
            out.append((rule.category, value, rule.confidence))
            whole.add(rule.category)
    if len(value) < 5:
        return out
    value = value[:MAX_STRING]
    if "\n" in value or ":" in value:
        for label, text in labelled_pairs(value):
            for rule in fields:
                if rule.matches(label, text, labelled=True):
                    out.append((rule.category, text, rule.confidence))
    claimed: list[tuple[int, int]] = []
    for det in detectors:
        for m in det.regex.finditer(value):
            start, end = m.span()
            if det.category in whole or any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            if det.validator and not det.validator(m.group()):
                continue
            confidence = det.judge(m.group(), value[max(0, start - CONTEXT_WINDOW):start], key)
            if confidence is None:
                continue
            claimed.append((start, end))
            out.append((det.category, m.group(), confidence))
    return out


def _loads(s: str):
    """json.loads that reports nesting too deep to parse as invalid JSON."""
    try:
        return json.loads(s)
    except RecursionError as e:
        raise ValueError("JSON nested too deeply") from e


def _children(obj, path: str, key: str, depth: int):
    if isinstance(obj, dict):
        for k, v in obj.items():
            k = str(k)
            yield v, f"{path}.{k}" if path else k, k, depth
    else:
        for v in obj:
            yield v, f"{path}[]", key, depth


def walk(obj, path: str = "", key: str = "", depth: int = 0):
    """Yield (path, key, string_value) for every leaf, normalising list indexes to [].

    Iterative, so a deeply nested document cannot exhaust the call stack.
    """
    stack = [iter([(obj, path, key, depth)])]
    while stack:
        item = next(stack[-1], None)
        if item is None:
            stack.pop()
            continue
        obj, path, key, depth = item
        if isinstance(obj, (dict, list)):
            stack.append(_children(obj, path, key, depth))
        elif isinstance(obj, str):
            s = obj.strip()
            if depth < MAX_JSON_DEPTH and s[:1] in "{[" and s[-1:] in "}]":
                try:
                    stack.append(iter([(_loads(s), path, key, depth + 1)]))
                    continue
                except ValueError:
                    pass
            decoded = from_base64(s) if depth < MAX_JSON_DEPTH else None
            if decoded is not None:
                stack.append(iter([(decoded, f"{path}(base64)", key, depth + 1)]))
                continue
            yield path, key, obj
        elif isinstance(obj, bool) or obj is None:
            continue
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
            return "json", list(walk(_loads(stripped)))
        except ValueError:
            pass
        # NDJSON and Sentry envelopes: one JSON document per line.
        lines = [ln for ln in stripped.splitlines() if ln.strip()]
        parsed = []
        for ln in lines:
            try:
                parsed.append(_loads(ln))
            except ValueError:
                break
        else:
            if parsed:
                return "ndjson", [leaf for doc in parsed for leaf in walk(doc)]
    return "text", [("body", "", text)]


def walk_text(text: str, path: str, key: str):
    return list(walk(text, path, key))


BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")


def from_base64(s: str):
    """Decoded text (or JSON) when s is base64 of readable text, else None.

    Mixpanel sends events as data=<base64 JSON>; secrets are often stored the same way.
    """
    if len(s) < 16 or len(s) > MAX_STRING or not BASE64.fullmatch(s) or s.isalpha() or s.isdigit():
        return None
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_" if "-" in s or "_" in s else None, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    if sum(c.isprintable() or c in "\n\r\t" for c in text) < 0.95 * len(text) or len(text) < 8:
        return None
    t = text.strip()
    if t[:1] in "{[":
        try:
            return _loads(t)
        except ValueError:
            pass
    return text


def scan_body(body: bytes, content_type: str, query=(), form_fields=None, path: str = ""):
    """Return (inspected_kind, [(field_path, category, raw_match, confidence)]).

    path is the URL path; it is percent-decoded and scanned as one value, so
    earlier segments give context (/orders/<id>).

    Raw matches never leave this process; inspect_request masks them. The
    benchmark uses this directly to score exact values.
    """
    kind, leaves = _parse_body(body, content_type, form_fields)
    leaves = [(f"query.{k}", k, v) for k, v in query] + list(leaves)
    if path:
        leaves.insert(0, ("url.path", "path", unquote(path.split("?", 1)[0])))
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
    kind, matches = scan_body(body, content_type, query, form_fields, path)
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
