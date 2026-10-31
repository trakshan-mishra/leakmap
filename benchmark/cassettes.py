"""Run every request recorded in VCR cassettes through leakmap's detectors.

Cassettes are HTTP traffic that projects record from real API calls and commit
for their tests, so they are a public sample of what SDKs actually send.

    python benchmark/cassettes.py PATH [--out findings.jsonl]

PATH is searched for */cassettes/*.yaml(.gz). Handles vcrpy (`interactions`),
pydantic-ai (`parsed_body`) and langchain (`requests`, gzipped) formats.
Requests to localhost are skipped.
"""

import argparse
import gzip
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml

from leakmap.detect import scan_body
from leakmap.model import mask
from leakmap.vendors import UNKNOWN_COUNTRY, resolve

Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
LOCAL = {"", "localhost", "127.0.0.1", "::1"}


def cassettes(root: Path):
    for path in sorted(root.rglob("*")):
        if "cassettes" in path.parts and ".git" not in path.parts and path.suffix in (".yaml", ".yml", ".gz"):
            yield path


def requests_in(path: Path):
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    doc = yaml.load(raw, Loader=Loader) or {}
    for it in doc.get("interactions") or []:
        yield it.get("request") or {}
    yield from doc.get("requests") or []


def body_of(req) -> bytes:
    if req.get("parsed_body") is not None:
        return json.dumps(req["parsed_body"]).encode()
    body = req.get("body")
    if isinstance(body, dict):
        body = body.get("string")
    if body is None:
        return b""
    return body if isinstance(body, bytes) else str(body).encode()


def header(req, name: str) -> str:
    for k, v in (req.get("headers") or {}).items():
        if k.lower() == name:
            return str((v[0] if isinstance(v, list) and v else v) or "")
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument("--out", type=Path, help="write every match (masked) as JSON lines")
    ap.add_argument("--json", type=Path, help="write the summary to this file")
    args = ap.parse_args()

    stats, kinds, found, dest = Counter(), Counter(), Counter(), Counter()
    out = open(args.out, "w") if args.out else None
    for path in cassettes(args.root):
        stats["files"] += 1
        for req in requests_in(path):
            url = urlsplit(req.get("uri") or "")
            host = (url.hostname or "").lower()
            if host in LOCAL:
                continue
            stats["requests"] += 1
            vendor = resolve(host)
            dest["unknown" if vendor.country == UNKNOWN_COUNTRY else "known"] += 1
            kind, matches = scan_body(body_of(req), header(req, "content-type"), parse_qsl(url.query))
            kinds[kind] += 1
            for field, category, raw, confidence in matches:
                found[(category, confidence)] += 1
                if out:
                    out.write(json.dumps({"file": str(path.relative_to(args.root)), "host": host, "field": field,
                                          "category": category, "confidence": confidence, "masked": mask(raw)}) + "\n")
    print(f"{stats['files']} cassettes, {stats['requests']} outgoing requests")
    print(f"vendor known for {dest['known']}, unknown for {dest['unknown']}")
    print("bodies:", dict(kinds.most_common()))
    matches = {f"{c} ({conf})": n for (c, conf), n in sorted(found.items())}
    print("matches:", matches)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"cassettes": stats["files"], "requests": stats["requests"],
                                         "vendor_known": dest["known"], "vendor_unknown": dest["unknown"],
                                         "bodies": dict(kinds.most_common()), "matches": matches}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
