"""Compare raw captured bodies (rawcap.py) with what leakmap finds in them.

    python compare.py <capture-dir> <name>... [--json out.json]

For each request: which planted fake values are in the body, which leakmap
caught at the default floor, and anything it flagged that was not planted.
"""
import base64
import gzip
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from leakmap.detect import scan_body
from leakmap.model import CONFIDENCE_RANK

PLANTED = {"aadhaar": "2000 0000 0009", "pan": "ABCPK1234F", "email": "rahul.k@example.com",
           "phone_in": "+91 98765 43210", "card": "4111 1111 1111 1111", "name (free text)": "Rahul Kumar"}

args = sys.argv[1:]
out = args.pop(args.index("--json") + 1) if "--json" in args else None
args = [a for a in args if a != "--json"]
root, names = Path(args[0]), args[1:]
result = {}
for name in names:
    rows = [json.loads(line) for line in open(root / name / "events.jsonl.raw.jsonl")]
    t = Counter()
    for r in rows:
        body = base64.b64decode(r["body"])
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        kind, matches = scan_body(body, r["ct"], parse_qsl(urlsplit(r["path"]).query))
        found = {(c, raw) for _, c, raw, conf in matches if CONFIDENCE_RANK[conf] >= CONFIDENCE_RANK["medium"]}
        caught = {c for c, _ in found}
        for cat, value in PLANTED.items():
            if value.encode() in body:
                t[f"{r['host']} | {'caught' if cat in caught else 'MISSED'} {cat}"] += 1
        for c, raw in found:
            if not any(raw in v or v in raw for v in PLANTED.values()):
                t[f"{r['host']} | NOT PLANTED {c}"] += 1
        t[f"{r['host']} | requests ({kind})"] += 1
    result[name] = dict(sorted(t.items()))
    print(f"\n{name}: {len(rows)} requests")
    for k, n in sorted(t.items()):
        print(f"  {k}  x{n}")
if out:
    Path(out).write_text(json.dumps(result, indent=2) + "\n")
