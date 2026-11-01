"""Score on Gretel's public PII test split (gretelai/gretel-pii-masking-en-v1, Apache-2.0).

This is text leakmap's author did not write, so it checks the synthetic corpus
is not just testing itself. Only categories both sides label are scored:
email, card, IP addresses and API keys / passwords. Gold cards that fail Luhn and
private or reserved IPs are dropped (an LLM wrote many of them; real ones pass).

    python benchmark/gretel.py                    # downloads ~4 MB on first run
    python benchmark/gretel.py --floor low        # include low-confidence matches
    python benchmark/gretel.py --engine presidio
"""

import argparse
import ast
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

from evaluate import norm, presidio_engine, save, table
from leakmap.detect import scan_body
from leakmap.model import CONFIDENCE_RANK
from leakmap.validators import ipv4_public, ipv6_global, luhn

URL = ("https://datasets-server.huggingface.co/rows?dataset=gretelai/gretel-pii-masking-en-v1"
       "&config=default&split=test&offset={}&length=100")
ROWS = 5000
MAP = {"email": "email", "credit_card_number": "card", "ipv4": "ip_address", "ipv6": "ip_address",
       "api_key": "secret", "password": "secret"}


def download(cache: Path):
    cache.mkdir(parents=True, exist_ok=True)
    for offset in range(0, ROWS, 100):
        path = cache / f"rows_{offset}.json"
        for attempt in range(5):
            try:
                if path.exists():
                    json.loads(path.read_text())
                    break
                path.write_bytes(urllib.request.urlopen(URL.format(offset), timeout=30).read())
            except ValueError:
                path.unlink()
            except OSError:
                time.sleep(2 * (attempt + 1))


def load(cache: Path):
    for path in sorted(cache.glob("rows_*.json")):
        for r in json.loads(path.read_text())["rows"]:
            ents = r["row"]["entities"]
            yield r["row"]["text"], ast.literal_eval(ents) if isinstance(ents, str) else ents


def gold(entities):
    out = set()
    for e in entities:
        for t in e["types"]:
            cat, value = MAP.get(t), e["entity"]
            if not cat or (cat == "card" and not luhn(value)) or (cat == "ip_address" and not (ipv4_public(value.strip()) or ipv6_global(value.strip()))):
                continue
            out.add((cat, norm(cat, value)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["leakmap", "presidio"], default="leakmap")
    ap.add_argument("--floor", choices=["low", "medium", "high"], default="medium")
    ap.add_argument("--threshold", type=float, default=0.5, help="Presidio score threshold")
    ap.add_argument("--cache", type=Path, default=Path(__file__).parent / "data" / "gretel")
    ap.add_argument("--json", help="also write metrics to this file")
    args = ap.parse_args()

    download(args.cache)
    cats = {"email", "card", "ip_address"}
    if args.engine == "presidio":
        engine = presidio_engine(args.threshold)
        # Presidio also reports IPv6, which leakmap does not look for and Gretel labels separately.
        predict = lambda text: {p for p in engine({"body": text}) if not (p[0] == "ip_address" and ":" in p[1])}  # noqa: E731
    else:
        cats.add("secret")

        def predict(text):
            _, matches = scan_body(text.encode(), "text/plain")
            return {(c, norm(c, raw)) for _, c, raw, conf in matches
                    if CONFIDENCE_RANK[conf] >= CONFIDENCE_RANK[args.floor]}

    tp, fp, fn = Counter(), Counter(), Counter()
    n = 0
    for text, entities in load(args.cache):
        n += 1
        g = {x for x in gold(entities) if x[0] in cats}
        p = {x for x in predict(text) if x[0] in cats}
        for c, _ in g & p:
            tp[c] += 1
        for c, _ in p - g:
            fp[c] += 1
        for c, _ in g - p:
            fn[c] += 1
    setting = f"threshold {args.threshold}" if args.engine == "presidio" else f"floor {args.floor}"
    if n != ROWS:
        print(f"only {n} of {ROWS} samples downloaded; run again to fetch the rest", file=sys.stderr)
        return 1
    print(f"{args.engine} on Gretel test ({n} samples, {setting})\n")
    print(table(tp, fp, fn))
    save(args.json, {"dataset": "gretel-pii-masking-en-v1/test", "samples": n, "engine": args.engine,
                     "threshold": args.threshold if args.engine == "presidio" else None,
                     "floor": args.floor if args.engine == "leakmap" else None}, tp, fp, fn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
