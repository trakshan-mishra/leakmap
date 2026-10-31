"""Score leakmap (or Presidio) on the labeled corpus.

A prediction is correct when (category, normalised value) matches a label in
the same sample. Precision = TP / (TP + FP), recall = TP / (TP + FN).

    python benchmark/evaluate.py dev            # leakmap on the dev split
    python benchmark/evaluate.py test --errors  # held-out split, show mistakes
    python benchmark/evaluate.py test --engine presidio
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from leakmap.detect import scan_body
from leakmap.model import CONFIDENCE_RANK

DATA = Path(__file__).parent / "data"

PRESIDIO_MAP = {
    "IN_AADHAAR": "aadhaar", "IN_PAN": "pan", "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone_in",
    "CREDIT_CARD": "card", "IP_ADDRESS": "ip_address", "PERSON": "person_name",
}


def norm(category: str, value: str) -> str:
    value = value.strip()
    if category in ("aadhaar", "card"):
        return re.sub(r"\D", "", value)
    if category == "phone_in":
        return re.sub(r"\D", "", value)[-10:]
    if category in ("email", "upi_id", "pan", "gstin", "ifsc"):
        return value.lower()
    return value


def leakmap_predict(sample, floor="medium"):
    _, matches = scan_body(sample["body"].encode(), sample["content_type"])
    return {(cat, norm(cat, raw)) for _, cat, raw, conf in matches
            if CONFIDENCE_RANK[conf] >= CONFIDENCE_RANK[floor]}


def presidio_engine(threshold: float):
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"])
    # Country-specific recognizers ship disabled; enable India's for a fair comparison.
    from presidio_analyzer.predefined_recognizers import InAadhaarRecognizer, InPanRecognizer
    for rec in (InAadhaarRecognizer(), InPanRecognizer()):
        registry.add_recognizer(rec)
    analyzer = AnalyzerEngine(registry=registry, supported_languages=["en"])

    def predict(sample):
        text = sample["body"]
        found = set()
        for r in analyzer.analyze(text=text, language="en", score_threshold=threshold):
            cat = PRESIDIO_MAP.get(r.entity_type)
            if cat:
                found.add((cat, norm(cat, text[r.start:r.end])))
        return found
    return predict


def score(samples, predict, categories=None):
    tp, fp, fn = Counter(), Counter(), Counter()
    errors = []
    for s in samples:
        gold = {(lab["category"], norm(lab["category"], lab["value"])) for lab in s["labels"]}
        pred = predict(s)
        if categories:
            gold = {g for g in gold if g[0] in categories}
            pred = {p for p in pred if p[0] in categories}
        for c, _ in gold & pred:
            tp[c] += 1
        for c, v in pred - gold:
            fp[c] += 1
            errors.append(("FP", c, v, s))
        for c, v in gold - pred:
            fn[c] += 1
            errors.append(("FN", c, v, s))
    return tp, fp, fn, errors


def pr(t, f, n):
    p = t / (t + f) if t + f else 1.0
    r = t / (t + n) if t + n else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1


def metrics(tp, fp, fn) -> dict:
    out = {}
    for c in sorted(set(tp) | set(fp) | set(fn)) + ["all"]:
        t, f, n = (sum(x.values()) for x in (tp, fp, fn)) if c == "all" else (tp[c], fp[c], fn[c])
        p, r, f1 = pr(t, f, n)
        out[c] = {"tp": t, "fp": f, "fn": n, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}
    return out


def save(path, meta: dict, tp, fp, fn):
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({**meta, "metrics": metrics(tp, fp, fn)}, indent=2) + "\n")


def table(tp, fp, fn) -> str:
    rows = ["| Category | Labeled | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|"]
    for c in sorted(set(tp) | set(fp) | set(fn)):
        p, r, f1 = pr(tp[c], fp[c], fn[c])
        rows.append(f"| {c} | {tp[c] + fn[c]} | {tp[c]} | {fp[c]} | {fn[c]} | {p:.1%} | {r:.1%} | {f1:.1%} |")
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    p, r, f1 = pr(T, F, N)
    rows.append(f"| **all (micro)** | {T + N} | {T} | {F} | {N} | **{p:.1%}** | **{r:.1%}** | **{f1:.1%}** |")
    return "\n".join(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["dev", "test"])
    ap.add_argument("--engine", choices=["leakmap", "presidio"], default="leakmap")
    ap.add_argument("--threshold", type=float, default=0.5, help="Presidio score threshold")
    ap.add_argument("--shared", action="store_true", help="only categories both engines support")
    ap.add_argument("--errors", type=int, nargs="?", const=25, default=0, help="print up to N mistakes")
    ap.add_argument("--json", help="also write metrics to this file")
    args = ap.parse_args()

    samples = [json.loads(line) for line in open(DATA / f"{args.split}.jsonl")]
    predict = presidio_engine(args.threshold) if args.engine == "presidio" else leakmap_predict
    cats = set(PRESIDIO_MAP.values()) - {"person_name"} if args.shared else None
    tp, fp, fn, errors = score(samples, predict, cats)
    print(f"{args.engine} on {args.split} ({len(samples)} samples)\n")
    print(table(tp, fp, fn))
    save(args.json, {"dataset": f"synthetic-{args.split}", "samples": len(samples), "engine": args.engine,
                     "threshold": args.threshold if args.engine == "presidio" else None,
                     "shared_only": args.shared}, tp, fp, fn)
    for kind, c, v, s in errors[: args.errors]:
        print(f"\n{kind} {c} {v!r} [{s['content_type']}] {s['body'][:220]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
