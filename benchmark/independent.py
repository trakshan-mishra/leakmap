"""Score leakmap per category on public PII datasets that its author did not write.

    uv run --with pyarrow==21.0.0 python benchmark/independent.py --download
    uv run --with pyarrow==21.0.0 python benchmark/independent.py ylemis --floor low

Every file is pinned to a dataset commit and checked against its sha256.
Scoring is type-aware span overlap (a prediction counts if it overlaps a gold
span of the same category), the primary metric of the Ylemis benchmark.

Generators write values that real systems never issue (Aadhaar starting with
0, cards failing Luhn, SSN area 9xx). leakmap drops those on purpose, so recall
is reported twice: against every label, and against labels that pass the
category's checksum. Labels leakmap has no category for are listed with how
often any finding overlapped them, so gaps are visible rather than left out.
"""

import argparse
import ast
import hashlib
import json
import math
import multiprocessing
import random
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from leakmap import validators as v
from leakmap.detect import scan_body
from leakmap.model import CONFIDENCE_RANK

DATA = Path(__file__).parent / "data"
HF = "https://huggingface.co/datasets/{repo}/resolve/{rev}/{path}"

# name: (repo, revision, [(path, sha256)], licence)
SOURCES = {
    "nemotron": ("nvidia/Nemotron-PII", "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
                 [("data/test-00000-of-00001.parquet", "1a4b0512ecb5370f0992d29d0f9c07351e6de13f0d7ea33bb18cecb984780247")],
                 "CC-BY-4.0"),
    "gretel-finance": ("gretelai/synthetic_pii_finance_multilingual", "7b844d16738527a04264f50214cb426a4cea0897",
                       [("data/test-00000-of-00001.parquet", "014e1057978f030fce4f4cad7c93b9e3377fd0ded713d2bf4c7de00e3e3c8c72")],
                       "Apache-2.0"),
    "ylemis": ("Pranshurs/ylemis-india-pii-benchmark", "dafb239bab71cd336549de70d3328afc5a1cb652",
               [("benchmark.jsonl", "7003719c62f451b68ec68280fbccaca12990718ad9ee7aacbcaba66c4c43f914")],
               "CC0-1.0"),
    "maskara": ("somukandula/maskara-indian-pii-200k", "0146bc560e657a52a17113b9fb227498b751901a",
                [("data/template_disjoint_eval-00000-of-00001.parquet", "127953108ff228272647f7c8cb6fcb761d8d02850a48d67345d876c1a99c7b59"),
                 ("data/real_world_eval-00000-of-00001.parquet", "b0ddfeb444172ca655e483ce2b9de10c193abcf8ef932bfd0610a7eee48eef84")],
                "MIT"),
    # Development only: rules were tuned on these, so they are never reported.
    "nemotron-train": ("nvidia/Nemotron-PII", "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
                       [("data/train-00000-of-00001.parquet", "9cb1a88c339ab84ddbc35ccdde4f6bb713300f5585881f9e02b8db1e0dfdbece")],
                       "CC-BY-4.0"),
    "maskara-train": ("somukandula/maskara-indian-pii-200k", "0146bc560e657a52a17113b9fb227498b751901a",
                      [("data/train-00000-of-00001.parquet", "82f88fe4f312aa2b880c1ebacfb0099885aa4d7ca3a7c1ad3989be906fb544e6")],
                      "MIT"),
}
REPORTED = ["nemotron", "gretel-finance", "ylemis", "maskara"]

PHONE, ID, IP, SECRET, NAME, ADDR = "phone", "id_document", "ip_address", "secret", "person_name", "address"

# Dataset label -> scored category. Labels not listed are reported as unmapped.
LABELS = {
    "nemotron": {
        "email": "email", "phone_number": PHONE, "fax_number": PHONE, "credit_debit_card": "card",
        "ipv4": IP, "ipv6": IP, "api_key": SECRET, "password": SECRET, "ssn": "ssn",
        "swift_bic": "swift_bic", "bank_routing_number": "bank_routing", "account_number": "bank_account",
        "mac_address": "mac_address", "vehicle_identifier": "vin", "license_plate": "vehicle_reg",
        "date_of_birth": "date_of_birth", "first_name": NAME, "last_name": NAME, "street_address": ADDR,
        "postcode": "postal_code", "gender": "gender", "coordinate": "coordinates", "cvv": "cvv",
        "pin": "account_pin", "medical_record_number": "health_id", "health_plan_beneficiary_number": "health_id",
        "blood_type": "health", "tax_id": "tax_id", "national_id": ID, "certificate_license_number": ID,
    },
    "gretel-finance": {
        "email": "email", "phone_number": PHONE, "credit_card_number": "card", "ipv4": IP, "ipv6": IP,
        "api_key": SECRET, "password": SECRET, "ssn": "ssn", "swift_bic_code": "swift_bic",
        "bank_routing_number": "bank_routing", "bban": "bank_account", "iban": "iban",
        "date_of_birth": "date_of_birth", "name": NAME, "first_name": NAME, "last_name": NAME,
        "street_address": ADDR, "credit_card_security_code": "cvv", "account_pin": "account_pin",
        "driver_license_number": "driving_licence", "passport_number": "passport", "local_latlng": "coordinates",
    },
    "ylemis": {
        "person": NAME, "indian_phone": PHONE, "address": ADDR, "pan": "pan", "aadhaar": "aadhaar",
        "upi_id": "upi_id", "email": "email", "ifsc": "ifsc", "medical_id": "health_id", "voter_id": "voter_id",
        "vehicle_registration": "vehicle_reg", "gstin": "gstin", "indian_passport": "passport",
    },
    "maskara": (MASKARA := {
        "PERSON_NAME": NAME, "PHONE": PHONE, "AADHAAR": "aadhaar", "EMAIL": "email", "DATE_OF_BIRTH": "date_of_birth",
        "ADDRESS": ADDR, "DRIVER_LICENSE": "driving_licence", "VEHICLE_REG": "vehicle_reg", "API_KEY": SECRET,
        "IP_ADDRESS": IP, "UPI_ID": "upi_id", "PASSWORD": SECRET, "PASSPORT": "passport", "PAN_CARD": "pan",
        "CREDIT_CARD": "card", "SSN": "ssn",
    }),
}
LABELS["nemotron-train"] = LABELS["nemotron"]
LABELS["maskara-train"] = MASKARA

# leakmap category -> scored category, where leakmap is finer than the datasets.
ALIAS = {"phone_in": PHONE}
# A postal code is part of an address: not a false alarm when it sits inside a gold address.
INSIDE = {"postal_code": {ADDR}}


def _check(name):
    fn = getattr(v, name, None)
    return (lambda s: fn(s.strip())) if fn else None


def _ip(s):
    s = re.sub(r"/\d+$", "", s.strip())
    return v.ipv4_public(s) or (v.ipv6_global(s) if hasattr(v, "ipv6_global") else False)


# Checksum or registry rule a real value always passes. Gold labels that fail are
# still counted in "recall (all labels)"; "recall (valid)" leaves them out.
VALID = {
    "card": lambda s: v.luhn(s) and v.card_issuer("".join(c for c in s if c.isdigit())),
    "aadhaar": lambda s: v.verhoeff(re.sub(r"\D", "", s)[-12:]) and re.sub(r"\D", "", s)[-12:][:1] in "23456789",
    "gstin": _check("gstin"),
    "pan": lambda s: bool(re.fullmatch(r"[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]", re.sub(r"\s", "", s).upper())),
    IP: _ip,
    "iban": _check("iban"),
    "bank_routing": _check("aba_routing"),
    "ssn": _check("ssn"),
    "vin": _check("vin"),
    PHONE: _check("phone"),
    "swift_bic": _check("swift_bic"),
    # Some gold spans are offset from their value; an email span without @ is one of those.
    "email": lambda s: "@" in s,
}


def fetch(name):
    repo, rev, files, _ = SOURCES[name]
    out = []
    for path, sha in files:
        dest = DATA / name / Path(path).name
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            print(f"downloading {repo}/{path}", file=sys.stderr)
            dest.write_bytes(urllib.request.urlopen(HF.format(repo=repo, rev=rev, path=path), timeout=300).read())
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if digest != sha:
            raise SystemExit(f"{dest}: sha256 {digest} does not match the pinned {sha}")
        out.append(dest)
    return out


def _parquet(path):
    import pyarrow.parquet as pq
    return pq.read_table(path).to_pylist()


def _spans(raw):
    return ast.literal_eval(raw) if isinstance(raw, str) else raw


def load(name):
    """Yield (id, text, [(label, start, end)], negative kind or None) for every document."""
    paths = fetch(name)
    if name.startswith("nemotron"):
        for r in _parquet(paths[0]):
            yield r["uid"], r["text"], [(s["label"], s["start"], s["end"]) for s in _spans(r["spans"])], None
    elif name == "gretel-finance":
        for i, r in enumerate(_parquet(paths[0])):
            spans = [(s["label"], s["start"], s["end"]) for s in json.loads(r["pii_spans"])]
            yield str(i), r["generated_text"], spans, None
    elif name == "ylemis":
        for line in paths[0].open():
            r = json.loads(line)
            neg = r["category"] if r["category"] in ("hard_negative", "benign") else None
            yield r["id"], r["text"], [(e["type"], e["start"], e["end"]) for e in r["entities"]], neg
    elif name.startswith("maskara"):
        for path in paths:
            for r in _parquet(path):
                spans = [(e["label"], e["start"], e["end"]) for e in r["entities"]]
                yield r["id"], r["text"], spans, r["template_family"] if r["difficulty"] == "hard_negative" else None


def predict(text):
    """[(category, start, end, confidence)] for leakmap's findings, located in text."""
    _, matches = scan_body(text.encode(), "text/plain")
    out = set()
    for _, cat, raw, conf in matches:
        cat = ALIAS.get(cat, cat)
        raw = raw.strip()
        if not raw:
            continue
        edge = (r"(?<![A-Za-z0-9])" if raw[0].isalnum() else "") + re.escape(raw) + (r"(?![A-Za-z0-9])" if raw[-1].isalnum() else "")
        for m in re.finditer(edge, text):
            out.add((cat, m.start(), m.end(), conf))
    return sorted(out)


def _score_doc(args):
    name, text, gold, neg, extra = args
    preds = predict(text)
    if extra:
        preds += extra
    return text, gold, neg, preds


def overlaps(a0, a1, b0, b1):
    return a0 < b1 and b0 < a1


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(100 * (c - h), 1), round(100 * (c + h), 1)]


def pct(k, n):
    return round(100 * k / n, 1) if n else None


def evaluate(name, docs, floor, ner=None):
    labels = LABELS[name]
    rank = CONFIDENCE_RANK[floor]
    tp, fn, fp, tpv, fnv = Counter(), Counter(), Counter(), Counter(), Counter()
    wrong_type, unmapped_hit, unmapped_n = defaultdict(Counter), Counter(), Counter()
    neg_docs, neg_hit = Counter(), Counter()
    examples = defaultdict(list)
    extras = ner.predict_many([d[1] for d in docs]) if ner else [None] * len(docs)
    jobs = [(name, text, gold, neg, extra) for (_, text, gold, neg), extra in zip(docs, extras)]
    # torch is not fork-safe once the model is loaded.
    with ProcessPoolExecutor(mp_context=multiprocessing.get_context("spawn") if ner else None) as pool:
        results = list(pool.map(_score_doc, jobs, chunksize=200))
    for text, gold, neg, preds in results:
        preds = [p for p in preds if CONFIDENCE_RANK[p[3]] >= rank]
        if neg:
            neg_docs[neg] += 1
            neg_hit[neg] += bool(preds)
            if preds and len(examples[("neg", neg)]) < 10:
                examples[("neg", neg)].append(f"{text[:160]} -> {sorted({p[0] for p in preds})}")
        for label, s, e in gold:
            cat = labels.get(label)
            hit_any = any(overlaps(s, e, p[1], p[2]) for p in preds)
            if cat is None:
                unmapped_n[label] += 1
                unmapped_hit[label] += hit_any
                continue
            hit = any(p[0] == cat and overlaps(s, e, p[1], p[2]) for p in preds)
            ok = VALID.get(cat)
            valid = ok(text[s:e]) if ok else True
            (tp if hit else fn)[cat] += 1
            if valid:
                (tpv if hit else fnv)[cat] += 1
            if not hit and valid and len(examples[("fn", cat)]) < 15:
                examples[("fn", cat)].append(text[max(0, s - 40):e + 10])
        for cat, s, e, conf in preds:
            if any(labels.get(label) in ({cat} | INSIDE.get(cat, set())) and overlaps(s, e, gs, ge)
                   for label, gs, ge in gold):
                continue
            fp[cat] += 1
            other = [label for label, gs, ge in gold if overlaps(s, e, gs, ge)]
            wrong_type[cat][other[0] if other else "(no label)"] += 1
            if len(examples[("fp", cat)]) < 15:
                examples[("fp", cat)].append(f"{text[max(0, s - 40):s]}[[{text[s:e]}]]{text[e:e + 10]}")
    cats = sorted(set(labels.values()) | set(fp))
    rows = {}
    for c in cats:
        n_gold, n_pred = tp[c] + fn[c], tp[c] + fp[c]
        rows[c] = {
            "gold": n_gold, "tp": tp[c], "fp": fp[c], "fn": fn[c],
            "precision": pct(tp[c], n_pred), "precision_ci": wilson(tp[c], n_pred),
            "recall": pct(tp[c], n_gold), "recall_ci": wilson(tp[c], n_gold),
            "gold_valid": tpv[c] + fnv[c], "recall_valid": pct(tpv[c], tpv[c] + fnv[c]),
            "recall_valid_ci": wilson(tpv[c], tpv[c] + fnv[c]),
            "fp_on_other_label": dict(wrong_type[c].most_common(5)),
        }
    return {
        "dataset": name, "repo": SOURCES[name][0], "revision": SOURCES[name][1], "licence": SOURCES[name][3],
        "documents": len(docs), "floor": floor, "ner": bool(ner), "categories": rows,
        "unmapped_labels": {k: {"gold": n, "any_finding_overlaps": pct(unmapped_hit[k], n)}
                            for k, n in unmapped_n.most_common()},
        "negative_documents": sum(neg_docs.values()), "negative_documents_with_findings": sum(neg_hit.values()),
        "negative_fpr": pct(sum(neg_hit.values()), sum(neg_docs.values())),
        "negative_fpr_ci": wilson(sum(neg_hit.values()), sum(neg_docs.values())),
        "negative_by_kind": {k: {"documents": n, "with_findings": neg_hit[k], "fpr": pct(neg_hit[k], n)}
                             for k, n in sorted(neg_docs.items())},
    }, examples


def show(res):
    print(f"\n{res['dataset']} ({res['documents']} docs, floor {res['floor']}{', ner' if res['ner'] else ''})")
    print(f"{'category':16s} {'gold':>6s} {'tp':>6s} {'fp':>6s} {'precision':>18s} {'recall':>18s} {'recall valid':>20s}")
    fmt = lambda p, ci: "-" if p is None else f"{p:5.1f} [{ci[0]:.0f}-{ci[1]:.0f}]"  # noqa: E731
    for c, r in res["categories"].items():
        print(f"{c:16s} {r['gold']:6d} {r['tp']:6d} {r['fp']:6d} {fmt(r['precision'], r['precision_ci']):>18s} "
              f"{fmt(r['recall'], r['recall_ci']):>18s} {fmt(r['recall_valid'], r['recall_valid_ci']):>14s} n={r['gold_valid']}")
    if res["negative_documents"]:
        print(f"negative documents with any finding: {res['negative_documents_with_findings']}/"
              f"{res['negative_documents']} ({res['negative_fpr']}%)",
              {k: f"{x['with_findings']}/{x['documents']}" for k, x in res["negative_by_kind"].items()})
    print("unmapped:", ", ".join(f"{k} {x['gold']} ({x['any_finding_overlaps']}%)" for k, x in res["unmapped_labels"].items()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("datasets", nargs="*", default=REPORTED)
    ap.add_argument("--download", action="store_true", help="only download and verify")
    ap.add_argument("--floor", choices=["low", "medium", "high"], default="medium")
    ap.add_argument("--sample", type=int, help="score a fixed random sample of this many documents")
    ap.add_argument("--ner", action="store_true", help="add leakmap's optional NER model (needs leakmap[ner])")
    ap.add_argument("--json", type=Path, help="write results to this file")
    ap.add_argument("--examples", type=Path, help="write misses and false alarms here (not for committing)")
    args = ap.parse_args()

    if args.download:
        for name in args.datasets:
            fetch(name)
        return 0
    ner = None
    if args.ner:
        from leakmap.ner import NER
        ner = NER()
    results, all_examples = [], {}
    for name in args.datasets:
        docs = list(load(name))
        if args.sample and args.sample < len(docs):
            docs = random.Random(0).sample(docs, args.sample)
        res, ex = evaluate(name, docs, args.floor, ner)
        res["sample"] = args.sample
        show(res)
        results.append(res)
        all_examples[name] = {f"{k[0]} {k[1]}": x for k, x in ex.items()}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
    if args.examples:
        args.examples.write_text(json.dumps(all_examples, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
