# Benchmark

Two datasets, scored on exact (category, normalised value) pairs. The default confidence floor is `medium`, same as the CLI.

## 1. Synthetic API traffic (`generate.py`, `evaluate.py`)

Request bodies shaped like what apps actually send: LLM chat messages, analytics properties, log lines, Sentry envelopes, form posts and OTLP attributes. Negatives are built in: order IDs, IMEIs, SIM ICCIDs, UUIDs, timestamps, version strings and amounts.

Dev and test use different sentence templates and seeds. Detectors were tuned on dev only; test was scored once afterwards.

```bash
python benchmark/generate.py
python benchmark/evaluate.py test
python benchmark/evaluate.py test --engine presidio --shared   # needs presidio-analyzer + en_core_web_lg
```

leakmap, test split (1,500 samples, 1,492 labels): **precision 100.0%, recall 99.3%, F1 99.6%**. The 11 misses are names and dates of birth under a generator-made field name (`customer_name_2`) that the field rules don't match.

On the categories both tools support, compared with Presidio 2.2 + spaCy `en_core_web_lg` (India recognizers enabled, threshold 0.5):

| Category | leakmap P / R | Presidio P / R |
|---|---|---|
| Aadhaar | 100 / 100 | 82.3 / 96.7 |
| Card | 100 / 100 | 75.2 / 75.9 |
| Email | 100 / 100 | 100 / 84.8 |
| Public IP | 100 / 100 | 100 / 100 |
| PAN | 100 / 100 | 100 / 100 |
| Indian mobile | 100 / 100 | 92.0 / 67.8 |
| **All** | **100 / 100** | **90.9 / 87.6** |

Presidio's card and Aadhaar false positives are mostly IMEIs and ICCIDs, which pass Luhn. Its email misses are URL-encoded form values: Presidio scans the raw body, while leakmap decodes it first.

Read this table with care. I wrote both the generator and the detectors, so this split tests the formats I expected. It is a regression suite, not proof.

## 2. Gretel PII test split (`gretel.py`)

[gretelai/gretel-pii-masking-en-v1](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1) (Apache-2.0): 5,000 documents written by someone else. The script downloads about 4 MB on first run; the data is not stored in this repo. Detectors were not changed after seeing it.

Only the categories both sides label are scored. Gold card numbers that fail Luhn (an LLM wrote many of them, some truncated) and private IPs are dropped.

```bash
python benchmark/gretel.py                  # default floor
python benchmark/gretel.py --floor low
python benchmark/gretel.py --engine presidio
```

Email + card + IPv4:

| | Precision | Recall | F1 |
|---|---|---|---|
| leakmap, floor `medium` (default) | 99.0% | 78.3% | 87.4% |
| leakmap, floor `low` | 98.7% | 98.4% | 98.5% |
| Presidio, threshold 0.5 (IPv6 excluded) | 95.7% | 96.5% | 96.1% |

What the errors are:

- **IP recall at the default floor (46%).** A bare IP with no nearby word like "client" or "ip" is low confidence, because in API traffic it is usually a server address. The report still counts these as hidden findings. At floor `low` IP recall is 98.9%.
- **Email "false positives" (16).** 15 are real addresses Gretel did not label (`support@…`, `privacy@…`, `billing@…`); one is a typo in a Gretel label.
- **Card misses (26).** Mostly card-valid numbers that the dataset put in "Transaction ID", "Order ID", "Booking Ref" or "nonce" fields. leakmap drops numbers after those words on purpose. One is a real miss: "credit card used for booking, 5429…".
- **Secrets (P 78%, R 15%, not in the table above).** Most Gretel API keys use invented formats (`sl.`, `lnkd-`, AIza with the wrong length) or are bare hex strings that no shape-based scanner can tell apart from a hash. The two real formats missed, SendGrid `SG.` and Square `sq0atp-`, are not covered yet.
