# leakmap

See what personal data your app sends to third parties. Fail CI when a new flow appears.

Run your tests through leakmap. It records every outgoing request, finds personal data in it (Aadhaar, PAN, UPI IDs, Indian mobile numbers, emails, cards and more), names the company and country receiving it, and keeps a reviewed baseline in your repo. A pull request that starts sending something new fails the check.

![leakmap report](docs/report.png)

## Try it (10 seconds, offline)

```bash
uv tool install leakmap
leakmap demo --open
```

leakmap is not on PyPI yet. Until it is, install from the repo: `uv tool install git+https://github.com/trakshan-mishra/leakmap`.

The demo runs a small fake support bot that calls OpenAI, Langfuse, Sentry, Mixpanel, Razorpay and an unknown CRM. Every request is answered locally, so nothing leaves your machine.

## Use it on your app

```bash
leakmap run -- pytest              # record what your tests send out
leakmap report --format html -o leakmap.html
leakmap baseline                   # accept current flows into leakmap.lock, then commit it
leakmap check                      # exit 1 if a run has flows not in leakmap.lock
```

In CI, one step does both:

```yaml
- run: uv tool install leakmap
- run: leakmap run --stub --check -- pytest
```

`--stub` answers every request locally, so CI never sends test data to real vendors. Leave it off to forward requests normally.

## What it finds

| Data | How |
|---|---|
| Aadhaar | 12 digits + Verhoeff checksum |
| PAN, GSTIN | Structure; GSTIN check character |
| UPI ID | `name@handle` for 50+ bank/app handles |
| Indian mobile | +91 / 0 / bare 10-digit 6–9 numbers |
| Email, payment card, public IP, IFSC | Patterns; Luhn for cards |
| Name, date of birth, address, PIN code, gender, health fields | Field names |
| API keys and secrets | OpenAI/Anthropic, AWS, GitHub, Slack, Google, Stripe/Razorpay live keys, private keys, JWTs, password fields |

It looks inside JSON, JSON encoded inside JSON (common in tracing SDKs), NDJSON / Sentry envelopes, form bodies, multipart, query strings and **OpenTelemetry protobuf** (Langfuse, Logfire, Arize, Traceloop). Detectors live in [`leakmap/data/detectors.yaml`](leakmap/data/detectors.yaml); vendors in [`leakmap/data/vendors.yaml`](leakmap/data/vendors.yaml) (124 companies).

Precision comes first: a check that raises false alarms gets removed from CI. The test suite includes everyday payloads (UUIDs, trace IDs, timestamps, order IDs, tool schemas) that must produce no findings.

## Accuracy

On [Gretel's public PII test set](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1) (5,000 documents, not written by me, detectors not tuned on it), for email, card and IPv4:

| | Precision | Recall |
|---|---|---|
| leakmap (all confidence levels) | 98.7% | 98.2% |
| leakmap (default `medium` floor) | 99.0% | 78.2% |
| Presidio 2.2 + spaCy lg | 95.7% | 96.5% |

The default floor hides bare IPs with no context, which is where the recall difference comes from. On a synthetic set of Indian API traffic (Aadhaar, PAN, UPI, mobile and the rest), the held-out split scores 100% precision and 99.3% recall, against 90.9% / 87.6% for Presidio on the shared categories. I wrote that set, so treat it as a regression suite. Method, per-category tables and every error type are in [`benchmark/`](benchmark/README.md).

On real traffic recorded in public test suites (pydantic-ai, crewAI, langchain, llm-anthropic: 5,109 requests to OpenAI, Anthropic, Gemini, Bedrock and others), every match was checked by hand. Before the fix, 9 of 14 default-floor matches were correct; two rules caused the rest and were fixed, which brings it to 9 of 9. That second number is tuned on the same data. Details: [`benchmark/real-traffic.md`](benchmark/real-traffic.md). Run live on real codebases (crewAI, LiteLLM, chromadb, gradio, llm-anthropic's test suite) and checked against a raw capture, it caught 27 of 27 planted values that left the machine, with no false alarms; it missed a name written in free text. See [`benchmark/real-codebases.md`](benchmark/real-codebases.md).

## Tested against real SDKs

`tests/test_real_sdks.py` runs the official SDKs through the proxy with fake values and checks what is found:

| SDK | Version | What leakmap saw |
|---|---|---|
| openai | 3.42.0 | Aadhaar, email, phone in `messages[].content` |
| anthropic | 2.3.0 | Aadhaar, email, phone in `messages[].content` |
| langfuse | 5.1.0 | Aadhaar, email, phone in OTLP attribute `langfuse.observation.input` (captured automatically by `@observe`) |
| sentry-sdk | 2.73.0 | PAN in the exception message, IP in `user`, plus nearby **source code lines** |
| posthog | 7.81.1 | phone, UPI ID in event properties |
| mixpanel | 5.4.1 | name, PAN in event properties |

## Rules (`leakmap.yaml`, optional)

```yaml
home_country: IN          # flows outside this country are highlighted
min_confidence: medium    # low | medium | high
ignore_hosts: ["*.internal.example.com"]
deny:                     # always fail, even if baselined
  - data: aadhaar
    country_not: IN
    reason: Aadhaar must not leave India
```

## How it works

`leakmap run` starts [mitmproxy](https://mitmproxy.org) on 127.0.0.1 and runs your command with `HTTPS_PROXY` and a temporary CA set for Python, Node (`NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY`), curl and Go. Each request is inspected in memory; only the category, field path and a masked sample (`AB******4F`) are written. Bodies, headers and credentials are never stored, and the CA is deleted when the run ends.

## Limits

- It sees requests that reach the network. If your tests mock HTTP clients, those calls are invisible; run an integration suite or a staging smoke test instead.
- Browser-side trackers (pixels, analytics JS) are not covered yet; this is for backend and test traffic.
- In `--stub` mode every request gets `{}` back. SDKs that validate responses may log errors.
- Country is the vendor's headquarters. Where your data is processed depends on your plan and region; check the vendor's DPA.
- A clean report means leakmap saw nothing in this run, not that nothing is sent. It is evidence for a privacy review, not legal advice or a compliance certificate.

## License

Apache-2.0
