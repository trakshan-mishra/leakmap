# Real codebases, live

Run on 2026-11-01 with leakmap `a325d7e`. This is the live path: real code making real requests through leakmap's proxy. That's different from [real-traffic.md](real-traffic.md), which replays recorded requests offline.

Every run used `--stub`: each request got `{}` back locally, so nothing reached the real services, and errors after the first LLM call are expected. The only personal data in the inputs is fake: Rahul Kumar, rahul.k@example.com, +91 98765 43210, Aadhaar 2000 0000 0009 (Verhoeff-valid test number), PAN ABCPK1234F and card 4111 1111 1111 1111.

To check leakmap's results, the same programs were run a second time through a capture proxy (`real_codebases/rawcap.py`). It uses the same certificate setup but saves every body byte for byte. Request counts matched leakmap's runs exactly.

```bash
benchmark/real_codebases/run.sh /tmp/leakmap-real
```

## What ran

| Codebase | Version | What was run |
|---|---|---|
| simonw/llm-anthropic | `b66cdf1`, anthropic SDK 1.17.0, llm 0.36 | Its own test suite with recordings off (`--disable-recording`): 91 passed, 32 failed (failures from `{}` responses) |
| crewAI | 1.15.33 (openai 2.54.0) | One agent, one task whose description contains the fake customer |
| chromadb | 1.5.9 | In-memory client; add and query a document with fake data in text and metadata |
| LiteLLM | 1.106.6 | `completion()` to gpt-4o-mini with fake data in the message |
| gradio | 6.31.0 | Launch an Interface, then call it locally |

## Results, against the raw capture

| Codebase | Requests | Destinations | Planted values in bodies | Caught by leakmap | Flagged but not planted |
|---|---|---|---|---|---|
| llm-anthropic | 32 | Anthropic 31, static.simonwillison.net 1 | none (the tests' own prompts) | – | 0 |
| crewAI | 7 | OpenAI 6, telemetry.crewai.com 1 | Aadhaar, PAN, email, phone, name, each in 6 requests | Aadhaar, PAN, email, phone in all 6 | 0 |
| chromadb | 0 | – | – | – | – |
| LiteLLM | 2 | OpenAI 1, raw.githubusercontent.com 1 | card, email, phone in 1 request | all 3 | 0 |
| gradio | 4 | huggingface.co 3, api.gradio.app 1 | none (the local call never left the machine) | – | 0 |

**Every planted structured value that left the machine was caught: 27 of 27, and nothing was wrongly flagged.**

The one miss is the name "Rahul Kumar" in free text, in all 6 crewAI requests. leakmap finds names only by field name (`first_name`, `customer_name`…), never in prose. That's a known limit, now measured.

Masked leakmap events and the comparison counts: `results/2026-11-01-real-codebases/`. Raw bodies were not kept.

## What each library sends, from the raw capture

- **crewAI.**
  - 6 calls to OpenAI: 3 to `/v1/responses/input_tokens` (token counting) and 3 to `/v1/chat/completions`. The full task text, including the customer data, goes into both.
  - One OTLP protobuf trace to `telemetry.crewai.com/v1/traces`. leakmap decoded it. It contains the agent role, model name, error types, crewAI and Python versions, a CPU band, `crew_inputs_present = false`, and the name of the coding agent driving the run. It contains no task text and no customer data.
- **LiteLLM.** On import it fetches `raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json`, a model price list, with no body. Then one chat completion to OpenAI carrying the message.
- **gradio.** Bodyless requests:
  - `GET api.gradio.app/pkg-version`, a version check;
  - `GET huggingface.co/api/agent-harnesses`;
  - two `HEAD huggingface.co/api/telemetry/…/gradio-initiated-analytics` and `…/gradio-launched-telemetry`, where the event name is in the URL path.
- **chromadb.** Nothing. In 1.5.9 its PostHog telemetry client is a no-op (`capture()` is `pass`), even though `anonymized_telemetry` defaults to true.
- **llm-anthropic.** 28 `/v1/messages` and 3 `/v1/messages/count_tokens` calls, plus one `HEAD` for an image used by an attachment test.

## Gaps this found

1. **Names in free text are not detected** (6 of 6 in crewAI). An NER model would fix it but costs precision and speed. Worth trying behind an option.
2. **URL paths are not scanned.** Only bodies and query strings are (`detect.py`, `inspect_request`). Gradio puts telemetry event names in the path, and a library that put an email or ID there would be missed.
3. **The vendor catalog misses common hosts:** `huggingface.co` (only Hugging Face's inference hosts are listed), `telemetry.crewai.com`, `api.gradio.app`, `raw.githubusercontent.com`. They appear as unknown hosts with country `??`.

## Advisories in the throwaway environments

These were installed only for this test, in separate environments, and are not leakmap dependencies. Each environment was audited with pip-audit right after install.

| Package | Advisory | What it is | Relevant to this run? |
|---|---|---|---|
| chromadb 1.5.9 (also pulled in by crewAI) | PYSEC-2026-3813 / CVE-2026-45830 | Authenticated users can read or write other tenants' collections | No: in-memory client, no server |
| pillow 12.3.0 (gradio) | GHSA-78g4-xqwv-q3g8, fixed in 13.0.0 | Heap overflow in the bundled libopenjp2 via `Image.open()` | No images were opened |
| filelock 3.32.7 (LiteLLM) | CVE-2026-112908, fixed in 4.2.1 | No description published in OSV | Unknown |

The environments were deleted after the run.
