# Real traffic: public VCR cassettes

First run on 2026-10-31 against leakmap commit `47a536f`, with detectors unchanged from that commit. Two rules were then fixed; see [After the fix](#after-the-fix).

## Data

VCR cassettes are recordings of real HTTP calls that projects commit so their tests can replay them. They show what SDKs actually put on the wire. Only the `cassettes/` folders were downloaded (sparse clone); no project code was run.

| Repo | Commit | License | Cassette files |
|---|---|---|---|
| pydantic/pydantic-ai | `2a89126b7a96` | MIT | 2,162 |
| crewAIInc/crewAI | `97bbfb648117` | MIT | 601 |
| langchain-ai/langchain | `6671bf76d3e1` | MIT | 135 |
| simonw/llm-anthropic | `b66cdf112c7d` | Apache-2.0 | 32 |

```bash
python benchmark/cassettes.py <folder with the clones> --out findings.jsonl
```

2,930 files parsed with no errors: 5,109 outgoing requests (26,624 more went to localhost and were skipped). Top destinations: OpenAI 1,913, Anthropic 909, Google Gemini 637, AWS Bedrock 419, Vertex AI 177, OpenRouter 122.

## Parsing

| Body | Requests | Notes |
|---|---|---|
| JSON | 3,264 | |
| empty | 1,746 | GETs |
| OTLP protobuf | 65 | All to `telemetry.crewai.com`; all decoded into 48 attribute paths |
| text | 26 | SDP offers, a text body labelled JSON, and 2 multipart bodies that pydantic-ai stores base64-encoded |
| form | 7 | |
| binary | 1 | A raw multipart upload. In proxy mode mitmproxy splits multipart into fields (`addon.py:33`); only this offline path sees raw bytes |

The CrewAI telemetry is a real example of the problem leakmap targets. Decoded attributes include `crew_agents[].backstory`, `crew_agents[].goal`, `crew_tasks[].description` and `crew_tasks[].expected_output` (15 of 65 requests), which is prompt content sent to CrewAI's telemetry endpoint. No personal data was in it in these recordings.

## Every match, judged by hand (before the fix)

18 matches; 14 at the default `medium` floor. Secret values are masked here.

| # | Where | Field | Category (conf.) | Value | Verdict | Rule and why it fired |
|---|---|---|---|---|---|---|
| 1–3 | crewAI cassette (file withheld) → oauth2.googleapis.com | `form.client_secret` | secret (high) | (removed) | Correct | Field rule `password` (`client_?secret`, detectors.yaml:172). The `client_id` is Google Cloud SDK's (`CLOUD_SDK_CLIENT_ID` in google-auth `_cloud_sdk.py`); whether this secret is public too is not verified |
| 4–6 | same | `form.refresh_token` | secret (high) | (removed) | Correct | Same rule (`refresh_?token`). A user's Google refresh token committed to a public repo. Not tested for validity |
| 7 | crewAI `test_crew_emits_end_task_event.yaml` → api.agentops.ai | `session.jwt` | secret (medium) | (removed) | Correct | `jwt` pattern (detectors.yaml:60). A session token sent back to its issuer, so a credential but not a leak |
| 8 | pydantic-ai `test_google_validated_accepts_strict_incompatible_schema.yaml` → Gemini | `contents[].parts[].functionCall.args.address.street` | address (high) | `123 Main St.` | Correct | Field rule `address` (`street`, detectors.yaml:150). Test value, but it is an address in a tool call sent to the model |
| 9 | same | `…functionCall.args.password` | secret (high) | (removed) | Correct | Field rule `password` |
| 10–13 | pydantic-ai `test_google_model_file_search_*` (4 files) → Gemini | `displayName` | person_name (high) | `test-file-search-store` etc. | **False positive** | Field rule `person_name` matches the key `displayName` (`display_?name`, detectors.yaml:140) and never looks at the value. In Google's API it names a file-search store, not a person |
| 14 | crewAI `test_using_memory.yaml` → OpenAI | `messages[].content` | phone_in (medium) | `6251497744` | **False positive** | Text is `<MagicMock name='build_context_for_task()' id='6251497744'>`, a Python object id. It fits the mobile pattern (6 + 9 digits, detectors.yaml:112). The negative-context list (detectors.yaml:17) only knows `id` after a word like "order" or "ticket", so a bare `id='` doesn't rule it out |
| 15–18 | crewAI `test_crew_emits_end_task_event.yaml` → AgentOps | `…Installed Packages.opencv-python-headless`, `…ninja` | ip_address (low) | `4.11.0.86`, `1.11.1.3` | False positive, hidden by default | Four-part version numbers that are valid public IPv4 addresses. The key is a package name, so neither the hint nor the negative context applies. Low confidence, so the default report only counts them as hidden |

**Precision at the default floor: 9 of 14 matches correct (64%).** Counting distinct (file, field, value) instead, it is 5 of 10. That's below the 90% target, caused by two rules: `displayName` and a bare `id=`. At floor `low` it is 9 of 18.

## What was missed

There are no labels, so recall can only be checked for what a broad search can find:

- **Emails:** a bounded email regex over every outgoing body found **0** addresses. Nothing to miss.
- **Card and Aadhaar numbers:** every 12–19 digit run was checked with Luhn plus issuer prefix, and 12-digit runs with Verhoeff. **0** passed, so there's nothing leakmap could have caught and didn't.
- **Names and addresses in free text:** not measurable here without labels. leakmap only finds names through field names, so a name written inside a prompt is not detected. That is a known gap, not something this run tested.

## Vendor coverage

4,618 of 5,109 requests (90.4%) went to a host in `vendors.yaml`. The 491 unknown include `app.crewai.com`, `telemetry.crewai.com`, `api.scarf.sh` (package-download telemetry), `api.githubcopilot.com`, `oauth2.googleapis.com` and `gateway.pydantic.info`. They are reported as `host:<name>` with country `??`, not guessed.

## After the fix

Two rule changes, made after seeing the matches above:

- `person_name` field rule: a value that looks like a lowercase identifier (`^[a-z0-9]+([-_][a-z0-9]+)+$`) is skipped.
- Number negatives (phone, Aadhaar, card): a bare `id` before the number rules it out (`<MagicMock … id='…'>`, `user id: …`). Confirming words like "phone" or "aadhaar" still win.

Results, from `results/2026-10-31-before-fix/` → `results/2026-10-31-after-fix/`:

| Run | Before | After |
|---|---|---|
| Cassettes, default-floor matches correct | 9 / 14 | 9 / 9 (tuned on this data) |
| Synthetic test, P / R | 100 / 99.26 | 100 / 99.26 |
| Synthetic dev, P / R | 100 / 99.73 | 100 / 99.73 |
| Gretel email+card+IP, floor low, P / R | 98.67 / 98.37 | 98.67 / 98.24 |

The Gretel drop is 3 cards (373 → 370) that the dataset placed after "customer ID", "Dispute ID" and "Reservation ID". leakmap already skipped numbers after "Transaction ID" and "Order ID", so this is the same trade-off applied consistently. Both cases are now regression tests in `tests/test_detect.py`.

## Takeaways

1. On real SDK traffic, almost everything leakmap flagged at high confidence through a credential shape or a credential field name was right, including one real credential committed to a public repo.
2. Both default-visible false positives came from rules that looked at only one signal: a field name without its value, or digits without enough context. Both are fixed (above).
3. This set contains almost no personal data, so it measures false alarms on real traffic, not recall. Recall evidence comes from the Gretel run in [README.md](README.md).
