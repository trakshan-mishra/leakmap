# Contributing

Thanks for looking. Bug reports with a sample request body (fake values only) are the most useful thing you can send.

## Setup

```bash
git clone https://github.com/trakshan-mishra/leakmap
cd leakmap
uv sync --extra dev
uv run pytest -q
```

## Before opening a pull request

```bash
uv run pytest -q                                   # unit, e2e and fuzz tests
uvx ruff@0.17.3 check leakmap tests benchmark
uv run mypy leakmap
```

CI runs the same three checks plus a dependency audit.

## Changing a detector

Detectors live in [`leakmap/data/detectors.yaml`](leakmap/data/detectors.yaml). A change needs:

- a test in `tests/test_detect.py` that the new value is found;
- a test that a similar everyday value is **not** found, for example an order ID or a timestamp. False alarms get a check removed from CI, so they matter as much as misses.
- a before/after run of `benchmark/independent.py` on the train splits (`nemotron-train`, `maskara-train`) if the change could move recall. Don't tune on the test sets; see [`benchmark/independent.md`](benchmark/independent.md).

## Test data

Use generated or published fake values only. Never paste real personal data or real credentials into an issue, a test or a fixture.

## Security problems

Report them privately; see [SECURITY.md](SECURITY.md).
