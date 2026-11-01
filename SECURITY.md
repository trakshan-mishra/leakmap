# Security

## Reporting a problem

Please don't open a public issue for a security problem. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. I'll reply within a week.

Supported version: the latest release only (currently 0.1.x).

## What leakmap does with your traffic

leakmap decrypts HTTPS traffic on your machine, so it should be judged the way you'd judge any local proxy:

- The proxy listens on `127.0.0.1` only, on a random free port.
- A new CA certificate is created for every run in a temporary folder (`leakmap-ca-*`). It's trusted only by the command leakmap starts, through environment variables, and never added to your system store. The folder is deleted when the run ends (`runner.py`).
- Request bodies are inspected in memory. Only the category, field path, host, confidence and a masked sample (`AB******4F`) are written to `.leakmap/`. Raw values, bodies, headers and credentials are never stored.
- `--stub` answers every request locally, so nothing reaches the real service.

## Dependencies

Dependencies are locked in `uv.lock` with hashes. CI installs from the lock (`uv sync --locked`) and runs `pip-audit` against it on every push and once a week. Dependabot opens updates for the lock file and for GitHub Actions. Actions are pinned to commit SHAs.

The optional `ner` extra (names and addresses in free text) adds GLiNER, transformers and torch. torch comes from the PyTorch CPU index (`download.pytorch.org/whl/cpu`), pinned by hash in the lock like everything else. pip-audit cannot look up `+cpu` builds, so CI checks the locked torch version against OSV in a separate step. The model is downloaded from Hugging Face at a pinned commit (`urchade/gliner_multi_pii-v1@1fcf13e`); its tokenizer comes from `microsoft/mdeberta-v3-base`, which GLiNER does not let us pin. Text is processed locally; nothing is sent to Hugging Face. The base install does not include any of this.

Known advisories that are accepted, and why:

| Package | Advisories | Why it's accepted |
|---|---|---|
| tornado 6.5.10 | CVE-2026-116577, CVE-2026-115927, CVE-2026-116578 (fixed in 6.6) | All three are in tornado's HTTP server. mitmproxy 12.3.1 (latest) requires `tornado<=6.5.10`, and uses tornado only for `mitmweb` and the console UI. leakmap runs `mitmdump`; a probe in a real run showed no `tornado` module is loaded. This is removed once a mitmproxy release allows tornado 6.6. |
