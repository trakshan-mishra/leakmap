# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Deeply nested JSON no longer crashes body scanning; it is reported as an uninspected body.

### Added
- Property and adversarial tests for the body parsers (Hypothesis), run in CI.
- Type checking with mypy in CI.
- Benchmark of the optional `--ner` model on 1,000 documents per dataset.

## [0.1.0] - 2026-11-01

First release.

### Added
- `leakmap run` records outgoing HTTP(S) requests through a local mitmproxy and reports personal data per vendor and country; `baseline` and `check` fail CI on new flows; `--stub` answers requests locally.
- **Detectors (34 categories).**
  - India: Aadhaar (Verhoeff), PAN, GSTIN, UPI, IFSC, mobile numbers, vehicle registration, driving licence, voter ID, ABHA.
  - Finance: cards (Luhn and issuer ranges), IBAN, US routing numbers, SWIFT/BIC, bank account, CVV, PIN, Bitcoin and Ethereum addresses.
  - Identity, contact and location: US SSN, passport, tax IDs, VIN, date of birth, health IDs, email, worldwide phone numbers, IPv4/IPv6, MAC, coordinates, postal codes.
  - Secrets: 30+ API key formats, JWTs, private keys, connection strings.
  - Names, addresses, gender and health data, found from field names and "Label: value" text.
- Optional GLiNER model for names and addresses in free text (`leakmap[ner]`, `--ner`).
- Body decoding: JSON, JSON inside JSON, NDJSON and Sentry envelopes, form and multipart, query strings, URL paths, base64 values, OpenTelemetry protobuf and gRPC.
- A catalog of 127 vendors with headquarters country.
- HTML, Markdown and JSON reports.
- Benchmarks on four public PII datasets with rules frozen before scoring (`benchmark/independent.md`), plus recorded SDK traffic and live runs on real codebases.
- CI on Python 3.12 and 3.13, a dependency audit from the lock file, SHA-pinned actions, Dependabot, and PyPI trusted publishing.

[Unreleased]: https://github.com/trakshan-mishra/leakmap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/trakshan-mishra/leakmap/releases/tag/v0.1.0
