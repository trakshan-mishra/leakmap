# Independent datasets

Per-category scores on four public PII datasets that I did not write. Script: [`independent.py`](independent.py). Results: [`results/2026-11-01-independent/`](results/2026-11-01-independent/).

## How the numbers were made

1. Rules were written and tuned on development data only: the train splits of Nemotron-PII and Maskara, the synthetic dev split, and the recorded SDK traffic.
2. The rules were frozen. Each test set below was then scored once. Those are the **headline numbers**.
3. The held-out run showed some rule bugs. I fixed them afterwards. Numbers after that fix are in a separate section and marked as tuned on test, because they are.

| Dataset | Pinned revision | Licence | Test documents | What it is |
|---|---|---|---:|---|
| [nvidia/Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) | `b70ffaf` | CC-BY-4.0 | 100,000 | Synthetic English documents (forms, logs, emails, code) with span labels |
| [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) | `7b844d1` | Apache-2.0 | 5,594 | Financial documents in several European languages |
| [Pranshurs/ylemis-india-pii-benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | `dafb239` | CC0-1.0 | 10,000 | Indian PII, including Hindi and Bengali text, with 1,756 negative documents |
| [somukandula/maskara-indian-pii-200k](https://huggingface.co/datasets/somukandula/maskara-indian-pii-200k) | `0146bc5` | MIT | 17,600 | Indian PII; `template_disjoint_eval` (templates not in train) plus 200 hand-curated real-world negatives |

Every file is pinned to a dataset commit and checked against its sha256 before use. The data is not stored in this repo.

Datasets I looked at and did not use: SecretBench (needs a signed data-protection agreement), ai4privacy (custom licence), bigcode PII (gated), CredData (needs its own download script to rebuild the files from GitHub), and the Kaggle Learning Agency Lab PII competition (student essays, competition data terms; not downloaded).

### Scoring

- **Match:** a finding counts as correct if it overlaps a gold span of the same category. This is type-aware span overlap, the primary metric of the Ylemis benchmark.
- **Alias:** a postal code found inside a gold address counts as part of that address, not as a false alarm.
- **Two recall numbers.** Generators write values no real system issues: Aadhaar numbers that fail Verhoeff, card numbers that fail Luhn, SSNs with area 9xx, SWIFT codes with a made-up country. leakmap drops those on purpose. So recall is reported against every label and against labels that pass the category's checksum.
- **Unmapped labels.** Labels that leakmap has no category for are listed, together with how often any finding overlapped them.
- **Negatives.** Negative documents (Ylemis, Maskara) are counted by how many produced any finding at all.
- **Floor.** The default confidence floor is `medium`, the same as the CLI.
- **Uncertainty.** Brackets are Wilson 95% intervals.

## Before and after this rewrite

Same test sets, same scorer. "Before" is commit `ce179ae`.

| Dataset | Before: precision / recall | Categories found, before | Frozen rules: precision / recall | Categories found, frozen |
|---|---|---|---|---|
| nemotron | 95.1% / 14.2% | 5 of 24 | 97.0% / 58.1% | 23 of 24 |
| gretel-finance | 93.2% / 7.5% | 7 of 18 | 80.0% / 24.7% | 18 of 18 |
| ylemis | 100.0% / 45.0% | 7 of 13 | 96.7% / 56.9% | 12 of 13 |
| maskara | 98.4% / 20.2% | 8 of 15 | 94.3% / 53.5% | 15 of 15 |

Overall precision dropped on all three datasets other than Nemotron:

- **Ylemis:** all of the drop is one rule bug (below).
- **Gretel finance:** 1,052 of the 1,229 false alarms overlap no gold span at all.
- **Maskara:** 1,434 of the 1,450 false alarms overlap no gold span at all.

A finding with no label is either real data the dataset left out or a real mistake. In the samples I checked (health, crypto_wallet, postal_code, bank_account) it was mostly the first.

## Headline: frozen rules, held-out test sets

### nemotron — 100,000 docs, floor medium

| Category | Gold | Found | False alarms | Precision % (95% CI) | Recall % (95% CI) | Recall on valid labels % (n) |
|---|---:|---:|---:|---|---|---|
| person_name | 143,639 | 42,438 | 868 | 98.0 (98–98) | 29.5 (29–30) | 29.5 (143,639) |
| email | 53,930 | 53,481 | 117 | 99.8 (100–100) | 99.2 (99–99) | 99.7 (53,655) |
| phone | 30,353 | 24,678 | 1,174 | 95.5 (95–96) | 81.3 (81–82) | 99.9 (24,666) |
| health_id | 21,656 | 19,468 | 40 | 99.8 (100–100) | 89.9 (90–90) | 89.9 (21,656) |
| date_of_birth | 18,079 | 17,863 | 223 | 98.8 (99–99) | 98.8 (99–99) | 98.8 (18,079) |
| address | 16,879 | 11,589 | 154 | 98.7 (98–99) | 68.7 (68–69) | 68.7 (16,879) |
| bank_account | 16,693 | 13,557 | 400 | 97.1 (97–97) | 81.2 (81–82) | 81.2 (16,693) |
| card | 12,867 | 1,514 | 13 | 99.1 (98–100) | 11.8 (11–12) | 99.8 (1,517) |
| secret | 11,652 | 8,989 | 1,775 | 83.5 (83–84) | 77.1 (76–78) | 77.1 (11,652) |
| ip_address | 9,217 | 3,395 | 5 | 99.9 (100–100) | 36.8 (36–38) | 42.6 (7,975) |
| bank_routing | 8,354 | 783 | 4 | 99.5 (99–100) | 9.4 (9–10) | 92.9 (843) |
| coordinates | 7,659 | 6,591 | 72 | 98.9 (99–99) | 86.1 (85–87) | 86.1 (7,659) |
| gender | 7,645 | 2,424 | 257 | 90.4 (89–92) | 31.7 (31–33) | 31.7 (7,645) |
| account_pin | 6,456 | 4,999 | 37 | 99.3 (99–100) | 77.4 (76–78) | 77.4 (6,456) |
| postal_code | 6,279 | 2,039 | 107 | 95.0 (94–96) | 32.5 (31–34) | 32.5 (6,279) |
| ssn | 6,062 | 6,000 | 807 | 88.1 (87–89) | 99.0 (99–99) | 99.4 (6,036) |
| id_document | 5,849 | 0 | 0 | – | 0.0 (0–0) | 0.0 (5,849) |
| swift_bic | 5,559 | 3,555 | 16 | 99.6 (99–100) | 64.0 (63–65) | 87.3 (4,072) |
| health | 5,539 | 1 | 1,053 | 0.1 (0–0) | 0.0 (0–0) | 0.0 (5,539) |
| cvv | 4,843 | 4,068 | 25 | 99.4 (99–100) | 84.0 (83–85) | 84.0 (4,843) |
| vin | 4,561 | 3,663 | 44 | 98.8 (98–99) | 80.3 (79–81) | 100.0 (287) |
| mac_address | 4,250 | 4,245 | 9 | 99.8 (100–100) | 99.9 (100–100) | 99.9 (4,250) |
| vehicle_reg | 4,078 | 3,699 | 43 | 98.9 (98–99) | 90.7 (90–92) | 90.7 (4,078) |
| tax_id | 1,302 | 975 | 15 | 98.5 (98–99) | 74.9 (72–77) | 74.9 (1,302) |
| aadhaar | 0 | 0 | 28 | 0.0 (0–12) | – | – |
| driving_licence | 0 | 0 | 28 | 0.0 (0–12) | – | – |
| iban | 0 | 0 | 7 | 0.0 (0–35) | – | – |
| pan | 0 | 0 | 15 | 0.0 (0–20) | – | – |
| passport | 0 | 0 | 11 | 0.0 (0–26) | – | – |

Labels with no leakmap category: date 73,867, company_name 54,837, url 37,847, occupation 36,888, time 24,506, country 23,475, customer_id 20,502, city 18,347, state 18,318, user_name 15,800, date_time 13,221, biometric_identifier 11,379, employment_status 11,018, education_level 9,378, race_ethnicity 9,248, employee_id 8,878, language 8,651, county 8,465, age 7,167, political_view 6,402, religious_belief 6,257, http_cookie 4,892, sexuality 3,312, device_identifier 2,507, unique_id 1,777

### gretel-finance — 5,594 docs, floor medium

| Category | Gold | Found | False alarms | Precision % (95% CI) | Recall % (95% CI) | Recall on valid labels % (n) |
|---|---:|---:|---:|---|---|---|
| person_name | 10,812 | 950 | 48 | 95.2 (94–96) | 8.8 (8–9) | 8.8 (10,812) |
| address | 4,307 | 1,195 | 290 | 80.5 (78–82) | 27.7 (26–29) | 27.7 (4,307) |
| email | 1,422 | 1,347 | 45 | 96.8 (96–98) | 94.7 (93–96) | 97.5 (1,381) |
| phone | 946 | 402 | 101 | 79.9 (76–83) | 42.5 (39–46) | 93.2 (427) |
| ip_address | 298 | 73 | 0 | 100.0 (95–100) | 24.5 (20–30) | 29.4 (248) |
| date_of_birth | 250 | 146 | 38 | 79.3 (73–85) | 58.4 (52–64) | 58.4 (250) |
| swift_bic | 227 | 80 | 39 | 67.2 (58–75) | 35.2 (29–42) | 35.2 (227) |
| iban | 203 | 156 | 4 | 97.5 (94–99) | 76.8 (71–82) | 95.6 (158) |
| secret | 192 | 83 | 20 | 80.6 (72–87) | 43.2 (36–50) | 43.2 (192) |
| bank_account | 166 | 69 | 263 | 20.8 (17–26) | 41.6 (34–49) | 41.6 (166) |
| cvv | 160 | 65 | 4 | 94.2 (86–98) | 40.6 (33–48) | 40.6 (160) |
| bank_routing | 158 | 3 | 2 | 60.0 (23–88) | 1.9 (1–5) | 100.0 (3) |
| ssn | 153 | 68 | 1 | 98.6 (92–100) | 44.4 (37–52) | 90.5 (74) |
| account_pin | 143 | 69 | 1 | 98.6 (92–100) | 48.3 (40–56) | 48.3 (143) |
| driving_licence | 140 | 55 | 10 | 84.6 (74–91) | 39.3 (32–48) | 39.3 (140) |
| passport | 136 | 58 | 1 | 98.3 (91–100) | 42.6 (35–51) | 42.6 (136) |
| card | 120 | 49 | 8 | 86.0 (75–93) | 40.8 (32–50) | 100.0 (49) |
| coordinates | 97 | 63 | 47 | 57.3 (48–66) | 64.9 (55–74) | 64.9 (97) |
| aadhaar | 0 | 0 | 11 | 0.0 (0–26) | – | – |
| crypto_wallet | 0 | 0 | 83 | 0.0 (0–4) | – | – |
| gender | 0 | 0 | 7 | 0.0 (0–35) | – | – |
| health | 0 | 0 | 8 | 0.0 (0–32) | – | – |
| health_id | 0 | 0 | 4 | 0.0 (0–49) | – | – |
| postal_code | 0 | 0 | 149 | 0.0 (0–2) | – | – |
| tax_id | 0 | 0 | 26 | 0.0 (0–13) | – | – |
| vehicle_reg | 0 | 0 | 7 | 0.0 (0–35) | – | – |
| vin | 0 | 0 | 12 | 0.0 (0–24) | – | – |

Labels with no leakmap category: date 8,469, company 6,342, time 1,746, customer_id 195, employee_id 175, date_time 89, user_name 71

### ylemis — 10,000 docs, floor medium

| Category | Gold | Found | False alarms | Precision % (95% CI) | Recall % (95% CI) | Recall on valid labels % (n) |
|---|---:|---:|---:|---|---|---|
| person_name | 8,244 | 0 | 0 | – | 0.0 (0–0) | 0.0 (8,244) |
| phone | 3,650 | 3,650 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (3,650) |
| address | 3,649 | 1,553 | 0 | 100.0 (100–100) | 42.6 (41–44) | 42.6 (3,649) |
| pan | 2,567 | 2,567 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (2,567) |
| aadhaar | 1,757 | 1,757 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (1,757) |
| upi_id | 1,081 | 1,081 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (1,081) |
| email | 1,080 | 1,080 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (1,080) |
| ifsc | 946 | 946 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (946) |
| health_id | 676 | 270 | 0 | 100.0 (99–100) | 39.9 (36–44) | 39.9 (676) |
| voter_id | 541 | 270 | 0 | 100.0 (99–100) | 49.9 (46–54) | 49.9 (541) |
| vehicle_reg | 540 | 540 | 0 | 100.0 (99–100) | 100.0 (99–100) | 100.0 (540) |
| gstin | 405 | 405 | 0 | 100.0 (99–100) | 100.0 (99–100) | 100.0 (405) |
| passport | 405 | 405 | 0 | 100.0 (99–100) | 100.0 (99–100) | 100.0 (405) |
| bank_account | 0 | 0 | 500 | 0.0 (0–1) | – | – |

Negative documents with any finding: 0 of 1,756   {'benign': '0/810', 'hard_negative': '0/946'}

Labels with no leakmap category: account_id 2,433, location 2,433, organization 1,623

### maskara — 17,600 docs, floor medium

| Category | Gold | Found | False alarms | Precision % (95% CI) | Recall % (95% CI) | Recall on valid labels % (n) |
|---|---:|---:|---:|---|---|---|
| person_name | 10,985 | 2,300 | 0 | 100.0 (100–100) | 20.9 (20–22) | 20.9 (10,985) |
| phone | 8,279 | 4,587 | 64 | 98.6 (98–99) | 55.4 (54–56) | 97.3 (3,503) |
| aadhaar | 5,079 | 381 | 0 | 100.0 (99–100) | 7.5 (7–8) | 86.1 (440) |
| email | 3,704 | 3,664 | 40 | 98.9 (98–99) | 98.9 (98–99) | 100.0 (3,663) |
| address | 2,820 | 1,802 | 202 | 89.9 (88–91) | 63.9 (62–66) | 63.9 (2,820) |
| date_of_birth | 2,690 | 2,436 | 0 | 100.0 (100–100) | 90.6 (89–92) | 90.6 (2,690) |
| secret | 2,234 | 1,896 | 29 | 98.5 (98–99) | 84.9 (83–86) | 84.9 (2,234) |
| driving_licence | 1,613 | 1,553 | 0 | 100.0 (100–100) | 96.3 (95–97) | 96.3 (1,613) |
| vehicle_reg | 1,585 | 1,585 | 0 | 100.0 (100–100) | 100.0 (100–100) | 100.0 (1,585) |
| upi_id | 1,483 | 1,354 | 0 | 100.0 (100–100) | 91.3 (90–93) | 91.3 (1,483) |
| ip_address | 1,258 | 900 | 0 | 100.0 (100–100) | 71.5 (69–74) | 75.1 (1,198) |
| pan | 1,213 | 358 | 0 | 100.0 (99–100) | 29.5 (27–32) | 76.3 (469) |
| passport | 891 | 855 | 0 | 100.0 (100–100) | 96.0 (94–97) | 96.0 (891) |
| card | 698 | 20 | 0 | 100.0 (84–100) | 2.9 (2–4) | 100.0 (20) |
| ssn | 373 | 324 | 0 | 100.0 (99–100) | 86.9 (83–90) | 100.0 (324) |
| health | 0 | 0 | 1,100 | 0.0 (0–0) | – | – |
| postal_code | 0 | 0 | 15 | 0.0 (0–20) | – | – |

Negative documents with any finding: 0 of 200   {'real_world_curated': '0/200'}

Labels with no leakmap category: USERNAME 1,244

## Where the errors come from

### Labels that no real system would issue

The "recall on valid labels" column explains most of the low recall numbers:

- **Nemotron cards:** 1,517 of 12,867 gold card numbers pass Luhn. On those, recall is 99.8%.
- **Maskara Aadhaar:** 440 of 5,079 pass Verhoeff (86.1% recall on those).
- **Maskara PAN:** 469 of 1,213 have a valid structure (76.3% recall on those).
- **Phones:** 24,666 of 30,353 Nemotron phone labels are valid numbers under the numbering plan (99.9% recall on those). For Maskara it is 3,503 of 8,279 (97.3%).
- **Nemotron bank routing numbers:** 843 of 8,354 pass the ABA checksum (92.9% recall on those).
- **Nemotron SWIFT:** 4,072 of 5,559 have a real country code (87.3% recall on those).

A rule that accepted the invalid ones would also accept every random 12-digit number as an Aadhaar. That is the trade this tool makes.

### False alarms that are still personal data

These are counted as false alarms in the tables, but the matched values are personal data. Either the dataset did not label them, or it labelled them as a different category. I checked samples by hand:

- **Nemotron `secret`:** 1,376 of the 1,775 false alarms overlap a span Nemotron labels `http_cookie`. They are session tokens in `Cookie:` headers, and leakmap treats those as secrets.
- **Nemotron `health`:** 1,053 false alarms. These are mostly diagnoses in fields like `Diagnosis:`, which Nemotron labels only some of the time.
- **Maskara `health`:** 1,100 false alarms, all `Diagnosis: Routine checkup`-style lines that Maskara does not label.
- **Gretel finance:** 83 `crypto_wallet` matches are checksum-valid Bitcoin and Ethereum addresses. The 149 `postal_code` matches are ZIP codes in addresses where Gretel labelled the street but not the code.
- **Nemotron `ssn`:** 807 false alarms. Of those, 134 overlap `national_id`, 115 overlap `tax_id` (both are 9-digit US numbers in the same format), and 421 have no label.
- **Nemotron `person_name`:** 623 of the 868 false alarms have no label at all.
- **Gretel finance `bank_account`:** 208 of the false alarms have no label. They are values right after "Account Number:". Many are placeholders like `123456789`, which Gretel did not label.

Two groups are real mistakes rather than missing labels:

- **Nemotron `postal_code`:** 107 false alarms overlap spans labelled `pin`. These are account PINs read as postal codes.
- **Nemotron `phone`:** 528 false alarms overlap `customer_id`, 193 overlap `account_number` and 155 overlap `health_plan_beneficiary_number`. These are ten-digit IDs that happen to be valid phone numbers.

### Real rule bugs found on the held-out data

- **Bank account timestamps.** `bank_account` read a timestamp as an account number when "account" ended the sentence before it ("…your account.\n\n[2022-08-15]"). This was 15 of the 263 Gretel finance `bank_account` false alarms. Most of the rest are the unlabelled values above.
- **Bank account inside an ID.** `bank_account` matched digits inside `acct_7161343_768`. That is all 500 Ylemis false alarms (an `account_id` label).

Fixes are in the next section.

### Schema disagreements

Maskara's train split has a hard-negative family called `account_number`, with text like "Bank account number 95528817151 for salary credit." and no labels. leakmap flags all 660 of them. I kept that behaviour, because a bank account number next to the words "account number" is personal data under DPDP and GDPR. That family is not in the test files scored here.

## After fixing the held-out bugs (tuned on test)

Changes made after seeing the results above:

- **`bank_account`:** a full stop or line break after "account" ends the context. Digits joined to `_` are not matched.
- **`labelled_secret`:** a bare "pass" counts as a label only with `:` or `=`. Before, "**Pass/Fail:** Pass **Notes:**" and boarding-pass text matched. Markdown `**` and a trailing `.`, `)` or `:` are no longer part of the value.
- **Duplicates:** a value that a field name already identifies is not reported a second time by a pattern of the same category.
- **Gretel-en scorer:** maps its `ipv6` label to `ip_address`. Before, real IPv6 addresses counted as false alarms.

Each change has a test in `tests/test_detect.py`.

| Dataset | Category | Found, frozen → after | False alarms, frozen → after |
|---|---|---|---|
| nemotron | bank_account | 13,557 → 13,553 | 400 → 395 |
| nemotron | email | 53,481 → 53,482 | 117 → 117 |
| nemotron | secret | 8,989 → 9,009 | 1,775 → 1,606 |
| gretel-finance | bank_account | 69 → 67 | 263 → 248 |
| gretel-finance | secret | 83 → 82 | 20 → 18 |
| ylemis | bank_account | 0 → 0 | 500 → 0 |
| maskara | secret | 1,896 → 1,893 | 29 → 0 |

| Dataset | Frozen: precision / recall | After fix: precision / recall |
|---|---|---|
| nemotron | 97.0% / 58.1% | 97.1% / 58.1% |
| gretel-finance | 80.0% / 24.7% | 80.3% / 24.7% |
| ylemis | 96.7% / 56.9% | 100.0% / 56.9% |
| maskara | 94.3% / 53.5% | 94.4% / 53.5% |

No other category changed. Full output: [`after-fix/rules-medium.txt`](results/2026-11-01-independent/after-fix/rules-medium.txt).

## Optional name and address model (`--ner`)

The same 1,000 randomly chosen documents per dataset (fixed seed), scored once with rules only and once with `--ner`. Rules are the after-fix version. Results: [`sample1000-rules.json`](results/2026-11-01-independent/after-fix/sample1000-rules.json), [`sample1000-ner.json`](results/2026-11-01-independent/after-fix/sample1000-ner.json).

| Dataset | Category | Gold | Rules only: precision / recall | With `--ner`: precision / recall |
|---|---|---:|---|---|
| nemotron | person_name | 1,546 | 99.4% / 30.5% | 64.5% / 91.9% |
| nemotron | address | 155 | 99.1% / 72.9% | 49.8% / 98.7% |
| gretel-finance | person_name | 1,831 | 91.9% / 7.4% | 59.1% / 72.5% |
| gretel-finance | address | 703 | 75.0% / 26.0% | 72.5% / 92.0% |
| ylemis | person_name | 833 | – / 0.0% | 100% / 99.5% |
| ylemis | address | 378 | 100% / 43.7% | 80.4% / 99.7% |
| maskara | person_name | 619 | 100% / 21.3% | 93.6% / 98.7% |
| maskara | address | 183 | 89.0% / 66.1% | 73.2% / 79.2% |

The model finds almost every name and address. It also raises many more false alarms, which is why it is off by default.

- **Names with no label:** most of the name false alarms on Nemotron (443 of 782) and Gretel finance (861 of 919) overlap no gold span. From the samples, many are names the datasets did not label, for example in greetings and signatures.
- **Usernames and emails as names:** the model tags them as person names (Nemotron: 114 user_name, 76 email; Maskara: 26 USERNAME).
- **Addresses:** Nemotron labels city and county separately from the street address, so a whole address that overlaps only a `city` span counts as a false alarm (87 of 154). On Ylemis and Maskara, 49 address false alarms are Aadhaar numbers that the model read as part of an address.
- **Negatives:** with the model on, 25 of 87 Ylemis hard negatives and 5 of the 8 sampled Maskara real-world negatives produced a finding. Rules alone produced none.

Use `--ner` to find out whether names leave at all, for example in an audit run. Leave it off for the CI gate.

Scores for every other category are identical with and without the model.

## Regression sets

These sets were used during development, so they are not independent. They are here to show nothing broke.

**Gretel PII English test split** (5,000 documents; email, card, IP, secrets; default floor):

| Run | Card | Email | IP | Secret | All |
|---|---|---|---|---|---|
| 2026-10-31 rules | 99.7 / 92.7 | 98.5 / 99.8 | 99.8 / 46.1 (IPv4 only) | 78.3 / 15.1 | 98.8 / 75.1 |
| Frozen rules | 99.7 / 91.5 | 98.5 / 99.8 | 98.3 / 46.1 (IPv4 only) | 66.7 / 53.8 | 97.1 / 76.8 |
| After fix (IPv6 scored) | 99.7 / 91.5 | 98.5 / 99.8 | 99.8 / 43.5 | 86.7 / 60.5 | 98.5 / 75.4 |

Values are precision / recall in %. At floor `low`, IP recall after the fix is 97.2% and the total is 98.3% / 95.6%.

- **Cards: 5 fewer found.** Three are card-valid numbers written after "Account Number"; they are now reported as bank accounts. Two follow "Customer:" and `<DebtorAccount>`, words that were added to the list of labels that rule out a card.
- **Secrets.** Recall rose from 15.1% to 60.5% (labelled values, Bearer tokens, more key prefixes). There are 11 false alarms left:
  - 2 are the right password with one extra character at the edge (a quote, a leading `_`). This scorer needs an exact match.
  - 9 are secrets Gretel did not label, or labelled as something else: two private key headers, two JWTs, `admin123` after "Admin Password:", a reset token, a `refresh_token` value labelled as a user name, and two passwords that look like other IDs.

**Synthetic API traffic, test split** (1,500 samples): 98.9% precision, 99.3% recall after the fix. All 17 false alarms are `cvv 123` next to a card number. The set was written before the CVV detector existed, so it does not label them. During the frozen run there were also 34 duplicate address reports (a field name and a street pattern both reporting the same value); the duplicate fix removed them.

**Recorded SDK traffic** (pydantic-ai, crewAI, langchain and llm-anthropic cassettes; 5,109 requests): the matches are the ones checked by hand in [real-traffic.md](real-traffic.md), plus new ones from the new categories:

- an OAuth `client_secret` and `refresh_token` in a crewAI cassette, masked in the results and not tested;
- "Name: John Doe";
- two street addresses;
- latitude/longitude pairs;
- a test password field.

The four low-confidence IPs are package version strings, as before. They are hidden at the default floor. The fix removed one duplicate address report.

## Known gaps

- **Names in free text (rules only).** Without `--ner`, leakmap finds a name only after a label like `Name:` or in a field like `first_name`. Recall for names is 9–30%.
- **Voter IDs labelled in Hindi or Bengali** ("वोटर आईडी") are missed. Ylemis recall is 49.9%.
- **Hospital record numbers** written as `chart MRN-…` without "health" or "patient" nearby are missed.
- **Aadhaar written as `(3194) 7221 8772`**, a Maskara format, is not matched.
- **Passports and driving licences with no label** next to them are not reported. The shape alone matches too many order numbers.
- **`id_document`** (Nemotron's generic national ID and licence-certificate labels) has no rule, so recall is 0.

## Reproduce

```bash
uv run --with pyarrow==21.0.0 python benchmark/independent.py --download
uv run --with pyarrow==21.0.0 python benchmark/independent.py --json out.json
uv run --with pyarrow==21.0.0 python benchmark/independent.py --sample 1000 --ner   # needs leakmap[ner]
```

Nemotron-PII is © NVIDIA, used under CC-BY-4.0.
