import json

import pytest

from leakmap.detect import inspect_request, scan_value
from leakmap.validators import gstin, luhn, verhoeff, verhoeff_check_digit

AADHAAR = "20000000000" + verhoeff_check_digit("20000000000")


def cats(value, key="text", floor="medium"):
    rank = {"low": 0, "medium": 1, "high": 2}
    return sorted({c for c, _, conf in scan_value(value, key) if rank[conf] >= rank[floor]})


def test_verhoeff_accepts_valid_and_rejects_one_digit_off():
    assert verhoeff(AADHAAR)
    assert not verhoeff(AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10))
    assert not verhoeff("222222222222")


def test_gstin_and_luhn():
    assert gstin("29ABCPK1234F1Z1")
    assert not gstin("29ABCPK1234F1Z2")
    assert luhn("4111 1111 1111 1111")
    assert not luhn("4111 1111 1111 1112")


@pytest.mark.parametrize("value,key,expected", [
    (f"aadhaar {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}", "content", ["aadhaar"]),
    ("PAN ABCPK1234F please", "content", ["pan"]),
    ("gst 29ABCPK1234F1Z1", "content", ["gstin"]),
    ("pay rahul.k@okaxis", "content", ["upi_id"]),
    ("mail rahul@gmail.com", "content", ["email"]),
    ("call +91 98765 43210", "content", ["phone_in"]),
    ("4111111111111111", "card_number", ["card"]),
    ("8.8.8.8", "client_ip", ["ip_address"]),
    ("Rahul Kumar", "first_name", ["person_name"]),
    ("Rahul", "displayName", ["person_name"]),
    ("my number is 9876543210", "content", ["phone_in"]),
    ("1996-04-12", "dob", ["date_of_birth"]),
])
def test_detects(value, key, expected):
    assert cats(value, key) == expected


def test_aadhaar_is_not_also_reported_as_phone_or_card():
    assert cats(AADHAAR, "value") == ["aadhaar"]


# Precision matters more than recall for a CI gate: these are everyday
# payloads that must produce no findings at the default confidence.
NOT_PERSONAL = [
    ("550e8400-e29b-41d4-a716-446655440000", "id"),
    ("4bf92f3577b34da6a3ce929d0e0e4736", "trace_id"),
    ("1730390400000000000", "start_time_unix_nano"),
    ("1730390400123", "timestamp_ms"),
    ("ORD-9876543210", "order_id"),
    ("inv_98765432101234", "invoice"),
    ("v1.2.3.4", "version"),
    ("get_weather", "name"),
    ("gpt-4.1-mini", "model"),
    ("49900", "amount"),
    ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "digest"),
    ("https://cdn.example.com/assets/app.9876543210.js", "url"),
    ("Returns the current weather for a city.", "description"),
    ("noreply", "from"),
    # Seen in public VCR cassettes (benchmark/real-traffic.md).
    ("test-file-search-store", "displayName"),
    ("<MagicMock name='build_context_for_task()' id='6251497744'>", "content"),
]


@pytest.mark.parametrize("value,key", NOT_PERSONAL)
def test_no_false_positives(value, key):
    assert cats(value, key) == []


def test_tool_call_payload_has_no_findings():
    body = {
        "model": "gpt-4.1-mini",
        "tools": [{"type": "function", "function": {"name": "lookup_order", "description": "Find an order",
                                                    "parameters": {"type": "object", "properties": {"order_id": {"type": "string"}}}}}],
        "messages": [{"role": "user", "content": "Where is order ORD-9876543210?"}],
        "metadata": {"request_id": "req_01J9Z6X8Q2", "session": "550e8400-e29b-41d4-a716-446655440000"},
    }
    ev = inspect_request("POST", "api.openai.com", "/v1/chat/completions", [], "application/json", json.dumps(body).encode())
    assert ev.findings == []


def test_json_inside_json_is_unwrapped_with_full_path():
    inner = json.dumps({"messages": [{"content": "I am rahul@gmail.com"}]})
    body = json.dumps({"batch": [{"body": {"input": inner}}]}).encode()
    ev = inspect_request("POST", "cloud.langfuse.com", "/api/public/ingestion", [], "application/json", body)
    assert [(f.category, f.field) for f in ev.findings] == [("email", "batch[].body.input.messages[].content")]


def test_ndjson_form_and_query():
    nd = b'{"event_id":"x"}\n{"user":{"email":"a@b.co"}}'
    assert inspect_request("POST", "h", "/", [], "application/x-sentry-envelope", nd).inspected == "ndjson"
    form = inspect_request("POST", "h", "/", [], "application/x-www-form-urlencoded", b"phone=9876543210&x=1")
    assert [(f.category, f.field) for f in form.findings] == [("phone_in", "form.phone")]
    q = inspect_request("GET", "h", "/?email=a@b.co", [("email", "a@b.co")], "", b"")
    assert [f.field for f in q.findings] == ["query.email"]


def test_raw_values_are_masked():
    ev = inspect_request("POST", "h", "/", [], "application/json", json.dumps({"pan": "ABCPK1234F"}).encode())
    assert ev.findings[0].masked == "AB******4F"
    assert "ABCPK1234F" not in json.dumps(ev.to_dict())


def test_binary_bodies_are_marked_not_inspected():
    assert inspect_request("POST", "h", "/", [], "application/x-protobuf", b"\x0a\xff\xfe").inspected == "binary"


def _pb(num, payload: bytes) -> bytes:
    """Encode one length-delimited protobuf field (enough to build OTLP attributes)."""
    n, size = len(payload), b""
    while True:
        b = n & 0x7F
        n >>= 7
        size += bytes([b | (0x80 if n else 0)])
        if not n:
            break
    return bytes([(num << 3) | 2]) + size + payload


def test_otlp_protobuf_attributes_are_named_by_key():
    any_value = _pb(1, json.dumps({"args": ["my phone is +91 98765 43210"]}).encode())
    attribute = _pb(1, b"langfuse.observation.input") + _pb(2, any_value)
    span = _pb(1, bytes(16)) + _pb(5, b"answer") + _pb(9, attribute)
    body = _pb(1, _pb(2, _pb(2, span)))  # ExportTraceServiceRequest > ResourceSpans > ScopeSpans > Span
    ev = inspect_request("POST", "cloud.langfuse.com", "/api/public/otel/v1/traces", [], "application/x-protobuf", body)
    assert ev.inspected == "protobuf"
    assert [(f.category, f.field) for f in ev.findings] == [("phone_in", "otlp.langfuse.observation.input.args[]")]


def test_url_credentials_are_not_emails():
    assert cats('sentry_sdk.init(dsn="https://abc123@o450123.ingest.us.sentry.io/4505")') == []


def path_findings(path):
    event = inspect_request("GET", "api.example.com", path, [], "", b"")
    return sorted((f.category, f.field) for f in event.findings)


def test_personal_data_in_url_path_is_found():
    assert path_findings("/v1/users/rahul.k%40example.com/profile") == [("email", "url.path")]
    assert path_findings(f"/kyc/aadhaar/{AADHAAR}") == [("aadhaar", "url.path")]


@pytest.mark.parametrize("path", [
    "/v1/chat/completions",
    "/api/telemetry/https%3A/api.gradio.app/gradio-launched-telemetry",
    "/repos/o/r/commits/3d3c42e5aac5ba805825da76410c181273ba90b1",
    "/orders/550e8400-e29b-41d4-a716-446655440000",
    "/BerriAI/litellm/main/model_prices_and_context_window.json",
])
def test_ordinary_url_paths_have_no_findings(path):
    assert path_findings(path) == []


@pytest.mark.parametrize("name,good,bad", [
    ("iban", "GB82 WEST 1234 5698 7654 32", "GB82 WEST 1234 5698 7654 33"),
    ("aba_routing", "021000021", "123456789"),
    ("ssn", "274-39-9899", "984-64-5548"),
    ("vin", "1M8GDM9AXKP042788", "1M8GDM9AXKP042789"),
    ("btc_address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
    ("btc_address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
    ("ipv6_global", "2a00:1450:4001:82a::200e", "2001:db8::1"),
    ("phone", "+49 351 8765432", "13-10-2022"),
    ("swift_bic", "DEUTDEFF", "QWERTUS4K90"),
])
def test_validators(name, good, bad):
    from leakmap.validators import VALIDATORS
    assert VALIDATORS[name](good) and not VALIDATORS[name](bad)


@pytest.mark.parametrize("value,expected", [
    ("IBAN: GB82 WEST 1234 5698 7654 32", ["iban"]),
    ("SSN 274-39-9899 on file", ["ssn"]),
    ("routing number 021000021", ["bank_routing"]),
    ("account number: 87425693", ["bank_account"]),
    ("the CVV, which is 199", ["cvv"]),
    ("passport no. P2921304", ["passport"]),
    ("DOB: 24/02/1979", ["date_of_birth"]),
    ("medical record number is MRN-475721-12", ["health_id"]),
    ("contact us at +49 351 8765432.", ["phone"]),
    ("the MAC address A0:9B:D0:1F:4E:7A.", ["mac_address"]),
    ("vehicle KL49Q2612 assigned", ["vehicle_reg"]),
    ("DL MH12 2019 0012345", ["driving_licence"]),
    ("Voter ID: MDU6387510", ["voter_id"]),
    ("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", ["crypto_wallet"]),
    ("at 40.7128 N, 74.0060 W", ["coordinates"]),
    ("SWIFT code DEUTDEFF", ["swift_bic"]),
    ("UPI ID sheela.nath@pingpay.", ["upi_id"]),
    ("PAN xxtgk4977p", ["pan"]),
    ("I live at 826 Shoreham Pl.", ["address"]),
    ("District Ahmedabad, Karnataka PIN 380001", ["postal_code"]),
    ("**Password**: River2022!", ["secret"]),
    ("DB_PASS=RXC%BZM[(8Fgt:8i", ["secret"]),
    ("postgres://app:s3cretPw@db.internal:5432/main", ["secret"]),
    ("token hf_" + "a" * 34, ["secret"]),
    ("Name: Rahul Kumar\nCity: Pune", ["person_name"]),
    ("| Full Name | Gender |\n|---|---|\n| Rahul Kumar | male |", ["gender", "person_name"]),
])
def test_detects_more_categories(value, expected):
    assert cats(value, "content") == expected


# Everyday text that must stay silent: label-looking words, schemas, numbers.
@pytest.mark.parametrize("value", [
    "Meeting scheduled on 13-10-2022.",
    "Her PIN code is printed on the letter.",
    "password reset link sent",
    "token: ${API_TOKEN}",
    "set password=self.password here",
    "max_tokens: 4096",
    "Allergies: None",
    "address: Address\nzip_code: str",
    "Name: get_weather",
    "Name: Acme Technologies",
    "embedding [0.0123, -0.0456, 0.0789]",
    '<path d="M24 14.14c2.11 0 4.02.75 5.52 1.98C31.22 9.43 27.81 8 24 8"/>',
    "commit 3d3c42e5aac5ba805825da76410c181273ba90b1",
    "CUSTOMER SERVICE",
    "Transaction reference: DCTGV8FHIG.",
    "**Pass/Fail:** Pass **Notes:** Check performed by QA",
    "| **Code Style** | Pass | HPBN-7371387 consistently used. |",
    "Thanks for updating your account.\n\n[2022-08-15] Ticket closed",
    '{"account_id": "acct_7161343_768"}',
])
def test_ordinary_text_has_no_findings(value):
    assert cats(value, "content") == []


def test_base64_json_is_decoded():
    import base64
    data = base64.b64encode(json.dumps({"event": "signup", "properties": {"$email": "rahul@gmail.com"}}).encode()).decode()
    ev = inspect_request("POST", "api.mixpanel.com", "/track", [], "application/x-www-form-urlencoded",
                         f"data={data}".encode())
    assert [(f.category, f.field) for f in ev.findings] == [("email", "form.data(base64).properties.$email")]


def test_field_value_is_reported_once():
    from leakmap.detect import scan_value
    assert scan_value("186, Park Street, Pune", "billing_address") == [("address", "186, Park Street, Pune", "high")]


@pytest.mark.parametrize("text, secret", [
    ("Access controlled via API key SKbWnAVDLxFUiAydqikNnC37dv8dj3U8ki. Backups daily", "SKbWnAVDLxFUiAydqikNnC37dv8dj3U8ki"),
    ("Confirm your new password, **BHJ24nz^8z&UGkiT6o**. Then save", "BHJ24nz^8z&UGkiT6o"),
    ("'sheila' (API Key: FDA0873aEc91cF8DdE43C2f6Fa9DFac318B7) using", "FDA0873aEc91cF8DdE43C2f6Fa9DFac318B7"),
    ("Your current password is *ys2hKEMo0#CVE now", "*ys2hKEMo0#CVE"),
])
def test_secret_excludes_surrounding_punctuation(text, secret):
    from leakmap.detect import scan_value
    assert [m for c, m, _ in scan_value(text, "content") if c == "secret"] == [secret]
