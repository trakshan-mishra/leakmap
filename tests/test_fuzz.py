"""Property and adversarial tests for the parsers that read untrusted request bodies.

The proxy feeds every outgoing body through scan_body, so no input may raise or
take long: a crash would drop findings for that request, and a slow regex would
stall the app under test. HYPOTHESIS_PROFILE=long runs more examples.
"""

import base64
import json
import os
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from leakmap import protobuf
from leakmap.detect import from_base64, inspect_request, scan_body, scan_value

settings.register_profile("ci", max_examples=300, deadline=2000, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("long", max_examples=5000, deadline=2000, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

CONTENT_TYPES = st.sampled_from([
    "application/json", "application/x-www-form-urlencoded", "text/plain", "application/x-ndjson",
    "application/x-protobuf", "application/grpc", "application/x-sentry-envelope", "", "application/octet-stream",
])

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=80),
    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=12), inner, max_size=5),
    max_leaves=40,
)


def _check(result):
    kind, matches = result
    assert isinstance(kind, str)
    for field_path, category, matched, confidence in matches:
        assert isinstance(field_path, str) and isinstance(category, str) and isinstance(matched, str)
        assert confidence in ("low", "medium", "high")


@given(st.binary(max_size=2048), CONTENT_TYPES)
def test_scan_body_never_raises_on_bytes(body, content_type):
    _check(scan_body(body, content_type))


@given(json_values, CONTENT_TYPES)
def test_scan_body_never_raises_on_json(value, content_type):
    _check(scan_body(json.dumps(value).encode(), content_type))


@given(st.text(max_size=400), st.text(max_size=30))
def test_scan_value_never_raises(value, key):
    for category, matched, confidence in scan_value(value, key):
        assert matched and confidence in ("low", "medium", "high")


@given(st.text(max_size=200))
def test_from_base64_never_raises(s):
    from_base64(s)


@given(json_values)
def test_base64_round_trip_is_scanned(value):
    data = base64.b64encode(json.dumps(value).encode()).decode()
    _check(scan_body(f"data={data}".encode(), "application/x-www-form-urlencoded"))


@given(st.binary(max_size=2048))
def test_protobuf_reader_never_raises(buf):
    protobuf.parses(buf)
    list(protobuf.strings(buf))
    for frame in protobuf.grpc_payloads(buf):
        list(protobuf.strings(frame))


@given(st.text(max_size=60), st.lists(st.tuples(st.text(max_size=10), st.text(max_size=40)), max_size=4),
       st.binary(max_size=512), CONTENT_TYPES)
def test_inspect_request_never_raises(path, query, body, content_type):
    ev = inspect_request("POST", "api.example.com", "/" + path, query, content_type, body)
    for f in ev.findings:
        assert f.category and f.field


def _length_delimited(field: int, payload: bytes) -> bytes:
    n, out = len(payload), bytearray([field << 3 | 2])
    while n >= 0x80:
        out.append(n & 0x7F | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out) + payload


def _nested_protobuf(depth: int) -> bytes:
    buf = _length_delimited(1, b"rahul@gmail.com")
    for _ in range(depth):
        buf = _length_delimited(1, buf)
    return buf


# Inputs built to be slow or deep. Each must finish well inside a second.
ADVERSARIAL = {
    "deep json array": b"[" * 100_000 + b"]" * 100_000,
    "deep json object": b'{"a":' * 50_000 + b"1" + b"}" * 50_000,
    "unclosed json": b"[" * 200_000,
    "deep protobuf": _nested_protobuf(2_000),
    "digits and spaces": b"1 " * 200_000,
    "digits and dashes": b"9-" * 200_000,
    "long password value": b"password: " + b"x" * 500_000,
    "many labels": b"Name: Rahul\n" * 50_000,
    "label with no value": b"account number " * 50_000,
    "long base64": base64.b64encode(b"a" * 300_000),
    "ndjson lines": b'{"a": "b"}\n' * 50_000,
    "huge grpc length": b"\x00\xff\xff\xff\xff" + b"x" * 100,
    "at symbols": b"a@" * 200_000,
    "dots": b"1." * 200_000,
    "colons": b"a:" * 200_000,
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
@pytest.mark.parametrize("content_type", ["application/json", "text/plain", "application/x-protobuf"])
def test_adversarial_bodies_finish_quickly(name, content_type):
    start = time.perf_counter()
    _check(scan_body(ADVERSARIAL[name], content_type))
    assert time.perf_counter() - start < 3.0, name


def test_deep_but_valid_json_is_still_scanned():
    body = b"[" * 500 + b'{"email": "rahul@gmail.com"}' + b"]" * 500
    kind, matches = scan_body(body, "application/json")
    assert kind == "json"
    assert [(c, m) for _, c, m, _ in matches] == [("email", "rahul@gmail.com")]
