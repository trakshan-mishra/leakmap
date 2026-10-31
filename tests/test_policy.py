import copy

from leakmap.policy import DEFAULTS, check, lock_from_run
from leakmap.vendors import resolve


def run_with(**processors):
    """processors: id -> (country, [categories])"""
    return {"events": 1, "processors": [
        {"id": pid, "name": pid.title(), "kind": "x", "country": country, "hosts": [pid], "requests": 1, "uninspected": 0,
         "data": {c: {"label": c, "occurrences": 1, "fields": ["f"], "example": "x", "endpoint": "POST h/"} for c in cats}}
        for pid, (country, cats) in processors.items()
    ]}


BASE = run_with(openai=("US", ["email"]), razorpay=("IN", ["phone_in"]))
LOCK = lock_from_run(BASE)


def levels(issues):
    return sorted((i["level"], i["code"]) for i in issues)


def test_same_flows_pass():
    assert [i for i in check(BASE, LOCK, DEFAULTS) if i["level"] == "fail"] == []


def test_new_category_fails():
    run = run_with(openai=("US", ["email", "aadhaar"]), razorpay=("IN", ["phone_in"]))
    assert levels(check(run, LOCK, DEFAULTS)) == [("fail", "new_data")]


def test_new_recipient_of_personal_data_fails():
    run = copy.deepcopy(BASE)
    run["processors"] += run_with(mixpanel=("US", ["phone_in"]))["processors"]
    assert levels(check(run, LOCK, DEFAULTS)) == [("fail", "new_processor")]


def test_new_third_party_without_personal_data_warns():
    run = copy.deepcopy(BASE)
    run["processors"] += run_with(ga=("US", []))["processors"]
    assert levels(check(run, LOCK, DEFAULTS)) == [("warn", "new_processor")]


def test_deny_rule_fails_even_when_baselined():
    run = run_with(openai=("US", ["aadhaar"]))
    config = {**DEFAULTS, "deny": [{"data": "aadhaar", "country_not": "IN", "reason": "Aadhaar stays in India"}]}
    issues = check(run, lock_from_run(run), config)
    assert levels(issues) == [("fail", "denied")]
    assert "Aadhaar stays in India" in issues[0]["message"]


def test_vendor_resolution():
    assert resolve("o450123.ingest.us.sentry.io").id == "sentry"
    assert resolve("bedrock-runtime.ap-south-1.amazonaws.com").id == "aws-bedrock"
    assert resolve("API.OpenAI.com").id == "openai"
    assert resolve("notopenai.com").kind == "unclassified"
