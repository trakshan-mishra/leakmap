"""Official vendor SDKs through the proxy in stub mode, with fake values.

Each case is skipped unless its SDK is installed:
    pip install openai anthropic langfuse sentry-sdk posthog mixpanel
"""

import importlib.util
import sys
import textwrap

import pytest

from leakmap.runner import run

PROMPT = "I'm Rahul, Aadhaar 2000 0000 0009, phone +91 98765 43210, email rahul.k@example.com"

CASES = {
    "openai": ("openai", ["aadhaar", "email", "phone_in"], f"""
        from openai import OpenAI
        OpenAI(api_key="sk-fake", max_retries=0).chat.completions.create(
            model="gpt-4.1-mini", messages=[{{"role": "user", "content": {PROMPT!r}}}])
    """),
    "anthropic": ("anthropic", ["aadhaar", "email", "phone_in"], f"""
        from anthropic import Anthropic
        Anthropic(api_key="sk-ant-fake", max_retries=0).messages.create(
            model="claude-haiku-4-5", max_tokens=16, messages=[{{"role": "user", "content": {PROMPT!r}}}])
    """),
    "langfuse": ("langfuse", ["aadhaar", "email", "phone_in"], f"""
        import os
        os.environ.update(LANGFUSE_PUBLIC_KEY="pk-lf-fake", LANGFUSE_SECRET_KEY="sk-lf-fake", LANGFUSE_HOST="https://cloud.langfuse.com")
        from langfuse import observe, get_client
        @observe()
        def answer(question):
            return "ok"
        answer({PROMPT!r})
        get_client().flush()
    """),
    "sentry": ("sentry_sdk", ["ip_address", "pan"], """
        import sentry_sdk
        sentry_sdk.init(dsn="https://abc123@o450123.ingest.us.sentry.io/4505", send_default_pii=True)
        sentry_sdk.set_user({"ip_address": "49.36.12.7"})
        try:
            raise ValueError("KYC lookup failed for PAN " + "ABCPK1234F")
        except ValueError as e:
            sentry_sdk.capture_exception(e)
        sentry_sdk.flush(5)
    """),
    "posthog": ("posthog", ["phone_in", "upi_id"], """
        from posthog import Posthog
        ph = Posthog("phc_fake", host="https://us.i.posthog.com")
        ph.capture("signup", distinct_id="u_1842", properties={"phone": "+91 98765 43210", "upi_id": "rahul.demo@okaxis"})
        ph.flush(); ph.shutdown()
    """),
    "mixpanel": ("mixpanel", ["pan", "person_name"], """
        from mixpanel import Mixpanel
        try:
            Mixpanel("fake-token").track("u_1842", "refund", {"first_name": "Rahul", "pan": "ABCPK1234F"})
        except Exception:
            pass  # stub mode answers {} and the SDK expects {"status": 1}
    """),
}


@pytest.mark.parametrize("vendor", sorted(CASES))
def test_sdk(vendor, tmp_path):
    module, expected, code = CASES[vendor]
    if importlib.util.find_spec(module) is None:
        pytest.skip(f"{module} not installed")
    script = tmp_path / "app.py"
    script.write_text(textwrap.dedent(code))
    status, summary = run([sys.executable, str(script)], tmp_path / "out", stub=True)
    assert status == 0
    data = {p["id"]: sorted(p["data"]) for p in summary["processors"]}
    assert data == {vendor: expected}
