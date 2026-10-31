"""Real proxy, real HTTPS clients, stub mode (no network)."""

import json
import sys
import textwrap

from leakmap.cli import main
from leakmap.runner import run

EXPECTED_DEMO = {
    "openai": ["aadhaar", "phone_in"],
    "langfuse": ["aadhaar", "email", "phone_in"],
    "sentry": ["email", "ip_address", "pan"],
    "mixpanel": ["person_name", "phone_in", "upi_id"],
    "razorpay": ["email", "phone_in"],
    "host:api.acme-crm.example": ["address", "date_of_birth", "person_name"],
    "google-analytics": [],
}


def flows(summary):
    return {p["id"]: sorted(p["data"]) for p in summary["processors"]}


def test_demo_app_flows(tmp_path):
    code, summary = run([sys.executable, "-m", "leakmap.demo_app"], tmp_path, stub=True)
    assert code == 0
    assert flows(summary) == EXPECTED_DEMO
    # Nothing written to disk contains a raw value.
    for f in tmp_path.iterdir():
        text = f.read_text()
        assert "ABCPK1234F" not in text and "98765 43210" not in text and "rahul.k@example.com" not in text


def test_common_python_clients_are_captured(tmp_path):
    script = tmp_path / "probe.py"
    script.write_text(textwrap.dedent("""
        import httpx, urllib.request
        httpx.post("https://api.anthropic.com/v1/messages", json={"messages": [{"content": "rahul@gmail.com"}]})
        urllib.request.urlopen(urllib.request.Request("https://api.groq.com/x", data=b'{"phone": "9876543210"}'))
    """))
    code, summary = run([sys.executable, str(script)], tmp_path / "out", stub=True)
    assert code == 0
    assert flows(summary) == {"anthropic": ["email"], "groq": ["phone_in"]}


def test_cli_baseline_then_check(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    demo = ["run", "--stub", "--", sys.executable, "-m", "leakmap.demo_app"]
    assert main(demo) == 0
    assert main(["check"]) == 2  # no baseline yet
    assert main(["baseline"]) == 0
    assert main(["check"]) == 0

    lock = json.loads((tmp_path / "leakmap.lock").read_text())
    lock["processors"]["openai"]["data"].remove("aadhaar")
    del lock["processors"]["mixpanel"]
    (tmp_path / "leakmap.lock").write_text(json.dumps(lock))
    capsys.readouterr()
    assert main(["check"]) == 1
    out = capsys.readouterr().out
    assert "OpenAI (US) now receives Aadhaar number" in out
    assert "New recipient of personal data: Mixpanel (US)" in out

    assert main(["run", "--stub", "--check", "--", sys.executable, "-m", "leakmap.demo_app"]) == 1


def test_reports_render(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["run", "--stub", "--", sys.executable, "-m", "leakmap.demo_app"]) == 0
    for fmt in ("terminal", "md", "html", "dpdp", "json"):
        assert main(["report", "--format", fmt, "-o", f"r.{fmt}"]) == 0
    assert "Transfer outside IN" in (tmp_path / "r.dpdp").read_text()
    assert "<html" in (tmp_path / "r.html").read_text()
