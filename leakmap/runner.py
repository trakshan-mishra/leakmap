"""Run a command with all of its HTTP(S) traffic going through the leakmap proxy."""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import certifi

from . import __version__
from .flows import aggregate
from .model import Event

ADDON = Path(__file__).with_name("addon.py")
CA_NAME = "mitmproxy-ca-cert.pem"
NO_PROXY = "localhost,127.0.0.1,::1"


class ProxyError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(proc: subprocess.Popen, port: int, ca: Path, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            raise ProxyError(f"proxy exited early (code {proc.returncode}):\n{err.strip()}")
        if ca.exists():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return
            except OSError:
                pass
        time.sleep(0.05)
    raise ProxyError("proxy did not start within 20s")


def proxy_env(port: int, ca: Path, bundle: Path) -> dict[str, str]:
    """Environment that routes Python, Node, curl and Go clients through the proxy."""
    url = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env[name] = url
    env["NO_PROXY"] = env["no_proxy"] = NO_PROXY
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE"):
        env[name] = str(bundle)
    env["NODE_EXTRA_CA_CERTS"] = str(ca)
    env["NODE_USE_ENV_PROXY"] = "1"  # Node 24+: make fetch() honour HTTPS_PROXY
    env["LEAKMAP_ACTIVE"] = "1"
    return env


def run(
    command: list[str],
    out_dir: Path,
    stub: bool = False,
    ner: bool = False,
    min_confidence: str = "medium",
    ignore_hosts: tuple[str, ...] = (),
) -> tuple[int, dict]:
    """Run command under the proxy. Returns (command exit code, run summary)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / "events.jsonl"
    events_path.write_text("")
    confdir = Path(tempfile.mkdtemp(prefix="leakmap-ca-"))
    port = _free_port()
    args = [
        sys.executable, "-c",
        "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())",
        "--quiet",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", f"confdir={confdir}",
        "--scripts", str(ADDON),
        "--set", f"leakmap_out={events_path}",
        "--set", f"leakmap_stub={'true' if stub else 'false'}",
        "--set", f"leakmap_ner={'true' if ner else 'false'}",
    ]
    if stub:
        args += ["--set", "connection_strategy=lazy"]
    proxy = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    started = time.monotonic()
    try:
        ca = confdir / CA_NAME
        _wait_ready(proxy, port, ca)
        bundle = confdir / "bundle.pem"
        bundle.write_text(Path(certifi.where()).read_text() + "\n" + ca.read_text())
        try:
            code = subprocess.call(command, env=proxy_env(port, ca, bundle))
        except FileNotFoundError:
            raise ProxyError(f"command not found: {command[0]}")
    finally:
        if proxy.poll() is None:
            proxy.send_signal(signal.SIGINT)
            try:
                proxy.wait(5)
            except subprocess.TimeoutExpired:
                proxy.kill()
        shutil.rmtree(confdir, ignore_errors=True)  # the CA key never outlives the run

    events = [Event.from_dict(json.loads(line)) for line in events_path.read_text().splitlines() if line]
    summary = {
        "leakmap": __version__,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": command,
        "stub": stub,
        "exit_code": code,
        "seconds": round(time.monotonic() - started, 2),
        **aggregate(events, min_confidence=min_confidence, ignore_hosts=ignore_hosts),
    }
    (out_dir / "run.json").write_text(json.dumps(summary, indent=2) + "\n")
    return code, summary
