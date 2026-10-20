"""`make probar` end to end against the fake internet (docs/probar.md, T09b), in the VM.

The real script (scripts/demo/probar.py, ``up --internet-falso``): the real `backtide vigilar`,
the real OpenClaw with Claude Sonnet 5.5 as its model and the proxy, where ``api.anthropic.com``
is T06's fake provider on an internal network. Nothing reaches Anthropic or Telegram and every
key is made up (invariant 8). It checks, in the order the founder goes:

1. the service starts with no Anthropic key, and a message gets the agent's answer
   (`make probar-pedir`), with the placeholder as the key the provider sees;
2. the key saved through the service's Settings path (the control socket, as the web does) is
   the one the provider sees from the next message on, and the agent's fake key never changes;
3. a write of the agent to a host off every list is held by the gate.

It shares the demo's folder (``~/backtide-demo-run``) and names, so it skips when a demo or a
test of the founder's is there, and removes everything it made.
"""

import base64
import contextlib
import io
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, load_key
from backtide.jail import AgentJail
from backtide.service.control import ask_set_secret
from scripts.demo import demo, probar
from tests.integration.internet_kit import REPLY_TEXT, FakeInternet

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
START_TIMEOUT = 1800.0  # the first pull of the OpenClaw image is 1.3 GB
PROVIDER_HOST = "api.anthropic.com"


@pytest.fixture(scope="module")
def running(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """`probar up --internet-falso` in front, as `make probar FALSO=1` runs it; its output."""
    paths = demo.PATHS
    if paths.base.exists() or demo.service_pid(paths) is not None:
        pytest.skip(f"{paths.base} is in use (a demo or a test of the founder's): not touched")
    log = tmp_path_factory.mktemp("probar") / "probar.log"
    with open(log, "wb") as out:
        process = subprocess.Popen(
            [sys.executable, "-m", "scripts.demo.probar", "up", "--internet-falso"],
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT
        while "sistema     agent_start" not in log.read_text(errors="replace"):
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"probar did not start the agent:\n{log.read_text()[-4000:]}")
            time.sleep(1)
        yield log
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(180)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(30)
        demo.teardown(paths)


def ask(message: str) -> str:
    """`make probar-pedir MSG=...`: the same command, in this process."""
    out = io.StringIO()
    encoded = base64.b64encode(message.encode()).decode()
    with contextlib.redirect_stdout(out):
        code = probar.main(["pedir", encoded])
    assert code == 0, out.getvalue()
    return out.getvalue()


def model_calls() -> list[dict]:
    internet = FakeInternet(demo.FAKE_INTERNET, "", "", Path())
    return internet.requests(PROVIDER_HOST, "/v1/messages")


def held_events() -> list:
    state = demo.PATHS.state
    box = BlackBox(
        state / "blackbox.db",
        load_key(state / "blackbox.key"),
        checkpoint_path=state / "blackbox.checkpoint",
        readonly=True,
    )
    try:
        return [e for e in box.events() if (e.source.value, e.action) == ("gate", "held")]
    finally:
        box.close()


def test_without_a_key_it_starts_and_the_agent_answers(running: Path) -> None:
    said = ask("Hola, ¿qué tal?")
    assert REPLY_TEXT in said
    assert "aún no has puesto la clave" in said
    keys = [c["headers"].get("x-api-key", "") for c in model_calls()]
    assert keys and all(k.startswith(probar.PLACEHOLDER_PREFIX) for k in keys)
    assert not (demo.PATHS.state / "keys" / "anthropic.key").exists()  # never written


def test_the_key_saved_in_settings_is_the_one_anthropic_sees(running: Path) -> None:
    fake = (demo.PATHS.state / "keys" / "anthropic.fake").read_text()
    key = "sk-ant-test-made-up-" + secrets.token_urlsafe(24)
    reply = ask_set_secret(demo.PATHS.state / "control.sock", "anthropic", key, via="web")
    assert reply["ok"] and reply["applied"] == "now", reply
    before = len(model_calls())

    assert REPLY_TEXT in ask("Otra vez")

    calls = model_calls()[before:]
    assert calls and all(c["headers"].get("x-api-key") == key for c in calls)
    assert (demo.PATHS.state / "keys" / "anthropic.fake").read_text() == fake
    assert key not in running.read_text()  # not in what the terminal shows either


def test_a_write_to_an_unknown_host_is_held(running: Path) -> None:
    """The agent's own POST (as its user, inside the jail: what its exec tool would run; with
    Sonnet 5.5 OpenClaw's exec tool takes code the fake model does not write)."""
    before = len(held_events())
    jail = AgentJail(replace(probar._config(demo.PATHS).jail_config(), allow_shared_ids=True))
    jail.exec(
        ["curl", "-s", "-m", "20", "-X", "POST", "-d", "hola=1", "https://other.fake.test/post"],
        timeout=60,
    )
    deadline = time.monotonic() + 60
    while len(held_events()) == before and time.monotonic() < deadline:
        time.sleep(1)
    (held, *_) = held_events()[before:]
    assert held.details["host"] == "other.fake.test" and held.details["method"] == "POST"
    assert held.risk >= 2
    internet = FakeInternet(demo.FAKE_INTERNET, "", "", Path())
    assert internet.requests("other.fake.test") == []  # held: nothing reached the server
    deadline = time.monotonic() + 30
    while "PUERTA      held" not in running.read_text() and time.monotonic() < deadline:
        time.sleep(1)  # the live view reads the black box every second
    assert "PUERTA      held" in running.read_text()
