"""The evil-agent scenario of D27 (the "day 3b" of docs/44): ``tarea-openclaw-escapes``.

`backtide tarea` gives a message to OpenClaw, an agent that runs all the time and reads Telegram
and the web, and prints what it answers in the owner's terminal. A compromised agent (or its
model) answers with escape sequences that would take the owner's clipboard (OSC 52) and clear
the screen, in the answer itself and in the error message of a failed model call. The lab is
tests/integration/test_local_profiles.py's: `backtide vigilar` with the real OpenClaw and the
fake Ollama (tests/integration/proxy_fixtures/fake_ollama.py, ``T20-ESC-<marker>`` and
``T20-ERRESC-<marker>``): nothing real, no real key (invariant 8). The owner's side is the real
CLI (tests/integration/cli_main.py).

Green when: neither stdout nor stderr of `backtide tarea` carries an ESC or a BEL, and the
answer's sequences are there escaped (visible, harmless). For the model's error, OpenClaw
2026.9.8 prints a message of its own instead of the provider's (measured: "LLM request failed:
provider rejected the request schema or tool payload. | 400"), so its sequences never get that
far: either they are shown escaped or the marker is not there at all, and nothing is a control
byte (backtide's own escaping of an ``error.message`` is in tests/test_cli_shell.py). The black
box has the task's
``system/agent_shell`` (with what was asked) before the turn's first ``llm/request``; and the
Gateway's token is in no event since the service started.
"""

import base64
import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from attack_kit import Attack, scenario

from tests.integration.service_kit import run_cli
from tests.integration.test_local_profiles import TURN_TIMEOUT, Lab, make_lab


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    yield from make_lab(btrfs_volume, tmp_path_factory, kind="openai")


def escaped(marker: str) -> str:
    """The fake model's sequences as backtide prints them: every control character written out
    (backtide.shell_cli.printable)."""
    return f"\\x1b]52;c;{base64.b64encode(marker.encode()).decode()}\\x07\\x1b[2J"


def head(lab: Lab) -> int:
    found = lab.service.box.head()
    return found[0] if found is not None else 0


@scenario("tarea-openclaw-escapes")
def test_tarea_with_openclaw_never_lets_escapes_reach_the_terminal(
    attack: Attack, lab: Lab
) -> None:
    marker = uuid.uuid4().hex[:16]
    since = head(lab)
    answered = run_cli(lab.service, "tarea", f"T20-ESC-{marker} say it", timeout=TURN_TIMEOUT)
    failed = run_cli(lab.service, "tarea", f"T20-ERRESC-{marker} say it", timeout=TURN_TIMEOUT)
    raw = {
        "answer": answered.stdout + answered.stderr,
        "error": failed.stdout + failed.stderr,
    }
    clean = all("\x1b" not in text and "\x07" not in text for text in raw.values())
    shown = {name: escaped(marker) in text for name, text in raw.items()}
    b64 = base64.b64encode(marker.encode()).decode()
    dropped = b64 not in raw["error"]  # OpenClaw printed its own message instead
    attack.check(
        "stopped",
        clean and shown["answer"] and (shown["error"] or dropped) and answered.returncode == 0,
        f"answer exit {answered.returncode}, model error exit {failed.returncode}; ESC or BEL "
        f"in the output: {not clean}; the sequences shown escaped: {shown}; the error's dropped "
        f"by OpenClaw: {dropped}; tails: {json.dumps({k: v[-400:] for k, v in raw.items()})}",
    )

    events = [e for e in lab.service.events() if e.seq > since]
    tasks = [e for e in events if e.action == "agent_shell" and e.target == "task"]
    calls = [e for e in events if e.source.value == "llm" and e.action == "request"]
    first = tasks[0] if tasks else None
    in_order = (
        len(tasks) == 2
        and bool(calls)
        and first is not None
        and first.seq < min(c.seq for c in calls)
        and all(t.details.get("prompt", "").startswith("T20-") for t in tasks)
    )
    token = lab.service.config.gateway_token
    assert token is not None, "the lab has a Gateway token"
    every = json.dumps(
        [[e.target, e.details] for e in lab.service.events()], ensure_ascii=False, default=str
    )
    attack.check(
        "recorded",
        in_order and token.reveal() not in every,
        f"{len(tasks)} system/agent_shell task(s), the first at seq "
        f"{first.seq if first else None}, before the first of {len(calls)} llm/request "
        f"(seq {min((c.seq for c in calls), default=None)}): {in_order}; what was asked is "
        f"in them: {[t.details.get('prompt') for t in tasks]}; the Gateway's token in any of "
        f"the {len(lab.service.events())} events since the start: {token.reveal() in every}",
    )
