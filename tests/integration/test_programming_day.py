"""T17b-1 in the VM: a scripted day of programming with Claude Code, its notices counted
(docs/34, section 8, "Fatiga esperada").

The lab of T17a-4 (tests/integration/test_claude_code.py): the real `backtide vigilar` with
``[agent] profile = "claude-code"``, the fake internet and the bot on a fake Bot API. The fake
internet's github.com serves two repositories baked here with the VM's git (``t17/app``, a small
project, and ``t17/bigrefs``, one with 1400 tags), and its npm and PyPI registries make up every
package (proxy_fixtures/fake_internet.py). Claude Code does the day through its own Bash tool,
one `backtide tarea` per step, as a person would ask it:

    clone → npm install (≈300 reads) → pip install and uv pip install → the tests (nothing goes
    out) → git pull after upstream moved → push a new branch (asked; approved with a batch) →
    push another new branch (the batch) → push the first branch again (asked again)

Each push that is asked fails first: git speaks HTTP/2 to the proxy, and a held HTTP/2 request
hears "pending" (429) at once. The step pushes again 30 s later, as the agent would, and the
person's yes (a preapproval) lets that one out.

Then the known limits, from a plain shell in the jail: a clone with more refs than fit in 64
KiB of ``want`` lines and a git LFS batch request (both held), and an npm install of 800
packages from a cold cache, which meets the request budget (20 a second after a burst of 500).

Every hold and every refusal of the day is counted and printed (``pytest -s``), and the counts
are the test's assertions: section 8 of docs/34 has them. Only fake keys and fake hosts:
nothing reaches GitHub, npm, PyPI, Anthropic or Telegram (invariant 8).
"""

import json
import os
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from backtide.blackbox import Event
from backtide.service.config import ServiceConfig
from backtide.service.control import ask_decide, ask_holds
from backtide.service.proxy_channel import REQUEST_BURST, REQUEST_RATE, THROTTLED_EVERY
from backtide.service.read_budget import DEFAULT_HOST_BYTES, ReadBudget
from tests.integration import sensor_kit
from tests.integration.conftest import _new_service
from tests.integration.internet_kit import (
    REGISTRY_HOSTS,
    FakeInternet,
    bake_git_repo,
    made_up_key,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import Service, run_cli, wait_until
from tests.telegram_fake import OWNER, TOKEN, Call, FakeBotApi, buttons

pytestmark = pytest.mark.integration

AGENT_TOML = 'profile = "claude-code"\n'
PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
# A hold's life and wait, shorter than in production (5 min and 90 s); a preapproval and a
# rejection are remembered 60 s.
TIMINGS = ("--hold-timings", "150,120,60,60")
TASK_TIMEOUT = 400.0
# t17-wide-150: 151 packuments and 151 tarballs, a project of a medium size. Under the request
# budget's burst (500, then 20 a second): BIG_NPM, over it, is one of the limits measured.
WIDE_NPM = 150
BIG_NPM = 800
WIDE_PYPI = 30  # t17-pywide-30: 31 simple pages and 31 wheels, for pip and again for uv
BIG_TAGS = 1400  # more wants than fit in 64 KiB (about 1300 of 50 bytes)
APP = "t17/app"
BIG = "t17/bigrefs"

APP_FILES = {
    "package.json": json.dumps(
        {
            "name": "app",
            "version": "0.1.0",
            "private": True,
            "scripts": {"test": "node test.js"},
            "dependencies": {f"t17-wide-{WIDE_NPM}": "1.0.0"},
        }
    ),
    "test.js": (
        f"const assert = require('assert');\n"
        f"assert.strictEqual(require('t17-wide-{WIDE_NPM}'), 't17-wide-{WIDE_NPM}');\n"
        f"assert.strictEqual(require('t17-leaf-0'), 't17-leaf-0');\n"
        "console.log('npm test ok');\n"
    ),
    "requirements.txt": f"t17-pywide-{WIDE_PYPI}\n",
    "test_app.py": (
        "import unittest\n\n"
        f"import t17_pyleaf_0\nimport t17_pywide_{WIDE_PYPI}\n\n\n"
        "class AppTest(unittest.TestCase):\n"
        "    def test_packages(self):\n"
        f"        self.assertEqual(t17_pywide_{WIDE_PYPI}.NAME, 't17-pywide-{WIDE_PYPI}')\n"
        "        self.assertEqual(t17_pyleaf_0.NAME, 't17-pyleaf-0')\n"
    ),
    "README.md": "app\n",
}
WORK = "/workspace/work"
REPO = f"{WORK}/app"
IDENTITY = "git config user.email t17@example.invalid && git config user.name t17"


def done(step: str) -> str:
    return f"touch {WORK}/ok-{step}"


RETRY_AFTER_S = 30  # how long the agent waits before it pushes again


def push(branch: str) -> str:
    """A push, and once more a while later if it failed (each attempt says so in the log)."""
    once = f"git push -q origin {branch}"
    return (
        f"{{ {once} && echo push-first=ok; }} || "
        f"{{ echo push-first=failed; sleep {RETRY_AFTER_S}; {once} && echo push-again=ok; }}"
    )


# Each step: what Claude Code is asked to run (its Bash tool), ending in a file that says it
# went through.
STEPS = {
    "clone": f"cd {WORK} && git clone -q https://github.com/{APP}.git && {done('clone')}",
    "npm": f"cd {REPO} && npm install --no-progress --loglevel=error && {done('npm')}",
    "pip": (
        f"cd {REPO} && pip install -q --user --break-system-packages -r requirements.txt && "
        f"{done('pip')}"
    ),
    "uv": (
        f"cd {REPO} && uv venv -q .venv && uv pip install -q --python .venv/bin/python "
        f"-r requirements.txt && {done('uv')}"
    ),
    "tests": (
        f"cd {REPO} && npm test && python3 -m unittest -q && .venv/bin/python -m unittest -q && "
        f"{done('tests')}"
    ),
    "pull": (
        f"cd {REPO} && git pull -q --ff-only && git fetch -q && git ls-remote origin >/dev/null "
        f"&& grep -q upstream README.md && {done('pull')}"
    ),
    # git speaks HTTP/2 to the proxy, and a held HTTP/2 request is never kept waiting (the
    # addon's B1): its push hears "pending" (429) at once and fails; the person's yes becomes a
    # preapproval, and the push again (as the agent would, a while later) goes out with it.
    "push-new": (
        f"cd {REPO} && {IDENTITY} && git checkout -q -b feat-1 && echo uno >> notes.txt && "
        f"git add notes.txt && git commit -qm uno && {push('feat-1')} && {done('push-new')}"
    ),
    "push-batch": (
        f"cd {REPO} && git checkout -q -b feat-2 && echo dos >> notes.txt && "
        f"git commit -qam dos && git push -q origin feat-2 && {done('push-batch')}"
    ),
    "push-update": (
        f"cd {REPO} && git checkout -q feat-1 && echo tres >> notes.txt && "
        f"git commit -qam tres && {push('feat-1')} && {done('push-update')}"
    ),
}


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    bot: FakeBotApi

    @property
    def work(self) -> Path:
        return self.service.store.workspace / "agente" / "work"

    def task(self, step: str) -> Any:
        prompt = f"T17-BASH:[[( {STEPS[step]} ) > {WORK}/log-{step} 2>&1]] paso {step}"
        return run_cli(self.service, "tarea", prompt, timeout=TASK_TIMEOUT)

    def log(self, step: str) -> str:
        """What a step's commands printed (each step writes it in the agent's folder)."""
        path = self.work / f"log-{step}"
        return path.read_text(errors="replace")[-3000:] if path.exists() else "(no log)"

    def head(self) -> int:
        return sensor_kit.head_seq(self.service)

    def events(self, since: int) -> list[Event]:
        return list(self.service.box.events(since_seq=since))

    def notices(self, after: float) -> list[Call]:
        return [
            c
            for c in self.bot.sent()
            if c.at > after and str(c.params.get("text", "")).startswith("⏸")
        ]

    def notice(self, text: str, after: float, timeout: float = 60) -> Call:
        found = self.bot.wait_call(
            "sendMessage",
            lambda c: str(c.params.get("text", "")).startswith("⏸") and text in c.params["text"],
            after=after,
            timeout=timeout,
        )
        time.sleep(0.5)  # the desk binds its buttons once the answer reached it
        return found

    def press(self, call: Call, label: str) -> float:
        before = time.monotonic()
        self.bot.push_callback(dict(buttons(call))[label], call.message_id)
        return before


@pytest.fixture(scope="module")
def lab(btrfs_volume: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    sensor_kit.remove_stale_sensors()
    git = tmp_path_factory.mktemp("t17b1-git")
    bake_git_repo(git, APP, APP_FILES, then={"README.md": "app upstream\n"})
    bake_git_repo(git, BIG, {"README.md": "big\n"}, tags=BIG_TAGS)
    service = _new_service(
        btrfs_volume,
        tmp_path_factory,
        agent_toml=AGENT_TOML,
        proxy_toml=PROVIDER,
        real_keys={"anthropic": made_up_key("anthropic")},
    )
    sensor = f"{sensor_kit.SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
    with service.config_path.open("a") as config:
        config.write(f'[sensor]\nname = "{sensor}"\n')
    service.config = ServiceConfig.from_file(service.config_path)
    telegram = service.config.state_dir / "telegram.toml"
    internet: FakeInternet | None = None
    with FakeBotApi(max_poll=5.0) as bot:
        telegram.write_text(f'token = "{TOKEN}"\nchat_id = {OWNER}\napi_base = "{bot.base}"\n')
        telegram.chmod(0o600)
        try:
            internet = start_fake_internet(service, tmp_path_factory.mktemp("t17b1-net"), git)
            service.main_args = ("--with-sensor", *internet.service_args(), *TIMINGS)
            service.start()
            service.wait_ready()
            sensor_kit.sensor_started(service)
            wait_until(lambda: bot.polls() >= 1, 60, "the bot to poll", context=service.diagnosis)
            yield Lab(service, internet, bot)
        finally:
            try:
                stop_with_internet(service, internet)
            finally:
                sensor_kit.remove_sensor(sensor)


# --- counting ----------------------------------------------------------------------------------


def where(event: Event) -> str:
    details = event.details
    return f"{details.get('method', '')} {details.get('host', '')}{details.get('path', '')}"


def tally(events: list[Event]) -> dict[str, Any]:
    """What the gate did with a step's requests: passes by host and rule, holds and refusals
    with their reason, and the model calls."""
    passed: Counter[str] = Counter()
    held, blocked = [], []
    llm = throttled = errors = 0
    for e in events:
        if e.source == "net" and e.action == "request":
            gate = e.details.get("gate") or {}
            passed[f"{e.details.get('host')} {gate.get('decision', '?')}"] += 1
        elif e.source == "llm" and e.action == "request":
            llm += 1
        elif e.source == "gate" and e.action == "held":
            reading = e.details.get("reading") or {}
            held.append(
                f"{e.details.get('reason')}/{reading.get('effect', '-')} r{e.risk} {where(e)}"
            )
        elif e.source == "net" and e.action == "blocked":
            blocked.append(f"{e.details.get('reason')} {where(e)}")
        elif e.source == "net" and e.action == "throttled":
            throttled += int(e.details.get("count", 0))
        elif e.source == "net" and e.action == "error":
            errors += 1
    return {"passed": dict(passed), "held": held, "blocked": blocked, "llm": llm,
            "throttled": throttled, "errors": errors}  # fmt: skip


REPORT: dict[str, dict[str, Any]] = {}


def record(step: str, counts: dict[str, Any], notices: int) -> dict[str, Any]:
    REPORT[step] = {**counts, "notices": notices}
    print(f"\nT17B1-STEP {step}: {json.dumps(REPORT[step], sort_keys=True)}", flush=True)
    return REPORT[step]


def run_step(lab: Lab, step: str) -> dict[str, Any]:
    since, after = lab.head(), time.monotonic()
    result = lab.task(step)
    time.sleep(THROTTLED_EVERY + 1)  # the last responses, refusals and net/throttled are in
    counts = record(step, tally(lab.events(since)), len(lab.notices(after)))
    if not (lab.work / f"ok-{step}").exists():
        print(f"T17B1-LOG {step}:\n{lab.log(step)}", flush=True)
    assert result.returncode == 0, (step, result.stdout[-2000:], result.stderr[-2000:])
    assert (lab.work / f"ok-{step}").exists(), (step, counts)
    return counts


def in_background(work: Callable[[], Any]) -> Callable[[], Any]:
    box: list[Any] = []
    thread = threading.Thread(target=lambda: box.append(work()), daemon=True)
    thread.start()

    def result() -> Any:
        thread.join(TASK_TIMEOUT + 60)
        assert box, "the background step did not end"
        return box[0]

    return result


def without_the_profile(lab: Lab, since: int, step: str) -> dict[str, Any]:
    """What the read budget would have said of a step's registry reads with the registries off
    the allowed list (as before T17b-1): it counts the URL and the headers but the credentials,
    256 KiB an hour per host. The headers are those the black box kept, a near enough count."""
    budget, sizes, first_held = ReadBudget(), Counter[str](), None
    reads = [
        e
        for e in lab.events(since)
        if e.source == "net" and e.action == "request" and e.details.get("host") in REGISTRY_HOSTS
    ]
    for n, e in enumerate(reads, start=1):
        headers = e.details.get("headers") or {}
        size = len(str(e.details.get("path", ""))) + sum(
            len(str(k)) + len(str(v)) for k, v in headers.items()
        )
        sizes[str(e.details.get("host"))] += size
        if not budget.take(str(e.details.get("host")), size, 0.0) and first_held is None:
            first_held = n
    found = {
        "reads": len(reads),
        "bytes_per_read": round(sum(sizes.values()) / max(1, len(reads))),
        "first_held": first_held,
        "host_kib": DEFAULT_HOST_BYTES // 1024,
    }
    REPORT[step]["without_profile"] = found
    print(f"T17B1-BUDGET {step} {json.dumps(found)}", flush=True)
    return found


def no_holds_nor_notices(counts: dict[str, Any]) -> None:
    assert counts["held"] == [] and counts["notices"] == 0, counts


# --- the day ---------------------------------------------------------------------------------


def test_1_clone_passes_without_asking(lab: Lab) -> None:
    counts = run_step(lab, "clone")
    no_holds_nor_notices(counts)
    assert counts["passed"].get("github.com translator_read", 0) >= 2, counts  # info/refs, pack
    # Claude Code's own start: its two reads to api.anthropic.com are refused, without a notice.
    assert all("api.anthropic.com" in item for item in counts["blocked"]), counts
    assert counts["llm"] >= 2, counts  # the tool call, and the answer after its result


def test_2_npm_install_is_reads_off_the_budget(lab: Lab) -> None:
    since = lab.head()
    counts = run_step(lab, "npm")
    no_holds_nor_notices(counts)
    assert counts["throttled"] == 0, counts
    reads = [
        e
        for e in lab.events(since)
        if e.source == "net" and e.action == "request" and e.details.get("host") in REGISTRY_HOSTS
    ]
    assert len(reads) >= 2 * (WIDE_NPM + 1), len(reads)
    assert {e.details.get("method") for e in reads} == {"GET"}  # no audit POST
    assert not any(r["method"] == "POST" for r in lab.internet.requests("registry.npmjs.org"))
    without_the_profile(lab, since, "npm")


def test_3_pip_and_uv_install_without_asking(lab: Lab) -> None:
    for step in ("pip", "uv"):
        counts = run_step(lab, step)
        no_holds_nor_notices(counts)
        assert counts["passed"].get("files.pythonhosted.org read", 0) >= WIDE_PYPI + 1, counts


def test_4_the_tests_send_nothing_out(lab: Lab) -> None:
    counts = run_step(lab, "tests")
    no_holds_nor_notices(counts)
    assert not any(not host.startswith("api.anthropic.com") for host in counts["passed"]), counts


def test_5_pull_after_upstream_moved_passes(lab: Lab) -> None:
    lab.internet.advance_git(APP)
    counts = run_step(lab, "pull")
    no_holds_nor_notices(counts)
    assert counts["passed"].get("github.com translator_read", 0) >= 4, counts


def decisions(lab: Lab, since: int) -> list[str]:
    """The gate's verdicts on the pushes of a step, in order."""
    out = []
    for e in lab.events(since):
        if "git-receive-pack" not in where(e) or "info/refs" in where(e):
            continue
        if e.source == "net" and e.action == "request":
            out.append(f"out:{(e.details.get('gate') or {}).get('decision')}")
        elif e.source == "gate" and e.action == "held":
            out.append("held")
    return out


def test_6_pushes_are_asked_and_a_batch_covers_only_new_branches(lab: Lab) -> None:
    # A new branch: held, with its sentence; approved with "pushes that create new branches".
    since, after = lab.head(), time.monotonic()
    first = in_background(lambda: lab.task("push-new"))
    notice = lab.notice("feat-1", after)
    asked = lab.press(notice, "Pushes que crean ramas nuevas, 1 h")
    question = lab.bot.wait_call(
        "sendMessage", lambda c: "¿Crear un lote?" in c.params.get("text", ""), after=asked,
        timeout=30,
    )  # fmt: skip
    time.sleep(0.5)
    lab.press(question, "Sí, crear el lote")
    result = first()
    time.sleep(2)
    counts = record("push-new", tally(lab.events(since)), len(lab.notices(after)))
    log = lab.log("push-new")
    REPORT["push-new"]["attempts"] = decisions(lab, since)
    assert result.returncode == 0 and (lab.work / "ok-push-new").exists(), log
    assert len(counts["held"]) == 1 and counts["notices"] == 1, counts
    assert counts["held"][0].startswith("change/change r2"), counts
    # The first try heard "pending" at once (HTTP/2); the second went out with the yes.
    assert "push-first=failed" in log and "429" in log and "push-again=ok" in log, log
    assert REPORT["push-new"]["attempts"] == ["held", "out:preapproved"], REPORT["push-new"]

    # Another new branch: the batch lets it out, no notice, first time.
    counts = run_step(lab, "push-batch")
    no_holds_nor_notices(counts)
    assert counts["passed"].get("github.com batch", 0) == 1, counts

    # The first branch again: it moves a ref that exists, so it is asked, batch or not.
    since, after = lab.head(), time.monotonic()
    third = in_background(lambda: lab.task("push-update"))
    notice = lab.notice("feat-1", after)
    assert "push forzado" in notice.params["text"], notice.params["text"]
    lab.press(notice, "Aprobar")
    result = third()
    time.sleep(2)
    counts = record("push-update", tally(lab.events(since)), len(lab.notices(after)))
    log = lab.log("push-update")
    REPORT["push-update"]["attempts"] = decisions(lab, since)
    assert result.returncode == 0 and (lab.work / "ok-push-update").exists(), log
    assert len(counts["held"]) == 1 and counts["notices"] == 1, counts
    assert "push-first=failed" in log and "push-again=ok" in log, log
    assert REPORT["push-update"]["attempts"] == ["held", "out:preapproved"], REPORT
    pushed = [r for r in lab.internet.requests("github.com") if r["method"] == "POST"]
    assert sum("git-receive-pack" in r["path"] for r in pushed) == 3


# --- the known limits ------------------------------------------------------------------------


def held_then_rejected(lab: Lab, script: str, what: str) -> dict[str, Any]:
    """Run ``script`` in the jail (a plain shell), wait for its hold, reject it, and count."""
    since, after = lab.head(), time.monotonic()
    ran = in_background(lambda: lab.service.jail.exec(["sh", "-c", script], timeout=200))
    try:
        wait_until(
            lambda: any(e.action == "held" for e in lab.events(since)), 60, f"the hold of {what}"
        )
        lab.notice("", after)
    finally:
        for hold in ask_holds(lab.service.config.control_socket):
            ask_decide(lab.service.config.control_socket, hold["hold_id"], "reject")
        done = ran()
        time.sleep(2)
        counts = record(what, tally(lab.events(since)), len(lab.notices(after)))
        print(f"T17B1-LIMIT {what}: {done.stdout.strip()[-300:]} {done.stderr[-300:]}", flush=True)
    return counts


def test_7_a_clone_of_a_repository_with_many_refs_is_held_as_unknown(lab: Lab) -> None:
    counts = held_then_rejected(
        lab, f"cd {WORK} && git clone -q https://github.com/{BIG}.git; echo exit=$?", "bigrefs"
    )
    assert len(counts["held"]) == 1 and counts["notices"] == 1, counts
    assert counts["held"][0].startswith("unknown/unknown"), counts
    assert "git-upload-pack" in counts["held"][0], counts


def test_8_a_git_lfs_batch_request_is_held(lab: Lab) -> None:
    body = json.dumps(
        {
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{"oid": "a" * 64, "size": 12}],
        }
    )
    script = (
        f"curl -s -o /dev/null --max-time 150 -X POST "
        f"-H 'Accept: application/vnd.git-lfs+json' "
        f"-H 'Content-Type: application/vnd.git-lfs+json' -d '{body}' "
        f"https://github.com/{APP}.git/info/lfs/objects/batch; echo exit=$?"
    )
    counts = held_then_rejected(lab, script, "lfs")
    assert len(counts["held"]) == 1 and counts["notices"] == 1, counts
    assert counts["held"][0].startswith("write/- r2 POST github.com/"), counts


def test_9_a_big_install_meets_the_request_budget_not_a_notice(lab: Lab) -> None:
    """npm with 800 dependencies, from a fresh cache: about 1600 reads as fast as npm
    sends them. Off the read budget, but not off the request budget (docs/21, section 8: a
    burst of 500, then 20 a second): past it the proxy answers 429 (``net/throttled``), never a
    hold. Whether npm, with its own retries, still gets through is measured and printed."""
    since, after = lab.head(), time.monotonic()
    script = (
        f"mkdir -p {WORK}/big && cd {WORK}/big && npm init -y >/dev/null && "
        f"npm install --no-progress --loglevel=error --cache {WORK}/big/.cache "
        f"t17-wide-{BIG_NPM} > {WORK}/log-npm-big 2>&1; echo $?"
    )
    ran = lab.service.jail.exec(["sh", "-c", script], timeout=TASK_TIMEOUT)
    time.sleep(THROTTLED_EVERY + 1)
    counts = record("npm-big", tally(lab.events(since)), len(lab.notices(after)))
    counts["npm_exit"] = ran.stdout.strip()
    counts["budget"] = {"burst": REQUEST_BURST, "per_second": REQUEST_RATE}
    print(f"T17B1-NPM-BIG exit={counts['npm_exit']} log={lab.log('npm-big')[-600:]!r}")
    without_the_profile(lab, since, "npm-big")
    time.sleep(REQUEST_BURST / REQUEST_RATE)  # the request budget is full again
    no_holds_nor_notices(counts)
    assert counts["throttled"] > 0, counts


def test_10_the_day_in_numbers(lab: Lab) -> None:
    """The whole day, as section 8 of docs/34 counts it."""
    day = [s for s in STEPS if s in REPORT]
    assert len(day) == len(STEPS), REPORT.keys()
    notices = sum(REPORT[s]["notices"] for s in day)
    held = sum(len(REPORT[s]["held"]) for s in day)
    summary = {
        "notices": notices,
        "held": held,
        "blocked": sum(len(REPORT[s]["blocked"]) for s in day),
        "model_calls": sum(REPORT[s]["llm"] for s in day),
        "requests_out": sum(sum(REPORT[s]["passed"].values()) for s in day),
    }
    print(f"\nT17B1-DAY {json.dumps(summary, sort_keys=True)}", flush=True)
    assert (notices, held) == (2, 2), summary
