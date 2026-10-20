"""The real OpenClaw's Telegram channel through the gate (T10-5, docs/32 sections 3, 12 and 16).

Not a scenario of the battery: a measurement, with the battery's lab (test_proxy_attacks.py's:
the real `backtide vigilar`, the real OpenClaw in its jail, the proxy and T06's fake internet,
where ``api.telegram.org`` is a fake Bot API, ``proxy_fixtures/fake_internet.py``). Nothing
reaches Telegram and every token is made up (invariant 8).

backtide's own openclaw.json has no channel, so a second OpenClaw Gateway runs INSIDE the agent's
container (the same jail: user, network, proxy, CA, seccomp), with a copy of that config plus
``channels.telegram`` (a made-up bot token of the fake Bot API, ``dmPolicy: allowlist`` with the
owner only) and its own port and state folder. The owner's messages are pushed to the fake Bot
API; the model is the fake one ("T06 PONG FROM THE FAKE MODEL"). A message to another chat is
sent the way the agent's ``message`` tool does it: `openclaw message send --channel telegram`,
which the Gateway itself delivers (its Telegram actions run "gateway"), through the same bot and
its account throttler as the replies to the owner.

What it checks, in two labs (Telegram's "pending" Retry-After of 30 s, and the short one):

1. a reply to the owner's chat passes without a hold;
2. a message to another chat is held, the 429 "pending" makes OpenClaw retry it (its flood
   gate: docs/32 P6), and approving it while a retry waits lets out exactly one copy;
3. whether that 429 stalls the whole bot: how long the owner's reply takes while it is active;
4. the notices of the whole session (what would reach the person's phone): docs/32 section 12.

The figures are printed and written to ``openclaw-telegram.json`` in the test's tmp folder.
"""

import json
import secrets
import string
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from test_proxy_attacks import Lab, start_lab

from backtide.blackbox import Event
from backtide.jail import docker as jail_docker
from backtide.service.control import ask_decide, ask_holds
from tests.integration.internet_kit import stop_with_internet
from tests.integration.service_kit import wait_until

pytestmark = pytest.mark.ataques

OWNER = 424242424
OTHER_CHAT = "556"
BOT_ID = "7100000001"  # proxy_fixtures/fake_internet.py: the fake Bot API answers this bot
GATEWAY_PORT = 18799
# In the agent's /tmp (tmpfs): the second Gateway's config, state and log.
WORK = "/tmp/oc-tg"  # noqa: S108 - a path inside the agent's container
PONG = "T06 PONG FROM THE FAKE MODEL"
LIFE, WAIT = 240, 90  # a hold lives 4 min here (5 in production); Telegram's own wait is 50 s
LONG_RETRY, SHORT_RETRY = 30, 2  # Telegram's "pending" Retry-After, before and after T10-5
# Two Gateways in one container: with 2 GiB the kernel kills the second when it runs the agent.
AGENT_MEMORY = "4g"


def made_up_token() -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return f"{BOT_ID}:" + "".join(secrets.choice(alphabet) for _ in range(35))


# The second Gateway's config: backtide's (read-only, mounted at /config) plus the channel.
WRITE_CONFIG = r"""
const fs = require("fs");
const base = JSON.parse(fs.readFileSync("/config/openclaw.json", "utf8"));
const [work, port, token, owner] = process.argv.slice(1);
base.gateway.port = Number(port);
base.channels = {
  telegram: {
    enabled: true,
    botToken: token,
    dmPolicy: "allowlist",
    allowFrom: [owner],
    groupPolicy: "disabled",
  },
};
fs.mkdirSync(work + "/state", { recursive: true });
fs.writeFileSync(work + "/openclaw.json", JSON.stringify(base, null, 2));
console.log("written");
"""


@dataclass
class Gateway:
    lab: Lab
    token: str
    log_lines: list[str] = field(default_factory=list)

    @property
    def container(self) -> str:
        return self.lab.agent.config.name

    def env(self) -> list[str]:
        return [
            "-e", f"OPENCLAW_CONFIG_PATH={WORK}/openclaw.json",
            "-e", f"OPENCLAW_STATE_DIR={WORK}/state",
            "-e", "OPENCLAW_CONFIG_READONLY=1",
        ]  # fmt: skip

    def start(self) -> None:
        jail_docker.run(
            ["exec", self.container, "node", "-e", WRITE_CONFIG, WORK, str(GATEWAY_PORT),
             self.token, str(OWNER)],
            timeout=60,
        )  # fmt: skip
        jail_docker.run(
            ["exec", "-d", *self.env(), self.container, "sh", "-c",
             f"cd /app && exec node openclaw.mjs gateway --port {GATEWAY_PORT} "
             f"> {WORK}/gateway.log 2>&1"],
            timeout=30,
        )  # fmt: skip

    def log(self) -> str:
        done = jail_docker.run(
            ["exec", self.container, "cat", f"{WORK}/gateway.log"], check=False, timeout=30
        )
        return done.stdout

    def send(self, chat: str, text: str, timeout: float = 400) -> dict[str, Any]:
        """`openclaw message send` inside the jail (what the agent's message tool does)."""
        started = time.monotonic()
        done = jail_docker.run(
            ["exec", *self.env(), self.container, "sh", "-c",
             f"cd /app && node openclaw.mjs message send --channel telegram --target {chat} "
             f"--message '{text}' --json 2>&1"],
            check=False, timeout=timeout,
        )  # fmt: skip
        return {
            "code": done.returncode,
            "seconds": round(time.monotonic() - started, 1),
            "out": done.stdout[-2000:],
        }


class Bot:
    """The fake Bot API's side, through the fake internet's control port."""

    def __init__(self, lab: Lab) -> None:
        self.lab = lab

    def calls(self) -> list[dict[str, Any]]:
        return self.lab.internet.stats()["telegram"]

    def requests(self) -> list[dict[str, Any]]:
        return [r for r in self.lab.internet.requests("api.telegram.org") if r.get("tg_method")]

    def push_owner(self, text: str) -> float:
        update = {
            "message": {
                "message_id": secrets.randbelow(10**6),
                "date": int(time.time()),
                "chat": {"id": OWNER, "type": "private", "first_name": "Owner"},
                "from": {"id": OWNER, "is_bot": False, "first_name": "Owner"},
                "text": text,
            }
        }
        script = (
            "import sys, urllib.request; urllib.request.urlopen(urllib.request.Request("
            "'http://127.0.0.1:9000/tg/push', data=sys.argv[1].encode(), method='POST'), "
            "timeout=10).read()"
        )
        at = time.time()
        jail_docker.run(
            ["exec", self.lab.internet.name, "python3", "-c", script, json.dumps(update)],
            timeout=30,
        )
        return at

    def sent(self, chat: str, after: float = 0.0) -> list[dict[str, Any]]:
        return [
            c
            for c in self.calls()
            if c["method"].lower() == "sendmessage" and c["chat_id"] == chat and c["at"] >= after
        ]

    def reply_after(self, at: float, timeout: float = 240) -> dict[str, Any]:
        found: list[dict[str, Any]] = []

        def look() -> bool:
            found[:] = self.sent(str(OWNER), at)
            return bool(found)

        wait_until(look, timeout, "a reply to the owner", context=self.lab.service.diagnosis)
        return found[0]


def held(lab: Lab, after: int = 0) -> list[Event]:
    return [e for e in lab.service.events("held", "gate") if e.seq > after]


def summary(lab: Lab, since: int = 0) -> dict[str, Any]:
    """What the black box says of the session: holds (notices) and what passed, by method."""
    events = [e for e in lab.service.events() if e.seq > since]
    holds = [e for e in events if (e.source, e.action) == ("gate", "held")]
    passed: dict[str, int] = {}
    for e in events:
        if (e.source, e.action) != ("net", "request"):
            continue
        if str(e.details.get("host", "")).split(":")[0] != "api.telegram.org":
            continue
        method = str(e.details.get("path", "")).rsplit("/", 1)[-1].split("?")[0]
        decision = (e.details.get("gate") or {}).get("decision", "?")
        key = f"{method}:{decision}"
        passed[key] = passed.get(key, 0) + 1
    return {
        "holds": [
            {
                "hold_id": e.details.get("hold_id"),
                "risk": e.risk,
                "reason": e.details.get("reason"),
                "phrase": e.details.get("phrase"),
                "path": str(e.details.get("path", "")).rsplit("/", 1)[-1],
            }
            for e in holds
        ],
        "telegram_passed": passed,
    }


@pytest.fixture(scope="module")
def results(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    found: dict[str, Any] = {}
    yield found
    out = tmp_path_factory.mktemp("openclaw-telegram") / "openclaw-telegram.json"
    out.write_text(json.dumps(found, indent=2, ensure_ascii=False))
    print(f"\nT10-5 figures ({out}):\n{json.dumps(found, indent=2, ensure_ascii=False)}")


def run_lab(
    retry_after: int,
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    results: dict[str, Any],
) -> None:
    timings = ("--hold-timings", f"{LIFE},{WAIT},600,600,{retry_after}")
    lab = start_lab(
        btrfs_volume,
        tmp_path_factory,
        hold_timings=timings,
        trusted_chat=str(OWNER),
        agent_memory=AGENT_MEMORY,
    )
    figures: dict[str, Any] = {"retry_after": retry_after}
    results[f"retry_after_{retry_after}"] = figures
    try:
        measure(lab, figures)
    except BaseException:
        figures["diagnosis"] = diagnosis(lab)
        raise
    finally:
        stop_with_internet(lab.service, lab.internet)


def diagnosis(lab: Lab) -> dict[str, Any]:
    """What OpenClaw and the fake internet saw, when something did not happen."""
    found: dict[str, Any] = {}
    container = lab.agent.config.name
    try:
        done = jail_docker.run(
            ["exec", container, "sh", "-c",
             "tail -c 200000 /tmp/openclaw/openclaw-*.log | grep -iE "
             "'telegram|flood|error|warn|model|agent|deliver' | tail -n 80"],
            check=False, timeout=30,
        )  # fmt: skip
        found["openclaw_log"] = done.stdout[-12000:]
        found["gateway_log"] = Gateway(lab, "").log()[-3000:]
    except Exception as error:  # noqa: BLE001 - only for the report
        found["openclaw_log"] = f"unreadable: {error}"
    try:
        found["internet"] = [
            f"{r['at']:.1f} {r['method']} {(r['host'] or '').split(':')[0]} "
            f"{str(r['path'])[-40:]} {r.get('tg_method', '')}"
            for r in lab.internet.requests()
            if r.get("tg_method") != "getUpdates"
        ][-60:]
    except Exception as error:  # noqa: BLE001 - only for the report
        found["internet"] = f"unreadable: {error}"
    found["gate"] = [
        f"{e.seq} {e.source}/{e.action} {e.risk} {str(e.details.get('path', ''))[-30:]} "
        f"{e.details.get('hold_id', '')} {(e.details.get('gate') or {}).get('decision', '')}"
        for e in lab.service.events()
        if e.source in ("gate", "net", "llm")
    ][-60:]
    return found


def measure(lab: Lab, figures: dict[str, Any]) -> None:
    bot = Bot(lab)
    start_seq = lab.head()
    gateway = Gateway(lab, made_up_token())
    started = time.monotonic()
    gateway.start()
    wait_until(
        lambda: any(r["tg_method"].lower() == "getupdates" for r in bot.requests()),
        180,
        "the second Gateway to poll the fake Bot API",
        context=lambda: gateway.log()[-3000:],
    )
    figures["gateway_polling_after_s"] = round(time.monotonic() - started, 1)
    time.sleep(5)
    figures["startup"] = summary(lab, start_seq)

    # 1. Replies to the owner pass (a few, for the baseline and the fatigue count).
    latencies = []
    for n in range(3):
        at = bot.push_owner(f"hola {n}")
        reply = bot.reply_after(at)
        latencies.append(round(reply["at"] - at, 2))
    figures["owner_reply_s"] = latencies
    owner_holds = [e for e in held(lab, start_seq) if str(OWNER) in str(e.details.get("phrase"))]
    assert owner_holds == [], owner_holds

    # 2. A message to another chat: held; OpenClaw retries on "pending"; approve mid-wait.
    seq = lab.head()
    tag = f"t10-5-{secrets.token_hex(4)}"
    outcome: dict[str, Any] = {}
    sending = threading.Thread(target=lambda: outcome.update(gateway.send(OTHER_CHAT, tag)))
    sent_at = time.time()
    sending.start()
    found: list[Event] = []

    def hold_appears() -> bool:
        found[:] = [e for e in held(lab, seq) if OTHER_CHAT in str(e.details.get("phrase"))]
        return bool(found)

    wait_until(hold_appears, 60, "the hold of the other chat", context=lambda: gateway.log())
    hold = found[0]
    hold_id = str(hold.details["hold_id"])
    figures["held"] = {"risk": hold.risk, "phrase": hold.details.get("phrase")}
    socket_path = lab.service.config.control_socket

    def waiting() -> bool:
        return any(h["hold_id"] == hold_id and h.get("waiting") for h in ask_holds(socket_path))

    # The first attempt waits connected (Telegram: 50 s), then hears "pending" (429).
    wait_until(lambda: not waiting(), 120, "the first 'pending'")
    pending_at = time.time()
    # 3. While the flood gate is closed, the owner writes: how long until the reply?
    at = bot.push_owner("¿sigues ahí?")
    reply = bot.reply_after(at, timeout=180)
    figures["owner_reply_during_pending_s"] = round(reply["at"] - at, 2)
    figures["owner_wrote_after_pending_s"] = round(at - pending_at, 2)
    # The retry joins the hold and waits connected again: approve then.
    wait_until(waiting, 120, "OpenClaw's retry to wait on the hold again")
    figures["retry_after_pending_s"] = round(time.time() - pending_at, 1)
    decided = ask_decide(socket_path, hold_id, "approve")
    figures["approve_outcome"] = decided["outcome"]
    sending.join(timeout=420)
    figures["send_cli"] = {
        "code": outcome.get("code"),
        "seconds": outcome.get("seconds"),
        "out": str(outcome.get("out", ""))[-400:],
    }
    time.sleep(10)
    copies = [c for c in bot.sent(OTHER_CHAT, sent_at) if tag in c["text"]]
    figures["copies_delivered"] = len(copies)
    figures["flood_log_lines"] = [
        line for line in gateway.log().splitlines() if "flood" in line.lower()
    ][-6:]
    figures["session"] = summary(lab, start_seq)
    assert decided["outcome"] == "released", decided
    assert len(copies) == 1, copies


def test_openclaw_telegram_through_the_gate_long_retry(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    results: dict[str, Any],
) -> None:
    run_lab(LONG_RETRY, btrfs_volume, tmp_path_factory, results)


def test_openclaw_telegram_through_the_gate_short_retry(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    results: dict[str, Any],
) -> None:
    run_lab(SHORT_RETRY, btrfs_volume, tmp_path_factory, results)
