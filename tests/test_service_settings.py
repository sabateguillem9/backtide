"""T12e: the keys of the Settings page inside the service (backtide/service/settings.py), and how
the proxy gets a new one without a restart (``providers_now``, ``key_reloader``, ``Egress.reload``).

Every key here is made up by the test (``sk-ant-api03-TEST…``): never a real one. What matters
most is what must NOT happen: a key in a message, a log line or a black-box event, a file that is
not 0600, a write that follows a link, a change that is not recorded first."""

import json
import logging
import os
import secrets
import socket
import stat
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox, Source
from backtide.gate import protocol
from backtide.gate.protocol import LineReader, Sender
from backtide.gate.providers import Providers, new_fake_key
from backtide.service.config import ServiceConfig
from backtide.service.egress import Egress, EgressHooks
from backtide.service.proxy_channel import Policy, ProxyChannel
from backtide.service.runner import egress_policy, key_reloader, providers_now
from backtide.service.settings import (
    MIN_SHOWN,
    Applied,
    Outcome,
    Settings,
    SettingsError,
    check_chat_id,
    check_value,
    remove_private,
    tail_of,
    write_private,
)
from backtide.service.telegram_config import load_telegram

KEY = bytes(range(32))
GATEWAY = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
BOT_TOKEN_ID = "123456789"  # noqa: S105 - a made-up bot id


def anthropic_key() -> str:
    return "sk-ant-api03-TEST" + secrets.token_urlsafe(48).replace("=", "")


def openai_key() -> str:
    return "sk-proj-TEST" + secrets.token_urlsafe(40).replace("=", "")


def bot_token() -> str:
    return f"{BOT_TOKEN_ID}:AA" + secrets.token_urlsafe(30)[:33]


def chunks(value: str, size: int = 8) -> set[str]:
    return {value[i : i + size] for i in range(len(value) - size + 1)}


def leaks(value: str, *texts: str) -> list[str]:
    """Which of ``texts`` carry ``value`` or any 8-character piece of it."""
    pieces = chunks(value) | {value}
    return [text[:80] for text in texts if any(piece in text for piece in pieces)]


@pytest.fixture
def state(tmp_path: Path) -> Path:
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    return folder


@pytest.fixture
def box(tmp_path: Path) -> BlackBox:
    return BlackBox(tmp_path / "blackbox.db", KEY, checkpoint_path=tmp_path / "blackbox.ckpt")


class Reloads:
    def __init__(self, answer: Applied = Applied.NOW) -> None:
        self.calls = 0
        self.answer = answer
        self.error: Exception | None = None

    def __call__(self) -> Applied:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.answer


def make(state: Path, box: BlackBox, reloads: Reloads | None = None, **options: Any) -> Settings:
    options.setdefault("in_use", ["anthropic", "openai"])
    return Settings(state, record=box.append, reload_keys=reloads, **options)


def everything_said(box: BlackBox, caplog: pytest.LogCaptureFixture, *more: Any) -> list[str]:
    texts = [json.dumps(more, default=str)]
    texts += [r.getMessage() + (r.exc_text or "") for r in caplog.records]
    for event in box.events():
        texts.append(json.dumps([event.source, event.action, event.target, event.details]))
    return texts


# -- the shapes --------------------------------------------------------------------------------


def test_each_kind_takes_only_its_own_shape() -> None:
    assert check_value("anthropic", anthropic_key())
    assert check_value("openai", openai_key())
    assert check_value("openai", "sk-" + "A1b2" * 12)  # an old-style key
    assert check_value("telegram", bot_token())
    assert not check_value("anthropic", openai_key())
    assert not check_value("openai", anthropic_key()), "an Anthropic key is not an OpenAI one"
    assert not check_value("anthropic", "sk-ant-oat01-" + "x" * 40), "an OAuth token is not a key"
    assert not check_value("anthropic", new_fake_key("anthropic"))
    assert not check_value("anthropic", "sk-ant-api03-" + "x" * 30 + "backtide-fake-")
    for bad in ("", "sk-ant-short", "sk-ant-api03-" + "x" * 300, "sk-ant-api03-" + "x" * 30 + " y",
                "sk-ant-api03-" + "x" * 30 + "\n", "sk-ant-api03-ñ" + "x" * 30):  # fmt: skip
        assert not check_value("anthropic", bad)
    assert not check_value("telegram", "123:short")
    assert not check_value("gemini", anthropic_key())


def test_a_chat_is_a_positive_number() -> None:
    assert check_chat_id("123456789")
    for bad in ("", "0", "-100123", "12a", " 12", "1" * 17):
        assert not check_chat_id(bad)


def test_the_tail_is_four_plain_characters_of_a_long_value() -> None:
    assert tail_of("x" * (MIN_SHOWN - 4) + "AbC9") == "AbC9"
    assert tail_of("x" * (MIN_SHOWN - 1)) is None
    assert tail_of("x" * 20 + 'a"b<') is None


# -- writing ------------------------------------------------------------------------------------


def test_a_key_is_written_0600_in_a_0700_folder_and_recorded_without_it(
    state: Path, box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    reloads = Reloads()
    key = anthropic_key()
    outcome = make(state, box, reloads).set_secret("anthropic", key, requested_by="web (uid 1)")
    assert (outcome.status, outcome.applied) == (Outcome.SAVED, Applied.NOW)
    path = state / "keys" / "anthropic.key"
    assert path.read_text() == key + "\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((state / "keys").stat().st_mode) == 0o700
    assert path.stat().st_uid == os.geteuid()
    assert reloads.calls == 1
    [event] = box.events()
    assert (event.source, event.action, event.target, event.risk) == (
        Source.SETTINGS, "secret_set", "anthropic", 1,
    )  # fmt: skip
    assert event.details == {"kind": "anthropic", "requested_by": "web (uid 1)"}
    assert leaks(key, *everything_said(box, caplog, outcome)) == []
    assert [p.name for p in (state / "keys").iterdir()] == ["anthropic.key"], "no temp left"


def test_a_change_replaces_the_file_atomically_and_keeps_the_fake_key(
    state: Path, box: BlackBox
) -> None:
    folder = state / "keys"
    folder.mkdir(mode=0o700)
    fake = folder / "anthropic.fake"
    fake.write_text(new_fake_key("anthropic") + "\n")
    fake.chmod(0o600)
    before = fake.read_text()
    old = folder / "anthropic.key"
    old.write_text(anthropic_key() + "\n")
    old.chmod(0o644)  # a hand-written file left open to others: the new one is 0600 anyway
    inode = old.stat().st_ino
    new = anthropic_key()
    assert make(state, box).set_secret("anthropic", new, requested_by="web").ok
    assert old.read_text() == new + "\n"
    assert old.stat().st_ino != inode, "a new file renamed over the old one, not rewritten"
    assert stat.S_IMODE(old.stat().st_mode) == 0o600
    assert fake.read_text() == before, "the agent keeps the same fake key"


def test_a_bad_value_changes_nothing_and_is_never_quoted(
    state: Path, box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    reloads = Reloads()
    settings = make(state, box, reloads)
    almost = anthropic_key() + "!"
    for kind, value in (("anthropic", almost), ("openai", almost), ("telegram", almost),
                        ("anthropic", openai_key())):  # fmt: skip
        outcome = settings.set_secret(kind, value, requested_by="web")
        assert outcome.status is Outcome.INVALID
        assert leaks(value, outcome.message) == []
    assert not (state / "keys").exists() and not (state / "telegram.toml").exists()
    assert box.events() == [] and reloads.calls == 0
    assert leaks(almost, *everything_said(box, caplog)) == []


def test_a_key_for_a_provider_nobody_configured_is_saved_and_says_so(
    state: Path, box: BlackBox
) -> None:
    reloads = Reloads()
    outcome = make(state, box, reloads, in_use=["anthropic"]).set_secret(
        "openai", openai_key(), requested_by="web"
    )
    assert (outcome.status, outcome.applied) == (Outcome.SAVED, Applied.UNUSED)
    assert reloads.calls == 0
    assert "ningún proveedor" in outcome.message


def test_a_proxy_that_cannot_take_it_now_is_said(state: Path, box: BlackBox) -> None:
    reloads = Reloads(Applied.WHEN_UP)
    outcome = make(state, box, reloads).set_secret("openai", openai_key(), requested_by="web")
    assert outcome.applied is Applied.WHEN_UP
    reloads.error = RuntimeError("boom")
    outcome = make(state, box, reloads).set_secret("openai", openai_key(), requested_by="web")
    assert (outcome.status, outcome.applied) == (Outcome.SAVED, Applied.RESTART)


def test_nothing_changes_when_the_black_box_cannot_record_it(state: Path) -> None:
    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("disk full")

    reloads = Reloads()
    settings = Settings(state, record=broken, reload_keys=reloads, in_use=["anthropic"])
    outcome = settings.set_secret("anthropic", anthropic_key(), requested_by="web")
    assert outcome.status is Outcome.FAILED
    assert not (state / "keys" / "anthropic.key").exists() and reloads.calls == 0


@pytest.mark.parametrize("trap", ["symlink", "open_folder", "file_in_the_way"])
def test_a_keys_folder_that_is_not_ours_and_closed_is_refused(
    state: Path, box: BlackBox, tmp_path: Path, trap: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    if trap == "symlink":
        (state / "keys").symlink_to(elsewhere)
    elif trap == "open_folder":
        (state / "keys").mkdir(mode=0o700)
        (state / "keys").chmod(0o755)
    else:
        (state / "keys").write_text("not a folder")
    key = anthropic_key()
    outcome = make(state, box).set_secret("anthropic", key, requested_by="web")
    assert outcome.status is Outcome.FAILED
    assert list(elsewhere.iterdir()) == []
    assert [e.action for e in box.events()] == ["secret_set", "secret_failed"]
    assert box.events()[-1].details == {"kind": "anthropic", "requested_by": "web",
                                        "step": "write"}  # fmt: skip
    assert leaks(key, *everything_said(box, caplog, outcome)) == []


def test_write_private_never_follows_a_link_at_the_name(tmp_path: Path) -> None:
    folder = tmp_path / "f"
    folder.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_text("keep me")
    (folder / "a.key").symlink_to(target)
    write_private(folder, "a.key", b"new\n")
    assert target.read_text() == "keep me", "the link itself is replaced, not what it points to"
    assert not (folder / "a.key").is_symlink() and (folder / "a.key").read_text() == "new\n"
    with pytest.raises(SettingsError):
        write_private(target, "x", b"y")  # not a folder
    remove_private(folder, "a.key")
    assert not (folder / "a.key").exists()


# -- removing -----------------------------------------------------------------------------------


def test_a_key_is_removed_recorded_and_the_proxy_told(state: Path, box: BlackBox) -> None:
    reloads = Reloads()
    settings = make(state, box, reloads)
    assert settings.clear_secret("openai", requested_by="web").status is Outcome.NOT_SET
    assert box.events() == []
    settings.set_secret("openai", openai_key(), requested_by="web")
    outcome = settings.clear_secret("openai", requested_by="cli (uid 1)")
    assert (outcome.status, outcome.applied) == (Outcome.CLEARED, Applied.NOW)
    assert not (state / "keys" / "openai.key").exists()
    assert [(e.action, e.details) for e in box.events()] == [
        ("secret_set", {"kind": "openai", "requested_by": "web"}),
        ("secret_cleared", {"kind": "openai", "requested_by": "cli (uid 1)"}),
    ]
    assert reloads.calls == 2


# -- what the page sees -------------------------------------------------------------------------


def test_the_status_says_set_its_tail_and_when_and_nothing_more(state: Path, box: BlackBox) -> None:
    settings = make(state, box, in_use=["anthropic"])
    key = anthropic_key()
    settings.set_secret("anthropic", key, requested_by="web")
    shown = settings.status()
    assert set(shown) == {"anthropic", "openai", "telegram"}
    anthropic = shown["anthropic"]
    assert anthropic["set"] is True and anthropic["tail"] == key[-4:]
    assert anthropic["in_use"] is True and anthropic["problem"] is None
    assert anthropic["waiting"] is False
    assert anthropic["changed"].endswith("Z")
    assert shown["openai"] == {"set": False, "tail": None, "changed": None, "in_use": False,
                               "problem": None, "waiting": False}  # fmt: skip
    assert leaks(key, json.dumps(shown).replace(key[-4:], "")) == []


def test_a_broken_file_is_shown_as_a_problem_not_read(state: Path, box: BlackBox) -> None:
    folder = state / "keys"
    folder.mkdir(mode=0o700)
    key = anthropic_key()
    (folder / "anthropic.key").write_text(key + "\n")
    (folder / "anthropic.key").chmod(0o644)  # open to others: refused like the service does
    entry = make(state, box).status()["anthropic"]
    assert entry["set"] is True and entry["problem"] == "unreadable" and entry["tail"] is None
    assert entry["waiting"] is True  # the agent cannot use it until it is set again


def test_a_provider_in_use_without_its_key_is_shown_waiting(state: Path, box: BlackBox) -> None:
    proxy_says = {"openai": "missing"}
    settings = make(state, box, waiting=lambda: dict(proxy_says))
    shown = settings.status()
    assert shown["openai"]["set"] is False and shown["openai"]["waiting"] is True
    assert shown["anthropic"]["waiting"] is True  # no file either
    settings.set_secret("anthropic", anthropic_key(), requested_by="web")
    assert settings.status()["anthropic"]["waiting"] is False
    # Not used by [proxy]: nothing waits for it.
    assert make(state, box, in_use=["anthropic"]).status()["openai"]["waiting"] is False


def test_a_key_the_proxy_cannot_use_is_a_problem_though_its_file_reads(
    state: Path, box: BlackBox
) -> None:
    """A file that reads well but holds no key the gate can use (two providers with one key, a
    hand-written one too short): the proxy's view wins, and nothing of it is said."""
    key = anthropic_key()
    settings = make(state, box, waiting=lambda: {"anthropic": "unusable"})
    settings.set_secret("anthropic", key, requested_by="web")
    entry = settings.status()["anthropic"]
    assert entry["set"] is True and entry["problem"] == "unreadable" and entry["waiting"] is True


def test_a_broken_waiting_reader_never_breaks_the_page(state: Path, box: BlackBox) -> None:
    def broken() -> dict[str, str]:
        raise RuntimeError("boom")

    shown = make(state, box, waiting=broken).status()
    assert shown["anthropic"]["waiting"] is True  # still from the files: none set


# -- Telegram -----------------------------------------------------------------------------------


def test_telegram_needs_both_the_first_time_and_then_one_at_a_time(
    state: Path, box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    settings = make(state, box)
    token = bot_token()
    first = settings.set_secret("telegram", token, chat_id="", requested_by="web")
    assert first.status is Outcome.INVALID and not (state / "telegram.toml").exists()
    saved = settings.set_secret("telegram", token, chat_id="987654321", requested_by="web")
    assert (saved.status, saved.applied) == (Outcome.SAVED, Applied.RESTART)
    loaded = load_telegram(state)
    assert loaded is not None
    assert (loaded.token.reveal(), loaded.chat_id) == (token, 987654321)
    assert stat.S_IMODE((state / "telegram.toml").stat().st_mode) == 0o600
    # Only the chat: the token stays.
    assert settings.set_secret("telegram", "", chat_id="555666777", requested_by="web").ok
    loaded = load_telegram(state)
    assert loaded is not None and (loaded.token.reveal(), loaded.chat_id) == (token, 555666777)
    # Only the token: the chat stays.
    other = bot_token()
    assert settings.set_secret("telegram", other, chat_id="", requested_by="web").ok
    loaded = load_telegram(state)
    assert loaded is not None and (loaded.token.reveal(), loaded.chat_id) == (other, 555666777)
    shown = settings.status()["telegram"]
    assert shown["tail"] == other[-4:] and shown["chat_tail"] == "6777"
    assert settings.set_secret("telegram", "", chat_id="-100123", requested_by="web").status is (
        Outcome.INVALID
    )
    cleared = settings.clear_secret("telegram", requested_by="web")
    assert (cleared.status, cleared.applied) == (Outcome.CLEARED, Applied.RESTART)
    assert not (state / "telegram.toml").exists()
    assert [e.action for e in box.events()] == ["secret_set"] * 3 + ["secret_cleared"]
    for event in box.events():
        assert event.details == {"kind": "telegram", "requested_by": "web"}
    said = everything_said(box, caplog, first, saved, cleared)
    assert leaks(token, *said) == [] and leaks(other, *said) == []


def test_telegram_keeps_the_tests_api_base(state: Path, box: BlackBox) -> None:
    path = state / "telegram.toml"
    path.write_text(f'token = "{bot_token()}"\nchat_id = 42424242\n'
                    'api_base = "http://127.0.0.1:9999"\n')  # fmt: skip
    path.chmod(0o600)
    assert make(state, box).set_secret("telegram", bot_token(), chat_id="", requested_by="w").ok
    loaded = load_telegram(state)
    assert loaded is not None and loaded.api_base == "http://127.0.0.1:9999"


# -- the proxy takes the new key, no restart ----------------------------------------------------

PROVIDERS = (
    '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
    '[[proxy.providers]]\nname = "openai"\nkind = "openai"\n'
)


def service_config(tmp_path: Path, state: Path, keys: dict[str, str]) -> ServiceConfig:
    token = state / "gateway.token"
    token.write_text(GATEWAY + "\n")
    token.chmod(0o600)
    (tmp_path / "volume").mkdir()
    folder = state / "keys"
    folder.mkdir(mode=0o700)
    for name, value in keys.items():
        (folder / f"{name}.key").write_text(value + "\n")
        (folder / f"{name}.key").chmod(0o600)
    path = tmp_path / "backtide.toml"
    path.write_text(
        f'state_dir = "{state}"\nvolume = "{tmp_path / "volume"}"\n[proxy]\n{PROVIDERS}'
    )
    path.chmod(0o600)
    return ServiceConfig.from_file(path)


def real_keys(providers: Providers | tuple[Providers, Any]) -> dict[str, str | None]:
    if isinstance(providers, tuple):
        providers = providers[0]
    return {p.name: None if p.real_key is None else p.real_key.reveal() for p in providers.items}


def test_providers_now_reads_the_keys_folder_again(
    tmp_path: Path, state: Path, box: BlackBox
) -> None:
    first, second = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": first, "openai": second})
    assert real_keys(providers_now(config)) == {"anthropic": first, "openai": second}
    settings = make(state, box)
    changed = anthropic_key()
    settings.set_secret("anthropic", changed, requested_by="web")
    assert real_keys(providers_now(config)) == {"anthropic": changed, "openai": second}
    settings.clear_secret("openai", requested_by="web")
    now, problems = providers_now(config)
    assert real_keys(now) == {"anthropic": changed, "openai": None}, "a removed key: it waits"
    assert problems["openai"][0] == "missing"
    policy = egress_policy(config, now, problems)
    assert policy.waiting() == {"openai": "missing"}
    assert [p.name for p in policy.providers.items] == ["anthropic", "openai"]
    # Still a provider's host: a call there is refused (no_key), never a plain request.
    assert "api.openai.com" in policy.allow_list().entries
    # The fake keys (the agent's) are the very same ones it had.
    assert [p.fake_key for p in now.items] == [
        config.provider_keys[name].fake for name in ("anthropic", "openai")
    ]
    # Set again: usable at once.
    settings.set_secret("openai", second, requested_by="web")
    assert real_keys(providers_now(config)) == {"anthropic": changed, "openai": second}


def test_providers_now_fails_closed_on_a_keys_folder_it_cannot_use(
    tmp_path: Path, state: Path
) -> None:
    config = service_config(tmp_path, state, {"anthropic": anthropic_key()})
    assert config.provider_keys["openai"].real is None  # waits from the start
    config.keys_dir.chmod(0o755)
    now, problems = providers_now(config)
    assert real_keys(now) == {"anthropic": None, "openai": None}
    assert {name: problem for name, (problem, _) in problems.items()} == {
        "anthropic": "unusable",
        "openai": "unusable",
    }
    config.keys_dir.chmod(0o700)


class FakeJail:
    def __init__(self) -> None:
        self.config = type("C", (), {"uid": 1, "image": "x", "channel_dir": Path("/nowhere")})()

    def is_running(self) -> bool:
        return True


def handshake_with(policy: Policy) -> tuple[ProxyChannel, dict[str, Any]]:
    """A real channel's handshake over a socket pair: what the proxy would get as its config."""
    ours, theirs = socket.socketpair()
    theirs.sendall(protocol.encode(protocol.hello("0.1.0", 9), Sender.PROXY))
    channel = ProxyChannel(ours, record=lambda *a, **k: None, policy=policy)  # type: ignore[arg-type]
    channel.handshake(2)
    theirs.settimeout(2)
    reader = LineReader()
    lines: list[bytes] = []
    while not lines:
        lines = reader.feed(theirs.recv(65536))
    theirs.close()
    return channel, protocol.decode(lines[0], Sender.BACKTIDE)


def test_the_running_proxy_gets_the_new_key_on_a_new_connection(
    tmp_path: Path, state: Path, box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    """The whole way, without Docker: Settings writes the file, the reloader reads keys/ again,
    and Egress hands the proxy a config (a real handshake) that carries the new key."""
    caplog.set_level(logging.DEBUG)
    old = anthropic_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": openai_key()})
    configs: list[dict[str, Any]] = []
    records: list[tuple[str, dict[str, Any], int]] = []

    def connect(jail: Any, timeout: float) -> ProxyChannel:
        # What Egress._open does with the live policy, minus the socket folder and SO_PEERCRED.
        channel, sent = handshake_with(egress._policy)  # noqa: SLF001
        configs.append(sent)
        return channel

    egress = Egress(
        FakeJail(),  # type: ignore[arg-type]
        agent_name="agent",
        policy=egress_policy(config, config.model_providers()),
        record=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        thread=False,
        connect=connect,
    )

    def record(source: str, action: str, target: str = "", *, details: Any = None,
               risk: int = 0) -> None:  # fmt: skip
        records.append((action, details or {}, risk))

    hooks = EgressHooks(record=record, alert=lambda *a, **k: None)  # type: ignore[arg-type]
    egress._hooks = hooks  # noqa: SLF001 - as start() would, without starting a container
    egress._channel = connect(None, 1)  # noqa: SLF001
    egress._up = True  # noqa: SLF001
    first = configs[-1]
    assert {p["name"]: p["real_key"] for p in first["providers"]}["anthropic"] == old

    settings = make(state, box, key_reloader(config, egress))
    new = anthropic_key()
    outcome = settings.set_secret("anthropic", new, requested_by="web (uid 1, pid 2)")
    assert (outcome.status, outcome.applied) == (Outcome.SAVED, Applied.NOW)
    sent = configs[-1]
    assert {p["name"]: p["real_key"] for p in sent["providers"]}["anthropic"] == new
    assert sent["providers"][0]["fake_key"] == first["providers"][0]["fake_key"]
    assert ("proxy_reconfigured", {"providers": ["anthropic", "openai"], "now": True}, 0) in records
    texts = everything_said(box, caplog, outcome, records)
    assert leaks(new, *texts) == [] and leaks(old, *texts) == []

    # The proxy down: it is told when it comes back (the watch's next connection).
    egress._up = False  # noqa: SLF001
    later = anthropic_key()
    outcome = settings.set_secret("anthropic", later, requested_by="web")
    assert outcome.applied is Applied.WHEN_UP
    assert egress._policy.providers.items[0].real_key.reveal() == later  # noqa: SLF001


# -- the process sensor's list of secrets follows the keys -----------------------------------


class ReloadableEgress:
    """The part of Egress that key_reloader uses."""

    def __init__(self, config: ServiceConfig, *, up: bool = True) -> None:
        self.up = up
        self.policy = egress_policy(config, *config.model_providers_and_problems())
        self.policies: list[Policy] = []

    def reload(self, policy: Policy) -> bool:
        self.policies.append(policy)
        self.policy = policy
        return self.up


def test_the_sensor_strikes_the_keys_it_started_with(tmp_path: Path, state: Path, box: BlackBox):
    """build_sensor fills the sensor's list with the Gateway token and the providers' keys."""
    from backtide.jail import AgentJail
    from backtide.sensors.scrub import LiveScrub
    from backtide.service.runner import build_sensor
    from backtide.snapshots import SnapshotStore

    anthropic = anthropic_key()
    config = service_config(tmp_path, state, {"anthropic": anthropic, "openai": openai_key()})
    live = LiveScrub()
    build_sensor(
        config,
        AgentJail(config.jail_config()),
        box,  # type: ignore[arg-type]
        SnapshotStore(config.volume),
        scrub=live,
    )
    assert anthropic not in live.text(f"curl -H 'x-api-key: {anthropic}'")
    assert GATEWAY not in live.text(f"echo {GATEWAY}")


def test_changing_a_key_in_settings_refreshes_the_sensors_list(
    tmp_path: Path, state: Path, box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    """The new key is struck from the moment it is saved, the replaced one is dropped, the rest
    stays; and no key is said anywhere."""
    from backtide.sensors.scrub import LiveScrub
    from backtide.service.proxy_channel import known_secrets

    caplog.set_level(logging.DEBUG)
    old, other = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": other})
    live = LiveScrub(known_secrets([GATEWAY, *config.model_providers().known_secrets()]))
    egress = ReloadableEgress(config)
    settings = make(state, box, key_reloader(config, egress, live))  # type: ignore[arg-type]

    new = anthropic_key()
    assert live.text(f"echo {new}") == f"echo {new}"
    outcome = settings.set_secret("anthropic", new, requested_by="web (uid 1, pid 2)")
    assert outcome.status is Outcome.SAVED
    assert new not in live.text(f"echo {new}"), "the new key is struck"
    assert old in live.text(f"echo {old}"), "the replaced key is dropped"
    assert other not in live.text(f"echo {other}") and GATEWAY not in live.text(GATEWAY)
    assert len(egress.policies) == 1

    # Removing a key drops it too (the provider is left out of the proxy as well).
    outcome = settings.clear_secret("openai", requested_by="web")
    assert outcome.status is Outcome.CLEARED
    assert other in live.text(f"echo {other}")
    assert new not in live.text(f"echo {new}") and GATEWAY not in live.text(GATEWAY)
    texts = everything_said(box, caplog, outcome, repr(live))
    assert leaks(new, *texts) == [] and leaks(old, *texts) == [] and leaks(other, *texts) == []


def test_a_key_that_cannot_be_used_makes_its_provider_wait(tmp_path: Path, state: Path) -> None:
    """Fail closed: a file the gate cannot use is "waiting", never the old key and never a
    call without one. The proxy is told, nothing raises."""
    from backtide.sensors.scrub import LiveScrub
    from backtide.service.proxy_channel import known_secrets

    old, other = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": other})
    live = LiveScrub(known_secrets([GATEWAY, old, other]))
    egress = ReloadableEgress(config)
    (config.keys_dir / "anthropic.key").write_text("not a key at all\n")
    assert key_reloader(config, egress, live)() is Applied.NOW  # type: ignore[arg-type]
    (policy,) = egress.policies
    assert policy.waiting() == {"anthropic": "unusable"}
    assert real_keys(policy.providers) == {"anthropic": None, "openai": other}
    assert other not in live.text(f"echo {other}") and GATEWAY not in live.text(GATEWAY)

    (config.keys_dir / "anthropic.key").chmod(0o644)  # unreadable: the same
    key_reloader(config, egress, live)()  # type: ignore[arg-type]
    assert egress.policies[-1].waiting() == {"anthropic": "unusable"}


# -- security review of T09b (a238e4e): removing a key never fails open --------------------------


def running_egress(
    config: ServiceConfig,
) -> tuple[Egress, list[dict[str, Any]], list[tuple[str, dict[str, Any], int]]]:
    """An Egress "up" with a live channel, whose every connection is a real handshake (what the
    proxy would get as its config), without Docker."""
    configs: list[dict[str, Any]] = []
    records: list[tuple[str, dict[str, Any], int]] = []

    def connect(jail: Any, timeout: float) -> ProxyChannel:
        channel, sent = handshake_with(egress.policy)
        configs.append(sent)
        return channel

    providers, problems = config.model_providers_and_problems()
    egress = Egress(
        FakeJail(),  # type: ignore[arg-type]
        agent_name="agent",
        policy=egress_policy(config, providers, problems),
        record=lambda *a, **k: None,  # type: ignore[arg-type,return-value]
        thread=False,
        connect=connect,
    )

    def record(source: str, action: str, target: str = "", *, details: Any = None,
               risk: int = 0) -> None:  # fmt: skip
        records.append((action, details or {}, risk))

    egress._hooks = EgressHooks(record=record, alert=lambda *a, **k: None)  # type: ignore[arg-type]  # noqa: SLF001
    egress._channel = connect(None, 1)  # noqa: SLF001
    egress._up = True  # noqa: SLF001
    return egress, configs, records


def sent_keys(sent: dict[str, Any]) -> dict[str, str | None]:
    return {p["name"]: p["real_key"] for p in sent["providers"]}


def decision(policy: Policy, box: BlackBox) -> tuple[str, str | None]:
    """What backtide answers the proxy about a model call to Anthropic under ``policy``."""
    from tests.test_service_proxy_channel import make_channel
    from tests.test_spend_gate import llm_request

    channel, proxy = make_channel(box, policy=policy)
    try:
        channel.handle({"type": "request", "id": 1, "event": llm_request("f-review")})
        ack = proxy.receive_type("ack")
    finally:
        channel.close()
    return ack["verdict"], ack.get("reason")


def broken_telegram(state: Path) -> None:
    path = state / "telegram.toml"
    path.write_text("this is not toml = = [\n")
    path.chmod(0o600)


def test_a_broken_telegram_toml_never_keeps_a_removed_key(
    tmp_path: Path, state: Path, box: BlackBox
) -> None:
    """Finding 1: the reloader no longer reads telegram.toml (or anything but keys/). With a
    telegram.toml that cannot be used, removing a key still makes its provider wait at once,
    on the service's side and in the proxy's new config, and a call to it is refused."""
    old, other = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": other})
    egress, configs, _ = running_egress(config)
    before = egress.policy
    assert decision(before, box) == ("allow", None)
    broken_telegram(state)
    settings = make(state, box, key_reloader(config, egress))
    outcome = settings.clear_secret("anthropic", requested_by="web")
    assert (outcome.status, outcome.applied) == (Outcome.CLEARED, Applied.NOW)
    assert egress.waiting() == {"anthropic": "missing"}
    assert sent_keys(configs[-1]) == {"anthropic": None, "openai": other}
    assert decision(egress.policy, box) == ("deny", "no_key")
    # The rest is the policy it had: the gate's settings are not read again.
    after = egress.policy
    assert (after.secrets, after.trusted, after.allow_hosts, after.unknown_hosts) == (
        before.secrets,
        before.trusted,
        before.allow_hosts,
        before.unknown_hosts,
    )


def test_a_key_that_clashes_with_a_fake_one_never_keeps_a_removed_key(
    tmp_path: Path, state: Path, box: BlackBox
) -> None:
    """Finding 1, the Providers clash: openai.key holding the fake key of anthropic made the
    reload raise, and anthropic kept its removed key. Now that file waits ("unusable") and the
    removal applies at once."""
    old, other = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": other})
    egress, configs, _ = running_egress(config)
    clash = config.keys_dir / "openai.key"
    clash.write_text(config.provider_keys["anthropic"].fake + "\n")
    clash.chmod(0o600)
    settings = make(state, box, key_reloader(config, egress))
    outcome = settings.clear_secret("anthropic", requested_by="web")
    assert (outcome.status, outcome.applied) == (Outcome.CLEARED, Applied.NOW)
    assert egress.waiting() == {"anthropic": "missing", "openai": "unusable"}
    assert sent_keys(configs[-1]) == {"anthropic": None, "openai": None}
    assert decision(egress.policy, box) == ("deny", "no_key")


def test_a_service_starts_with_a_key_that_is_another_providers_fake_one(
    tmp_path: Path, state: Path
) -> None:
    config = service_config(tmp_path, state, {"anthropic": anthropic_key()})
    clash = config.keys_dir / "openai.key"
    clash.write_text(config.provider_keys["anthropic"].fake + "\n")
    clash.chmod(0o600)
    again = ServiceConfig.from_file(tmp_path / "backtide.toml")
    providers, problems = again.model_providers_and_problems()
    assert providers.waiting() == ("openai",) and problems["openai"][0] == "unusable"
    assert again.provider_keys["anthropic"].fake not in problems["openai"][1]


def test_a_reload_that_fails_during_a_removal_fails_closed(
    tmp_path: Path, state: Path, box: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever breaks the reload, a key that is no longer in keys/ stops being used at once:
    its provider waits in the service's policy, and the proxy's channel is replaced, so the
    proxy refuses until it has the new config. The other provider keeps its key."""
    from backtide.service import runner

    old, other = anthropic_key(), openai_key()
    config = service_config(tmp_path, state, {"anthropic": old, "openai": other})
    egress, configs, records = running_egress(config)
    channel = egress._channel  # noqa: SLF001

    def broken(config: ServiceConfig) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "providers_now", broken)
    settings = make(state, box, key_reloader(config, egress))
    outcome = settings.clear_secret("anthropic", requested_by="web")
    assert outcome.status is Outcome.CLEARED and outcome.applied is Applied.NOW
    assert egress.waiting() == {"anthropic": "missing"}
    assert egress._channel is not channel and channel is not None and channel.closed  # noqa: SLF001
    assert sent_keys(configs[-1]) == {"anthropic": None, "openai": other}
    assert decision(egress.policy, box) == ("deny", "no_key")
    assert ("proxy_reconfigured", {"providers": ["anthropic", "openai"], "now": True}, 0) in records
    # The removed key is still struck everywhere (it is never swapped in again).
    assert old in egress.policy.providers.known_secrets()
    assert egress.policy.providers.real_key_in(f"x {old}")

    # A set that fails the same way never hands over the new key, and the old one stops too.
    new = openai_key()
    outcome = settings.set_secret("openai", new, requested_by="web")
    assert (outcome.status, outcome.applied) == (Outcome.SAVED, Applied.RESTART)
    assert egress.waiting() == {"anthropic": "missing", "openai": "unusable"}
    assert sent_keys(configs[-1]) == {"anthropic": None, "openai": None}
    assert {old, other, new} <= set(egress.policy.providers.strike_only)


def test_a_failed_reload_with_the_proxy_down_still_makes_the_provider_wait(
    tmp_path: Path, state: Path, box: BlackBox, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.service import runner

    config = service_config(tmp_path, state, {"anthropic": anthropic_key()})
    egress, _, _ = running_egress(config)
    egress._up = False  # noqa: SLF001
    monkeypatch.setattr(runner, "providers_now", lambda config: 1 / 0)
    outcome = make(state, box, key_reloader(config, egress)).clear_secret(
        "anthropic", requested_by="web"
    )
    assert outcome.applied is Applied.WHEN_UP
    assert egress.waiting() == {"anthropic": "missing", "openai": "missing"}
    assert decision(egress.policy, box) == ("deny", "no_key")


def test_a_key_whose_file_cannot_be_used_is_still_struck_by_the_sensor(
    tmp_path: Path, state: Path
) -> None:
    """Finding 2: a key written by hand without chmod 600 (or of a shape the gate refuses) is
    never swapped in, but the sensor, the proxy and the black box still strike it."""
    from backtide.sensors.scrub import LiveScrub

    config = service_config(tmp_path, state, {"openai": openai_key()})
    live = LiveScrub()
    egress = ReloadableEgress(config)
    hand = anthropic_key()
    path = config.keys_dir / "anthropic.key"
    path.write_text(hand + "\n")
    path.chmod(0o644)
    key_reloader(config, egress, live)()  # type: ignore[arg-type]
    policy = egress.policies[-1]
    assert policy.waiting() == {"anthropic": "unusable"}
    assert real_keys(policy.providers)["anthropic"] is None
    assert hand not in live.text(f"echo {hand}")
    assert hand not in policy.scrubber().text(f"echo {hand}")
    assert policy.providers.real_key_in(hand)
