"""The service with several agents (T26-2b; docs/47, section 6), on the Mac with fakes.

The real thing, with two Claude Codes under the real unit, is
tests/attacks/test_two_agents_attacks.py in the VM. Here: what each agent is told of the others,
whose thread is whose, a neighbour that fails and takes nobody with it, keys that reach every
proxy, and the configuration that an agent cannot reach through a link. A machine with one agent
stays out of all of it (the last section).
"""

import dataclasses
import logging
import os
import stat
import threading
from pathlib import Path
from typing import Any

import pytest

from backtide import cli
from backtide.blackbox import BlackBoxError, create_key
from backtide.jail import AgentJail, JailError
from backtide.jail.config import Protected
from backtide.notify import Alert, AlertLevel, Labelled, LogBridge, LoggedProblem
from backtide.notify.telegram import ButtonBook, TelegramNotifier
from backtide.service import runner, scope
from backtide.service.agents import load_installation
from backtide.service.config import ConfigError, ServiceConfig, ensure_state_folder
from backtide.service.runner import (
    _Neighbours,
    build_budget,
    open_installation_box,
    record_agent_failed,
    reload_everyones_keys,
    serve,
)
from backtide.service.settings import Applied, ReloadFailedClosed
from backtide.setup import layout, selftest
from backtide.setup.preflight import Status
from backtide.web import BoxReader
from tests.test_service_agents import (
    Sink,
    add_agent,
    main_config,
    write_main,
)
from tests.test_service_agents import home as home  # noqa: F401, PLC0414 - the fixture


@pytest.fixture(autouse=True)
def _keys_read_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import backtide.service.config as config  # noqa: PLC0415

    monkeypatch.setattr(config, "KEY_SETTLE_S", 0.0)


# --- what each jail is told of the others -----------------------------------------------------


def labels(config: ServiceConfig) -> dict[str, Path]:
    return {p.label: p.path for p in config.agent_protected()}


def test_each_jail_is_told_the_volumes_and_folders_of_the_others(home: Path) -> None:  # noqa: F811
    image = home / "elsewhere" / "revisor.img"
    add_agent(
        home,
        "revisor",
        f'number = 1\nvolume = "{home / "vols" / "revisor"}"\nvolume_image = "{image}"\n'
        'max_volume_bytes = 1000000\n[agent]\nprofile = "claude-code"\n',
    )
    add_agent(home, "otro", number=2)
    found = load_installation(main_config(home))
    by_slug = {c.slug: c for c in found.agents}
    main, revisor, otro = by_slug["principal"], by_slug["revisor"], by_slug["otro"]
    seen_by_main = labels(main)
    assert seen_by_main["the volume of the agent revisor"] == revisor.volume
    assert seen_by_main["the image of the agent revisor"] == image
    assert seen_by_main["the config of the agent revisor"] == revisor.agent_config_dir
    assert seen_by_main["the volume of the agent otro"] == otro.volume
    seen_by_otro = labels(otro)
    assert seen_by_otro["the volume of the agent principal"] == main.volume
    assert seen_by_otro["the volume of the agent revisor"] == revisor.volume
    assert seen_by_otro["the config of the agent principal"] == main.agent_config_dir
    assert "the volume of the agent otro" not in seen_by_otro  # its own is the one it may have
    assert seen_by_otro["the snapshot volume"] == otro.volume
    # What the container's own check gets: AgentJail uses jail_config().protected.
    assert any(p.path == revisor.volume for p in otro.jail_config().protected)


def test_a_config_that_mounts_a_neighbours_volume_is_refused(home: Path) -> None:  # noqa: F811
    add_agent(home, "revisor", number=1)
    other = home / "agent-volumes" / "revisor" / "workspace" / "agente"
    write_main(home, f'[agent]\nconfig_dir = "{other}"\n')
    with pytest.raises(ConfigError, match="share a folder|the volume of the agent"):
        load_installation(main_config(home))


# --- links: where a path really leads ---------------------------------------------------------


def test_an_agents_state_folder_cannot_be_a_link(home: Path) -> None:  # noqa: F811
    outside = home / "outside"
    outside.mkdir(mode=0o700)
    (home / "state" / "agents").mkdir(mode=0o700)
    (home / "state" / "agents" / "revisor").symlink_to(outside)
    add_agent(home, "revisor")
    with pytest.raises(ConfigError, match="link|enlace"):
        load_installation(main_config(home))
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("target", ["keys", "installation", ""])
def test_a_volume_cannot_lead_into_the_state_through_a_link(
    home: Path,  # noqa: F811
    target: str,
) -> None:
    """The names say nothing: the comparison has to be with where it leads. Docker follows it."""
    (home / "state" / "keys").mkdir(mode=0o700, exist_ok=True)
    (home / "state" / "installation").mkdir(mode=0o700, exist_ok=True)
    link = home / "looks-fine"
    link.symlink_to(home / "state" / target if target else home / "state")
    add_agent(home, "revisor", f'number = 1\nvolume = "{link}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="volume .* is in the state"):
        load_installation(main_config(home))


def test_an_image_cannot_lead_into_the_state_through_a_link(home: Path) -> None:  # noqa: F811
    link = home / "looks-fine.img"
    link.symlink_to(home / "state" / "blackbox.db")
    add_agent(
        home,
        "revisor",
        f'number = 1\nvolume = "{home / "vols" / "revisor"}"\nvolume_image = "{link}"\n'
        'max_volume_bytes = 1000000\n[agent]\nprofile = "claude-code"\n',
    )
    with pytest.raises(ConfigError, match="volume_image .* is in the state"):
        load_installation(main_config(home))


def test_the_one_image_allowed_in_the_state_still_is(home: Path) -> None:  # noqa: F811
    image = home / "state" / "agents" / "revisor" / "volume.img"
    add_agent(
        home,
        "revisor",
        f'number = 1\nvolume = "{home / "vols" / "revisor"}"\nvolume_image = "{image}"\n'
        'max_volume_bytes = 1000000\n[agent]\nprofile = "claude-code"\n',
    )
    (found,) = load_installation(main_config(home)).others
    assert found.volume_image == image


def test_two_volumes_that_are_one_through_a_link_are_refused(home: Path) -> None:  # noqa: F811
    real = home / "vols" / "one"
    real.mkdir(parents=True)
    link = home / "vols" / "two"
    link.symlink_to(real)
    add_agent(home, "a", f'number = 1\nvolume = "{real}"\n[agent]\nprofile = "claude-code"\n')
    add_agent(home, "b", f'number = 2\nvolume = "{link}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="share a folder"):
        load_installation(main_config(home))


def test_the_neighbours_list_is_what_refuses_a_mount_of_another_agent(
    home: Path,  # noqa: F811
) -> None:
    """What _check_apart cannot see: a path of the neighbour given by hand to a jail, as a planned
    mount would be. The plain state and volume checks say nothing about it."""
    add_agent(home, "revisor", number=1)
    (other,) = load_installation(main_config(home)).others
    outside = other.volume / "workspace" / "agente"
    with pytest.raises(ConfigError, match="the volume of the agent revisor"):
        dataclasses.replace(
            ServiceConfig.from_file(main_config(home)),
            neighbours=(Protected("the volume of the agent revisor", other.volume),),
            agent={"config_dir": str(outside)},
        )


# --- whose thread is whose --------------------------------------------------------------------


def _record(message: str = "a problem") -> logging.LogRecord:
    return logging.LogRecord("backtide.x", logging.WARNING, __file__, 1, message, (), None)


def test_a_thread_works_for_the_agent_that_started_it() -> None:
    scope.hand_down()
    seen: dict[str, str | None] = {}

    def child(name: str) -> None:
        seen[name] = scope.current()

    def grandchild() -> None:
        thread = threading.Thread(target=child, args=("grandchild",))
        thread.start()
        thread.join()

    def agent() -> None:
        scope.enter("revisor")
        child("itself")
        thread = threading.Thread(target=grandchild)
        thread.start()
        thread.join()

    root = threading.Thread(target=agent)
    root.start()
    root.join()
    other = threading.Thread(target=child, args=("nobody's",))
    other.start()
    other.join()
    assert seen == {"itself": "revisor", "grandchild": "revisor", "nobody's": None}
    assert scope.current() is None


def test_each_agents_bridge_hears_only_its_own_threads() -> None:
    """The defence behind `eventos-del-vecino` for what backtide logs: one logger tree, two
    bridges, and each message reaches one box."""
    scope.hand_down()
    heard: dict[str, list[str]] = {"principal": [], "revisor": []}
    bridges = [
        LogBridge(lambda p: heard["principal"].append(p.message), accepts=scope.belongs_to(None)),
        LogBridge(
            lambda p: heard["revisor"].append(p.message), accepts=scope.belongs_to("revisor")
        ),
    ]
    for bridge in bridges:
        bridge.start()

    def emit_from_the_neighbour() -> None:
        scope.enter("revisor")
        for bridge in bridges:
            bridge.emit(_record("from revisor"))

    thread = threading.Thread(target=emit_from_the_neighbour)
    thread.start()
    thread.join()
    for bridge in bridges:
        bridge.emit(_record("from the main thread"))
        assert bridge.flush(5)
        bridge.close()
    assert heard == {"principal": ["from the main thread"], "revisor": ["from revisor"]}


def test_a_bridge_without_a_filter_hears_everything_as_before() -> None:
    heard: list[LoggedProblem] = []
    bridge = LogBridge(heard.append)
    bridge.start()
    bridge.emit(_record())
    assert bridge.flush(5)
    bridge.close()
    assert len(heard) == 1


def test_every_alert_says_whose_and_one_goes_at_a_time() -> None:
    sent: list[str] = []
    inside = threading.Semaphore(1)

    class Slow:
        def send(self, alert: Alert) -> None:
            assert inside.acquire(blocking=False), "two alerts at once"
            sent.append(alert.title)
            threading.Event().wait(0.01)
            inside.release()

    lock = threading.Lock()
    notifiers = [Labelled(Slow(), slug, lock) for slug in ("principal", "revisor")]
    threads = [
        threading.Thread(target=n.send, args=(Alert(AlertLevel.ERROR, "Algo", "b"),))
        for n in notifiers
        for _ in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(set(sent)) == ["principal: Algo", "revisor: Algo"]
    assert len(sent) == 10


class FakeApi:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def call(self, method: str, params: dict[str, Any], **_: Any) -> dict[str, Any]:
        self.sent.append(params)
        return {"message_id": len(self.sent)}


class FakeActions:
    def __init__(self) -> None:
        self.asked: list[int] = []

    def target_for(self, seq: int) -> str | None:
        self.asked.append(seq)
        return None


# --- the keys are the machine's ---------------------------------------------------------------


def test_every_alert_of_a_neighbour_offers_no_button_that_acts_on_the_main_agent() -> None:
    """Its event is in another box: "Pausar" would freeze the wrong agent, and "Rebobinar" would
    offer a snapshot of the main one for a number that means nothing there."""
    api = FakeApi()
    actions = FakeActions()
    notifier = TelegramNotifier(api, 42, ButtonBook(), actions)  # type: ignore[arg-type]
    lock = threading.Lock()
    Labelled(notifier, "revisor", lock, elsewhere=True).send(
        Alert(AlertLevel.ERROR, "Algo", "cuerpo", event_seq=7)
    )
    (sent,) = api.sent
    assert "reply_markup" not in sent and "revisor: Algo" in sent["text"]
    assert actions.asked == []
    Labelled(notifier, "principal", lock).send(
        Alert(AlertLevel.ERROR, "Algo", "cuerpo", event_seq=7)
    )
    assert "reply_markup" in api.sent[1] and actions.asked == [7]


def test_a_new_key_reaches_every_proxy() -> None:
    calls: list[str] = []

    def one(name: str, result: Applied = Applied.NOW) -> Any:
        def reload() -> Applied:
            calls.append(name)
            return result

        return reload

    together = reload_everyones_keys(one("main"), lambda: [one("a"), one("b")])
    assert together() is Applied.NOW
    assert calls == ["main", "a", "b"]
    later = reload_everyones_keys(one("main"), lambda: [one("a", Applied.WHEN_UP)])
    assert later() is Applied.WHEN_UP


def test_a_proxy_that_fails_closed_leaves_no_other_with_the_old_key() -> None:
    calls: list[str] = []

    def failing() -> Applied:
        calls.append("failing")
        raise ReloadFailedClosed(Applied.NOW)

    def bug() -> Applied:
        calls.append("bug")
        raise RuntimeError("a bug")

    def good() -> Applied:
        calls.append("good")
        return Applied.NOW

    together = reload_everyones_keys(failing, lambda: [bug, good])
    with pytest.raises(ReloadFailedClosed) as raised:
        together()
    assert calls == ["failing", "bug", "good"]  # all were tried
    assert raised.value.applied is Applied.WHEN_UP  # the bug's proxy cannot be vouched for


# --- a neighbour fails, and takes nobody with it ----------------------------------------------


class FakeGuardianParts:
    def __init__(self) -> None:
        self.ran: list[str] = []
        self.stopped = threading.Event()


def two_configs(home: Path) -> tuple[ServiceConfig, tuple[ServiceConfig, ...]]:  # noqa: F811
    write_main(home, "[budget]\nauto_prices = false\n")
    add_agent(home, "bueno", number=1)
    add_agent(home, "malo", number=2)
    found = load_installation(main_config(home))
    return found.main, found.others


def test_serve_hands_new_keys_to_every_proxy_and_each_agent_its_own_thread_scope(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wiring: a neighbour left out of the reload would keep a key the owner took away."""
    main, others = two_configs(home)
    reloaded: list[str] = []
    captured: dict[str, Any] = {}
    scopes: dict[str, str | None] = {}
    registered = threading.Barrier(3)
    real_build = runner.build_guardian
    real_settings = runner.Settings

    def build(config: ServiceConfig, **kwargs: Any) -> Any:
        return real_build(config, **{**kwargs, "jail": AgentJail(config.jail_config())})

    def key_reloader(config: ServiceConfig, egress: Any, secrets: Any) -> Any:
        def reload() -> Applied:
            reloaded.append(config.slug)
            return Applied.NOW

        return reload

    def settings(*args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return real_settings(*args, **kwargs)

    def run(guardian: Any, alerts: Any, box: Any, *, stop: threading.Event, **_: Any) -> None:
        scopes[guardian._config.slug] = scope.current()  # noqa: SLF001
        registered.wait(30)
        if threading.current_thread() is threading.main_thread():
            # The barrier: each neighbour registered its proxy before it ran.
            captured["applied"] = captured["reload_keys"]()
            stop.set()
        else:
            stop.wait(30)

    monkeypatch.setattr(runner, "build_guardian", build)
    monkeypatch.setattr(runner, "run_guardian", run)
    monkeypatch.setattr(runner, "key_reloader", key_reloader)
    monkeypatch.setattr(runner, "Settings", settings)
    serve(main, others=others, handle_signals=False)
    assert sorted(reloaded) == ["bueno", "malo", "principal"]
    assert captured["applied"] is Applied.NOW
    assert scopes == {"principal": None, "bueno": "bueno", "malo": "malo"}


def test_what_is_trusted_for_one_agent_is_its_own(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate: trust given for one agent must never let out what another sends."""
    add_agent(home, "revisor", number=1)
    found = load_installation(main_config(home))
    (other,) = found.others
    folders: list[Path] = []
    real = runner.TrustStore

    def store(folder: Path) -> Any:
        folders.append(folder)
        return real(folder)

    class Box:
        def append(self, *_: Any, **__: Any) -> None: ...
        def events(self, **_: Any) -> list[Any]:
            return []

    monkeypatch.setattr(runner, "TrustStore", store)
    for config in found.agents:
        runner.build_egress(config, AgentJail(config.jail_config()), Box())  # type: ignore[arg-type]
    assert folders == [found.main.state_dir, other.agent_dir]
    assert other.agent_dir != found.main.state_dir


def test_a_neighbour_that_cannot_start_is_told_and_the_others_go_on(home: Path) -> None:  # noqa: F811
    main, others = two_configs(home)
    told = Sink()
    stop = threading.Event()
    running = threading.Event()

    def build(config: ServiceConfig, **_: Any) -> Any:
        if config.slug == "malo":
            raise BlackBoxError("its key is gone")
        return ("guardian", "alerts", "box")

    def run(*_: Any, stop: threading.Event, **__: Any) -> None:
        running.set()
        stop.wait(30)

    neighbours = _Neighbours(
        main, others, notifier_for=lambda slug: None, stop=stop, share=None, told=told,  # type: ignore
        build=build, run=run,
    )  # fmt: skip
    neighbours.start()
    assert running.wait(10), "the good one never ran"
    deadline = threading.Event()
    for _ in range(200):
        if told.alerts:
            break
        deadline.wait(0.05)
    stop.set()
    neighbours.join(10)
    (alert,) = told.alerts
    assert alert.level is AlertLevel.ERROR
    assert "malo" in alert.title and "its key is gone" in alert.body
    with open_installation_box(main) as box:
        events = box.events(action="agent_failed")
    assert [(e.target, e.risk) for e in events] == [("malo", 2)]
    assert "its key is gone" in events[0].details["error"]


def test_a_neighbour_that_fails_later_is_told_the_same(home: Path) -> None:  # noqa: F811
    main, others = two_configs(home)
    told = Sink()
    stop = threading.Event()

    def run(*_: Any, stop: threading.Event, **__: Any) -> None:
        raise RuntimeError("it broke in the middle")

    neighbours = _Neighbours(
        main, others, notifier_for=lambda slug: None, stop=stop, share=None, told=told,  # type: ignore
        build=lambda config, **_: ("g", "a", "b"), run=run,
    )  # fmt: skip
    neighbours.start()
    neighbours.join(10)
    assert sorted(a.title for a in told.alerts) == [
        "El agente bueno no se está vigilando",
        "El agente malo no se está vigilando",
    ]


def test_a_secret_in_an_error_never_reaches_the_installations_box(home: Path) -> None:  # noqa: F811
    main, _ = two_configs(home)
    told = Sink()
    key = "sk-ant-api03-" + "abcdefgh" * 10
    record_agent_failed(main, told, "malo", RuntimeError(f"Authorization: Bearer {key}"))
    with open_installation_box(main) as box:
        (event,) = box.events(action="agent_failed")
    assert key not in event.details["error"]
    assert key not in told.alerts[0].body


def test_serve_starts_the_neighbours_and_they_end_with_the_main_agent(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The main one ending, for whatever reason, ends the rest: it is the only way to ask anything,
    and systemd starts it all again."""
    main, others = two_configs(home)
    built: list[str] = []
    ended: list[str] = []
    real_build = runner.build_guardian

    def build(config: ServiceConfig, **kwargs: Any) -> Any:
        built.append(config.slug)
        assert kwargs.get("log_filter") is not None
        assert kwargs.get("sensor_share") is not None
        assert kwargs["sensor_share"] is shares.setdefault("one", kwargs["sensor_share"])
        return real_build(config, **{**kwargs, "jail": AgentJail(config.jail_config())})

    shares: dict[str, Any] = {}

    def run(guardian: Any, alerts: Any, box: Any, *, stop: threading.Event, **_: Any) -> None:
        if threading.current_thread() is threading.main_thread():
            for _ in range(200):
                if len(built) == 3:
                    break
                threading.Event().wait(0.05)
            ended.append("main")
            raise RuntimeError("the main agent fell")
        assert stop.wait(30), "nobody told it to stop"
        ended.append("neighbour")

    monkeypatch.setattr(runner, "build_guardian", build)
    monkeypatch.setattr(runner, "run_guardian", run)
    with pytest.raises(RuntimeError, match="the main agent fell"):
        serve(main, others=others, handle_signals=False)
    assert sorted(built) == ["bueno", "malo", "principal"]
    assert ended == ["main", "neighbour", "neighbour"]
    with open_installation_box(main) as box:
        (start,) = box.events(action="service_start")
    assert start.details == {"agents": ["principal", "bueno", "malo"]}


# --- what is each one's -----------------------------------------------------------------------


def test_what_each_agent_keeps_is_in_its_own_folder(home: Path) -> None:  # noqa: F811
    """Two ledgers on one budget.json would lose each other's spending."""
    add_agent(home, "revisor", number=1)
    found = load_installation(main_config(home))
    (other,) = found.others

    class Box:
        def append(self, *_: Any, **__: Any) -> None: ...
        def events(self, **_: Any) -> list[Any]:
            return []

    budget, prices = build_budget(other, Box(), None)  # type: ignore[arg-type]
    assert budget._state_dir == other.agent_dir  # noqa: SLF001
    assert prices._state_dir == other.agent_dir  # noqa: SLF001
    budget_main, _ = build_budget(found.main, Box(), None)  # type: ignore[arg-type]
    assert budget_main._state_dir == found.main.state_dir  # noqa: SLF001


def test_each_reader_has_its_own_cursor_of_the_one_file(home: Path) -> None:  # noqa: F811
    add_agent(home, "revisor", number=1)
    found = load_installation(main_config(home))
    (other,) = found.others
    mine, theirs = found.main.sensor_reader_config(), other.sensor_reader_config()
    assert mine.events_dir == theirs.events_dir
    assert mine.cursor_file == found.main.sensor_jail_config().cursor_file  # as it always was
    assert theirs.cursor_file.parent == other.agent_dir
    assert mine.agent_name != theirs.agent_name
    assert found.main.sensor_jail_config() == other.sensor_jail_config()


def test_another_agents_channel_is_never_mounted_where_docker_cannot_see_it(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_agent(home, "revisor", number=1)
    (other,) = load_installation(main_config(home)).others
    monkeypatch.setenv(runner.SYSTEMD_RUN_MARK, "abc")
    jail = runner._proxy_jail(other)  # noqa: SLF001
    with pytest.raises(JailError, match="has to be mounted before the service starts"):
        jail._mount(["mount", "-t", "tmpfs"])  # noqa: SLF001
    monkeypatch.delenv(runner.SYSTEMD_RUN_MARK)
    assert runner._proxy_jail(other)._mount is not runner._channel_not_mounted  # noqa: SLF001


# --- the self-test: the installation's box ----------------------------------------------------


def test_the_self_test_verifies_the_installations_box(home: Path) -> None:  # noqa: F811
    from tests.test_blackbox_tamper import tamper  # noqa: PLC0415

    config = ServiceConfig.from_file(main_config(home))

    def checks() -> dict[str, Any]:
        return {c.key: c for c in selftest._verify(config)}  # noqa: SLF001

    assert checks()["installation-box"].status is Status.WARN  # no service has started yet
    runner.record_installation_start(config, Sink())
    runner.record_installation_start(config, Sink())
    good = checks()["installation-box"]
    assert good.status is Status.OK and "2 eventos" in good.summary
    with tamper(config.installation_db) as conn:
        conn.execute("UPDATE events SET target = 'otro' WHERE seq = 1")
    assert checks()["installation-box"].status is Status.FAIL


def test_the_self_test_says_when_the_installations_key_is_gone(home: Path) -> None:  # noqa: F811
    config = ServiceConfig.from_file(main_config(home))
    runner.record_installation_start(config, Sink())
    config.installation_key.unlink()
    (_, check) = selftest._verify(config)  # noqa: SLF001
    assert check.status is Status.FAIL


# --- a machine with one agent stays out of all this -------------------------------------------


def test_with_no_other_agent_nothing_is_added_to_the_jail(home: Path) -> None:  # noqa: F811
    found = load_installation(main_config(home))
    assert found.others == ()
    assert found.main.neighbours == ()
    assert (
        found.main.agent_protected() == ServiceConfig.from_file(main_config(home)).agent_protected()
    )


def test_an_empty_agents_folder_is_no_agent_at_all(home: Path) -> None:  # noqa: F811
    (home / "etc" / "agents").mkdir()
    found = load_installation(main_config(home))
    assert found.others == () and found.main.neighbours == ()


def test_serve_with_one_agent_starts_no_thread_and_filters_no_log(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = ServiceConfig.from_file(main_config(home))
    seen: dict[str, Any] = {}
    real_build = runner.build_guardian

    def build(config: ServiceConfig, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real_build(config, **{**kwargs, "jail": AgentJail(config.jail_config())})

    def run(*_: Any, **kwargs: Any) -> None:
        seen["threads"] = {t.name for t in threading.enumerate()}

    monkeypatch.setattr(runner, "build_guardian", build)
    monkeypatch.setattr(runner, "run_guardian", run)
    monkeypatch.setattr(runner, "_Neighbours", lambda *a, **k: pytest.fail("no neighbours to run"))
    serve(config, handle_signals=False)
    assert seen["log_filter"] is None and seen["sensor_share"] is None
    assert not any(name.startswith("backtide-agent-") for name in seen["threads"])
    with open_installation_box(config) as box:
        (start,) = box.events(action="service_start")
    assert start.details == {"agents": ["principal"]}


def test_the_state_of_a_machine_with_one_agent_gets_no_agents_folder(home: Path) -> None:  # noqa: F811
    load_installation(main_config(home))
    assert not (home / "state" / "agents").exists()
    assert not os.path.lexists(home / "etc" / "agents")


def test_ensure_state_folder_is_what_refuses_a_link(tmp_path: Path) -> None:
    """The refusal the first test of the links section relies on, and that it says so."""
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ConfigError):
        ensure_state_folder(link, "a folder")


# --- the CLI ----------------------------------------------------------------------------------


def test_vigilar_hands_the_other_agents_to_the_service(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    add_agent(home, "revisor", number=1)
    seen: dict[str, Any] = {}

    def fake_serve(config: ServiceConfig, **options: Any) -> None:
        seen.update(options, main=config)

    monkeypatch.setattr(cli, "serve", fake_serve)
    assert cli.main(["vigilar", "--config", str(main_config(home))]) == 0
    assert seen["main"].slug == "principal"
    assert [c.slug for c in seen["others"]] == ["revisor"]
    assert seen["main"].neighbours  # told of the neighbour, and its jail with it


def test_a_machine_with_one_agent_calls_the_service_as_it_always_did(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[ServiceConfig] = []

    def fake_serve(config: ServiceConfig) -> None:  # no other argument: it would fail
        seen.append(config)

    monkeypatch.setattr(cli, "serve", fake_serve)
    assert cli.main(["vigilar", "--config", str(main_config(home))]) == 0
    assert [c.slug for c in seen] == ["principal"]


@pytest.mark.parametrize(
    "order",
    [["vigilar"], ["aprobar", "h-0123456789abcdef"], ["tope"], ["tarea", "hola"]],
)
def test_a_file_of_another_agent_that_cannot_be_used_is_said_before_anything_runs(
    home: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    order: list[str],
) -> None:
    add_agent(home, "revisor", "number = 1\n")  # no volume
    monkeypatch.setattr(cli, "serve", lambda *a, **k: pytest.fail("the service must not run"))
    assert cli.main([*order, "--config", str(main_config(home))]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "revisor.toml" in err and "'volume'" in err


# --- the web reads the neighbour's black box (T26-2d) ---------------------------------------------


GID = os.getegid()


def shared(config: ServiceConfig) -> dict[str, int]:
    """The mode of what the web's group gets, by name."""
    db = config.blackbox_db
    return {
        path.name: stat.S_IMODE(os.lstat(path).st_mode)
        for path in (config.agents_dir, config.agent_dir, db)
    }


def test_the_webs_group_gets_the_neighbours_box_and_nothing_else(home: Path) -> None:  # noqa: F811
    _main, (other, *_) = two_configs(home)
    runner.share_box_with_web(other, GID)
    assert shared(other) == {"agents": 0o710, other.slug: 0o710, "blackbox.db": 0o640}
    for path in (other.agents_dir, other.agent_dir, other.blackbox_db):
        assert os.lstat(path).st_gid == GID
    key = other.blackbox_key
    assert stat.S_IMODE(os.lstat(key).st_mode) == 0o600, "the key is made first, and stays private"
    # What else is in there is what it was: not one more bit for the group.
    others = [p for p in other.agent_dir.rglob("*") if p != other.blackbox_db and p.is_file()]
    assert others and all(stat.S_IMODE(os.lstat(p).st_mode) & 0o077 == 0 for p in others)


def test_the_box_shared_works_for_the_service_and_for_the_web(home: Path) -> None:  # noqa: F811
    _main, (other, *_) = two_configs(home)
    runner.share_box_with_web(other, GID)
    with runner.open_black_box(other) as box:
        box.append("exec", "run", "del-vecino")
        wal = other.blackbox_db.with_name(f"{other.blackbox_db.name}-wal")
        assert stat.S_IMODE(os.lstat(other.blackbox_db).st_mode) == 0o640
        if os.path.lexists(wal):
            assert stat.S_IMODE(os.lstat(wal).st_mode) == 0o640, "SQLite copies the mode"
        reader = BoxReader(other.blackbox_db)
        try:
            assert [event.target for event in reader.events()][-1] == "del-vecino"
        finally:
            reader.close()
    runner.share_box_with_web(other, GID)  # again at the next start: nothing changes
    assert shared(other)["blackbox.db"] == 0o640
    with runner.open_black_box(other) as box:
        assert not box.verify().problems


def test_a_box_of_before_with_its_wal_is_shared_too(home: Path) -> None:  # noqa: F811
    _main, (other, *_) = two_configs(home)
    with runner.open_black_box(other) as box:
        box.append("exec", "run", "de-antes")
        before = stat.S_IMODE(os.lstat(other.blackbox_db).st_mode)
        assert before == 0o600
        runner.share_box_with_web(other, GID)
        for name in ("blackbox.db", "blackbox.db-wal", "blackbox.db-shm"):
            path = other.agent_dir / name
            if os.path.lexists(path):
                assert stat.S_IMODE(os.lstat(path).st_mode) == 0o640, name


@pytest.mark.parametrize("what", ["db", "folder"])
def test_a_link_is_never_followed(
    home: Path,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
    what: str,
) -> None:
    _main, (other, *_) = two_configs(home)
    outside = home / "outside"
    if what == "db":
        outside.write_text("")
        outside.chmod(0o600)
        other.blackbox_db.parent.mkdir(exist_ok=True)
        create_key(other.blackbox_key)
        other.blackbox_db.symlink_to(outside)
    else:
        outside.mkdir(mode=0o700)
        outside.rmdir()
        other.agent_dir.rename(outside)
        outside.chmod(0o700)
        other.agent_dir.symlink_to(outside)
    runner.share_box_with_web(other, GID)
    assert stat.S_IMODE(os.lstat(outside).st_mode) in (0o600, 0o700), "what it led to is as it was"
    assert "the web cannot be given the black box of the agent" in caplog.text


def test_a_box_without_its_key_is_left_for_what_stops_the_agent(
    home: Path,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    """It must not get in the way of ``build_guardian``, which stops an agent it cannot record:
    a container that lived through the service's death would go on without a box."""
    _main, (other, *_) = two_configs(home)
    other.blackbox_db.write_text("")
    runner.share_box_with_web(other, GID)
    assert not other.blackbox_key.exists()
    assert "the web cannot be given the black box of the agent" in caplog.text
    assert stat.S_IMODE(os.lstat(other.agent_dir).st_mode) == 0o700
    built: list[bool] = []

    def build(*args: Any, **options: Any) -> Any:
        built.append(True)
        raise BlackBoxError("the real one refuses it here, and stops the agent")

    neighbours = _Neighbours(
        _main, (other,), notifier_for=lambda slug: None, stop=threading.Event(), share=None,
        told=None, build=build, web_group=GID,
    )  # fmt: skip
    with pytest.raises(BlackBoxError):
        neighbours._serve_one(other)
    assert built == [True]


def test_what_the_folder_had_open_is_closed_first(home: Path) -> None:  # noqa: F811
    """The folder was 0700: an image made by hand with umask 022 was nobody's business. Now the
    web's group goes through it."""
    _main, (other, *_) = two_configs(home)
    image = other.agent_dir / "volume.img"
    image.write_text("todo el volumen")
    image.chmod(0o644)
    token = other.agent_dir / "gateway.token"
    token.write_text("de otra vida")
    token.chmod(0o640)
    open_folder = other.agent_dir / "abierta"
    open_folder.mkdir()
    open_folder.chmod(0o755)
    ca = other.agent_ca_dir
    ca.mkdir(exist_ok=True)
    ca.chmod(0o755)
    runner.share_box_with_web(other, GID)
    assert stat.S_IMODE(os.lstat(image).st_mode) & 0o077 == 0
    assert stat.S_IMODE(os.lstat(token).st_mode) & 0o077 == 0
    assert stat.S_IMODE(os.lstat(open_folder).st_mode) & 0o077 == 0
    assert stat.S_IMODE(os.lstat(ca).st_mode) == 0o755, "the certificate alone, as on the main one"
    assert stat.S_IMODE(os.lstat(other.agent_dir).st_mode) == 0o710


@pytest.mark.parametrize(
    ("mode", "gid", "bits"),
    [
        (0o750, 7, 0),  # the agent's or the proxy's folder: the group is theirs
        (0o640, 7, 0),
        (0o644, 7, 0o004),
        (0o755, 7, 0o005),
        (0o640, 9, 0o040),  # the web's own group
        (0o750, 9, 0o050),
        (0o600, 9, 0),
    ],
)
def test_only_what_lets_the_webs_group_in_counts(mode: int, gid: int, bits: int) -> None:
    assert runner.bits_for_the_web(mode, gid, 9) == bits


def test_a_folder_of_the_agents_group_keeps_what_the_agent_needs(home: Path) -> None:  # noqa: F811
    """`<profile>/` and `proxy-ca/` are 0750 with the agent's and the proxy's group: closing them
    would leave the jail without its config."""
    others = [gid for gid in os.getgroups() if gid != GID]
    if not others:
        pytest.skip("it takes a user with a second group")
    _main, (other, *_) = two_configs(home)
    theirs = other.agent_dir / "de-su-grupo"
    theirs.mkdir()
    os.chown(theirs, -1, others[0])
    theirs.chmod(0o750)
    runner.share_box_with_web(other, GID)
    assert stat.S_IMODE(os.lstat(theirs).st_mode) == 0o750


def test_a_link_in_the_folder_leaves_it_closed(
    home: Path,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    """What it leads to cannot be judged from here. Shared at an earlier start, it closes again."""
    _main, (other, *_) = two_configs(home)
    runner.share_box_with_web(other, GID)
    assert stat.S_IMODE(os.lstat(other.agent_dir).st_mode) == 0o710
    outside = home / "fuera"
    outside.write_text("")
    outside.chmod(0o644)
    (other.agent_dir / "enlace").symlink_to(outside)
    runner.share_box_with_web(other, GID)
    assert stat.S_IMODE(os.lstat(other.agent_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(outside).st_mode) == 0o644, "not followed"
    assert "the web cannot be given the black box of the agent" in caplog.text


def test_a_neighbour_gets_its_box_shared_before_it_is_built(home: Path) -> None:  # noqa: F811
    main, (other, *_) = two_configs(home)
    order: list[str] = []
    real = runner.share_box_with_web

    def share(config: ServiceConfig, group: int) -> None:
        order.append("shared")
        real(config, group)

    def build(*args: Any, **options: Any) -> Any:
        order.append("built")
        raise RuntimeError("enough")

    neighbours = _Neighbours(
        main, (other,), notifier_for=lambda slug: None, stop=threading.Event(), share=None,
        told=None, build=build, web_group=GID,
    )  # fmt: skip
    original, runner.share_box_with_web = runner.share_box_with_web, share
    try:
        with pytest.raises(RuntimeError, match="enough"):
            neighbours._serve_one(other)
    finally:
        runner.share_box_with_web = original
    assert order == ["shared", "built"]


def test_the_modes_are_the_installers(home: Path) -> None:  # noqa: F811
    assert runner.WEB_FOLDER_MODE == layout.STATE_DIR_MODE
    assert runner.WEB_BOX_MODE == layout.BLACKBOX_DB_MODE
