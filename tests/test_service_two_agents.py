"""The service with several agents (T26-2b; docs/47, section 6), on the Mac with fakes.

The real thing, with two Claude Codes under the real unit, is
tests/attacks/test_two_agents_attacks.py in the VM. Here: what each agent is told of the others,
whose thread is whose, a neighbour that fails and takes nobody with it, keys that reach every
proxy, and the configuration that an agent cannot reach through a link. A machine with one agent
stays out of all of it (the last section).
"""

import logging
import os
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from backtide import cli
from backtide.blackbox import BlackBoxError
from backtide.jail import AgentJail, JailError
from backtide.notify import Alert, AlertLevel, Labelled, LogBridge, LoggedProblem
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
from backtide.setup import selftest
from backtide.setup.preflight import Status
from tests.test_service_agents import (
    Sink,
    add_agent,
    claude_code,
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
    """Without the neighbours this file reads: its folder is nobody's until it runs."""
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


# --- the keys are the machine's ---------------------------------------------------------------


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


def test_a_replaced_config_still_validates_its_neighbours(home: Path) -> None:  # noqa: F811
    add_agent(home, "revisor", number=1)
    found = load_installation(main_config(home))
    (other,) = found.others
    rebuilt = replace(other, neighbours=other.neighbours)
    assert rebuilt.agent_protected() == other.agent_protected()
    assert claude_code(home, "revisor", 1).startswith("number = 1")


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
    [["vigilar"], ["instantaneas"], ["seguir"], ["retenidas"]],
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
