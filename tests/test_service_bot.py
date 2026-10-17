"""What the Telegram bot makes the service do (T09, ``vigia.service.bot``): the Guardian for
pausing and resuming, the control socket for rewinding (``via: "telegram"``), the snapshot to
offer for an alert, and the hooks that run the bot next to the control socket."""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from vigia.blackbox import BlackBox, BlackBoxError, create_key
from vigia.service.bot import GuardianActions, Hooks, TelegramParts, telegram_parts
from vigia.service.config import Secret, ServiceConfig
from vigia.service.control import ControlOutcomeUnknown, ControlUnavailable
from vigia.service.pause import PauseOutcome, PauseStatus, ResumeOutcome, ResumeStatus
from vigia.service.telegram_config import TelegramSettings
from vigia.snapshots import Snapshot

TOKEN = "123456789:" + "Q" * 35


@dataclass
class FakeGuardian:
    asked: list[str] = field(default_factory=list)
    agent_state: str = "frozen"
    pause_reasons: frozenset[str] = frozenset({"user"})

    def pause_by_user(self, *, requested_by: str) -> PauseOutcome:
        self.asked.append(f"pause:{requested_by}")
        return PauseOutcome(PauseStatus.FROZEN, "Agente congelado: no hace nada hasta /seguir.")

    def user_pause_mark(self) -> int:
        return 7

    def resume(self, *, requested_by: str, pause_mark: int | None = None) -> ResumeOutcome:
        self.asked.append(f"resume:{requested_by}:{pause_mark}")
        return ResumeOutcome(ResumeStatus.RESUMED, "El agente sigue donde estaba.")


@dataclass
class FakeStore:
    found: list[Snapshot] = field(default_factory=list)

    def snapshots(self) -> list[Snapshot]:
        return list(self.found)


@pytest.fixture
def box(tmp_path: Path) -> BlackBox:
    made = BlackBox(tmp_path / "bb.db", create_key(tmp_path / "bb.key"))
    made.open()
    yield made
    made.close()


def actions_with(
    box: BlackBox, snapshots: list[Snapshot], ask: Any = None
) -> tuple[GuardianActions, FakeGuardian]:
    guardian = FakeGuardian()
    actions = GuardianActions(Path("/state/control.sock"), ask=ask or (lambda *a, **k: {}), tz=UTC)
    actions.bind(guardian, box, FakeStore(snapshots))  # type: ignore[arg-type]
    return actions, guardian


def snap(moment: datetime, reason: str = "periodic") -> Snapshot:
    return Snapshot(moment.astimezone(UTC), reason)


def test_before_bind_every_action_says_vigia_is_starting(tmp_path: Path) -> None:
    actions = GuardianActions(tmp_path / "control.sock")
    assert "arrancando" in actions.pause()
    assert actions.pause_mark() is None
    assert "arrancando" in actions.resume(None)
    assert "arrancando" in actions.status()
    assert actions.target_for(1) is None
    actions.record("telegram_ignored", {}, 1)  # nowhere to record: nothing happens


def test_pause_and_resume_go_to_the_guardian_as_telegram(box: BlackBox) -> None:
    actions, guardian = actions_with(box, [])
    assert "congelado" in actions.pause()
    assert "donde estaba" in actions.resume(actions.pause_mark())
    assert guardian.asked == ["pause:telegram", "resume:telegram:7"]


def test_rewind_goes_through_the_control_socket_via_telegram(box: BlackBox) -> None:
    asked: list[tuple[Any, ...]] = []

    def ask(path: Path, snapshot_id: str, **options: Any) -> dict[str, Any]:
        asked.append((path, snapshot_id, options))
        return {"ok": True, "outcome": "done", "undo": "U1", "message": "Rebobinado."}

    actions, _ = actions_with(box, [], ask)
    text = actions.rewind("20261016T120000.000000Z-periodic")
    assert "Rebobinado." in text and "U1" in text
    ((path, snapshot_id, options),) = asked
    assert path == Path("/state/control.sock")
    assert snapshot_id == "20261016T120000.000000Z-periodic"
    assert options["via"] == "telegram"


@pytest.mark.parametrize(
    ("error", "says"),
    [
        (ControlUnavailable("x"), "no contesta"),
        (ControlOutcomeUnknown("No se sabe si el rebobinado se hizo."), "No se sabe"),
    ],
)
def test_rewind_says_what_is_known_when_the_socket_fails(
    box: BlackBox, error: Exception, says: str
) -> None:
    def ask(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise error

    actions, _ = actions_with(box, [], ask)
    assert says in actions.rewind("20261016T120000.000000Z-periodic")


def test_the_target_is_the_newest_snapshot_before_the_event(box: BlackBox) -> None:
    now = datetime.now(UTC)
    old, recent, later = (
        snap(now - timedelta(hours=1)),
        snap(now - timedelta(minutes=1)),
        snap(now + timedelta(hours=1)),
    )
    actions, _ = actions_with(box, [later, old, recent])
    event = box.append("file", "deleted", "work", risk=3)
    assert actions.target_for(event.seq) == recent.id
    assert actions.target_for(event.seq + 5) is None  # no such event


def test_no_snapshot_before_the_event_no_target(box: BlackBox) -> None:
    actions, _ = actions_with(box, [snap(datetime.now(UTC) + timedelta(hours=1))])
    event = box.append("file", "deleted", "work")
    assert actions.target_for(event.seq) is None


def test_the_notice_is_the_fixed_one_and_only_for_a_snapshot_that_exists(box: BlackBox) -> None:
    target = snap(datetime.now(UTC) - timedelta(minutes=10))
    actions, _ = actions_with(box, [target])
    notice = actions.notice(target.id)
    assert notice is not None
    assert notice.startswith("Vas a volver a las") and "hace 10 min" in notice
    assert "No se deshace" in notice
    assert actions.notice("20200101T000000.000000Z-periodic") is None  # gone
    assert actions.notice("../../etc") is None


def test_status_says_the_state_the_pauses_and_the_newest_snapshot(box: BlackBox) -> None:
    actions, _ = actions_with(box, [snap(datetime.now(UTC) - timedelta(minutes=3))])
    text = actions.status()
    assert "Agente: congelado." in text
    assert "la has pedido tú" in text
    assert "hace 3 min" in text


def test_record_writes_to_the_black_box_and_logs_a_failure(
    box: BlackBox, caplog: pytest.LogCaptureFixture
) -> None:
    actions, _ = actions_with(box, [])
    actions.record("telegram_ignored", {"reason": "not_owner"}, 2)
    (event,) = box.events(action="telegram_ignored")
    assert (event.source, event.risk, event.details) == ("system", 2, {"reason": "not_owner"})

    class Broken:
        def append(self, *args: Any, **kwargs: Any) -> None:
            raise BlackBoxError("disk full")

    actions._box = Broken()  # type: ignore[assignment] # noqa: SLF001
    with caplog.at_level(logging.ERROR):
        actions.record("telegram_ignored", {}, 1)
    assert "cannot write system/telegram_ignored" in caplog.text


# --- hooks and parts ---------------------------------------------------------------------------


@dataclass
class Hook:
    name: str
    log: list[str]
    fail_start: bool = False

    def start(self) -> None:
        if self.fail_start:
            raise RuntimeError("cannot start")
        self.log.append(f"start {self.name}")

    def close(self) -> None:
        self.log.append(f"close {self.name}")


def test_hooks_start_in_order_and_close_in_reverse() -> None:
    log: list[str] = []
    hooks = Hooks(Hook("control", log), Hook("bot", log))
    hooks.start()
    hooks.close()
    assert log == ["start control", "start bot", "close bot", "close control"]


def test_hooks_close_only_what_started() -> None:
    log: list[str] = []
    hooks = Hooks(Hook("control", log), Hook("bot", log, fail_start=True))
    with pytest.raises(RuntimeError):
        hooks.start()
    hooks.close()
    assert log == ["start control", "close control"]


def test_the_parts_share_one_book_and_touch_no_network(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    config = ServiceConfig(state_dir=state, volume=tmp_path / "vol", gateway_token=Secret("g" * 32))
    settings = TelegramSettings(Secret(TOKEN), 424242424, "http://127.0.0.1:9")
    parts = telegram_parts(config, settings)
    assert isinstance(parts, TelegramParts)
    assert parts.notifier._book is parts.bot._book  # noqa: SLF001
    assert TOKEN not in repr(parts.notifier._api)  # noqa: SLF001
