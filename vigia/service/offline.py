"""`vigia rebobinar` when no service runs: rewind in this process and leave the agent stopped.

Design: docs/19-diseno-t04.md, section 4 ("La CLI") and "Lo que hizo T04c-1" (``rewind()`` needs
a running service: the CLI without one opens the black box first).

The caller holds ``vigia.lock`` (that is how it knows there is no service), so nobody else owns
the agent while this runs. The rewind is the real ``Guardian.rewind``, with the real store and
jail and the real black box, and the same events; the differences from a service are:

- ``NullWatcher``: nobody watches files, so nothing is armed afterwards. The next
  ``vigia vigilar`` arms the watcher on the new workspace at boot (and records, as it does after
  any downtime, that nobody was watching).
- The agent is never started: a fresh Guardian is "stopped, no pause", so ``want_running`` is
  false. An agent found running unsupervised (a killed service left it) is frozen first and then
  killed by the rewind itself (never ``docker stop``: that gives it seconds of unwatched running)
  and stays stopped, with the usual ``agent_stop {reason: rewind}``.
- No snapshot is taken, no cycle runs. The person starts the service again when they want the
  agent back (`vigia vigilar`).

If the black box cannot be used nothing is rewound (no recording, no rewinding) and, like the
service does, an agent found running is stopped: it would run with nothing to record it.
"""

import logging
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import Any

from vigia.blackbox import BlackBoxError
from vigia.jail import AgentJail, JailError
from vigia.notify import AlertQueue, LogNotifier, Notifier
from vigia.service.config import ServiceConfig
from vigia.service.guardian import Guardian
from vigia.service.rewind import RewindOutcome
from vigia.service.runner import _stop_unrecorded_agent, make_grower, open_black_box
from vigia.snapshots import Snapshot, SnapshotStore

logger = logging.getLogger(__name__)


class NullWatcher:
    """A file watcher that watches nothing: ``vigia.service.guardian.FileWatcher`` for a process
    that only rewinds. Every method succeeds and does nothing."""

    def arm(self, current: str | None = None) -> bool:
        return False  # not armed: say so truthfully if anyone asks

    def barrier(self, take: Callable[[], Snapshot]) -> Snapshot:
        return take()

    def rearm_if_moved(self, workspace_id: int) -> bool:
        return False

    def report_unwatched(self) -> bool:
        return False

    def suspended(self, new_current: str | None = None) -> AbstractContextManager[None]:
        return _nothing()

    def close(self) -> None:
        return None


def _freeze_unwatched_agent(jail: AgentJail) -> bool:
    """An agent found running with no service has run unwatched. Freeze it at once (a few
    milliseconds) so that the rewind kills it, as it does a frozen one, instead of giving it
    `docker stop`'s grace period (up to ``stop_timeout`` seconds of running with no watcher).
    True if it was frozen here. A failure is logged and the rewind stops it the usual way."""
    try:
        if not jail.is_running() or jail.is_paused():
            return False
        jail.pause()
    except JailError as error:
        logger.warning("cannot freeze the unwatched agent before the rewind: %s", error)
        return False
    return True


def _thaw_if_left_frozen(jail: AgentJail) -> None:
    """The rewind ended and the agent we froze is still there (it was refused or failed before
    stopping it): it goes back to how it was found."""
    try:
        if jail.is_running() and jail.is_paused():
            jail.unpause()
    except JailError as error:
        logger.error("cannot thaw the agent that was frozen for the rewind: %s", error)


@contextmanager
def _nothing() -> Iterator[None]:
    yield


def rewind_without_service(
    config: ServiceConfig,
    snapshot_id: str,
    *,
    requested_by: str = "cli",
    jail: AgentJail | None = None,
    store: SnapshotStore | None = None,
    notifier: Notifier | None = None,
    guardian_options: Mapping[str, Any] | None = None,
) -> RewindOutcome:
    """Rewind to ``snapshot_id`` in this process and leave the agent stopped. The caller must
    hold ``vigia.lock``. Raises BlackBoxError, nothing rewound, if the black box cannot be used
    (a note says if the agent that was running had to be stopped; JailError if it cannot be).
    Alerts go to ``notifier`` (the log by default) and the events to the black box.
    ``guardian_options`` are extra arguments of ``Guardian`` (``info``, ``sync``, ``clock``...) for
    the tests, which run it with fake parts."""
    jail = jail if jail is not None else AgentJail(config.jail_config())
    try:
        box = open_black_box(config)
    except BlackBoxError as error:
        # Same as the service: an agent running with nothing to record it is stopped.
        _stop_unrecorded_agent(jail, error)
        raise
    alerts = AlertQueue(notifier if notifier is not None else LogNotifier())
    guardian = Guardian(
        config,
        store=store
        if store is not None
        else SnapshotStore(config.volume, workspace_limit=config.workspace_limit),
        jail=jail,
        blackbox=box,
        watcher=NullWatcher(),
        alerts=alerts,
        **{"grow": make_grower(config), **(guardian_options or {})},
    )
    alerts.start()
    try:
        try:
            guardian.open_for_rewind()
        except BlackBoxError as error:
            _stop_unrecorded_agent(jail, error)
            raise
        frozen = _freeze_unwatched_agent(jail)
        try:
            return guardian.rewind(snapshot_id, requested_by=requested_by)
        except Exception:
            # Logged while the bridge is still attached, so it reaches the black box too.
            logger.exception("the rewind to %s failed unexpectedly", snapshot_id)
            raise
        finally:
            if frozen:
                _thaw_if_left_frozen(jail)
            guardian.close_after_rewind()
    finally:
        try:
            alerts.close()
        finally:
            box.close()


__all__ = ["NullWatcher", "rewind_without_service"]
