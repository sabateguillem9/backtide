"""Which agent an order on the sockets is about (T26-2c; docs/47, section 6.9).

One process runs every agent and has one control socket and one narrow socket, so an order may say
which agent it is for: the field ``agent``, with its slug. Nothing else ever chooses: no path, no
folder, nothing that reaches the disk. A slug is only a key of this list, which the service made
from its own configuration, so ``../x`` or ``/etc`` is simply nobody.

- Without the field an order is about the main agent. That is every order of an installation of
  before T26-2, byte for byte.
- A name that is nobody's, or that is not even a text, is refused with no agent touched.
- An agent of the configuration that is not being watched (it could not start, it failed, or it is
  stopping) is said so, also with nothing touched: its ``Guardian`` is published by its own
  ``Guardian.run`` once it is up, and taken out before it stops, as the main agent's socket is. A
  request in flight is waited for, so a rewind that started is answered.
- While an order runs, the thread works for that agent (``scope``): what it logs reaches that
  agent's black box and its alerts, not the main one's.

The agents themselves never get here: the sockets are not in their jail (invariant 1), and the
narrow socket refuses their ids.
"""

import logging
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from backtide.service import scope
from backtide.snapshots import Snapshot

logger = logging.getLogger(__name__)

RETIRE_WAIT = 90.0  # a rewind takes seconds; this only keeps a stuck order from holding the stop
NOBODY = "Ese agente no existe en esta instalación: no se ha hecho nada."
STOPPED_BY_OWNER = "stopped_by_owner"  # in the list, for an agent the owner stopped (T26-6a)
# What the list says an order is doing to an agent right now (T26-6b), whoever asked it: "stopped"
# is Docker's word, so while it is being stopped, or if that failed, the list says that instead.
STARTING, STOPPING, DELETING, STOP_FAILED = "starting", "stopping", "deleting", "stop_failed"
IN_USE_TASK = "task"  # what the list says while a task runs in it (D42)
_MAIN = object()


class OrderInvalid(Exception):  # noqa: N818 - reads better than OrderInvalidError
    """An order about the agents outside its closed shape (T26-6a): nothing was touched. The
    message is the reply's text, and never repeats what the order said."""


class AgentRefused(Exception):  # noqa: N818 - reads better than AgentRefusedError
    """An order about an agent that cannot take it. The message is the reply's text."""


@dataclass(frozen=True)
class Desk:
    """What the sockets act on for one agent."""

    slug: str
    guardian: Any  # backtide.service.control.RewindService
    budget: Any = None  # backtide.service.control.BudgetService
    waiting: Callable[[], Mapping[str, str]] | None = None
    snapshots: Callable[[], Sequence[Snapshot]] | None = None
    name: str | None = None
    notice: tuple[str, ...] = ()  # what the rewind notice says of it (its profile's lines)


@dataclass(frozen=True)
class AgentKind:
    """Which agent it is (D42): its profile and the version its pinned image brings. The service
    says it, from its own configuration: nothing an agent writes reaches it."""

    profile: str
    version: str | None = None


class Roster:
    """Every agent of the installation, by slug: the main one always, the others while watched."""

    def __init__(
        self,
        main: Desk,
        others: Sequence[tuple[str, str | None]] = (),
        stopped: Sequence[str] = (),
        kinds: Mapping[str, AgentKind] | None = None,
    ) -> None:
        self._main = main
        self._kinds = dict(kinds or {})
        self._orders: dict[str, str] = {}
        self._deleted: list[dict[str, Any]] = []  # T26-6c: only the list reads it, no order
        self._named = {main.slug: main.name, **dict(others)}
        self._stopped = set(stopped)  # by the owner: not a failure, and it stays so (T26-6a)
        self._desks: dict[str, Desk] = {}
        self._busy: dict[str, int] = {}
        self._changed = threading.Condition()

    def add(self, slug: str, name: str | None, kind: AgentKind | None = None) -> None:
        """A new agent of this installation (T26-6a): it exists, and it is not watched yet."""
        with self._changed:
            self._named[slug] = name
            if kind is not None:
                self._kinds[slug] = kind

    def note_order(self, slug: str, doing: str | None) -> None:
        """What an order is doing to this agent now, for the list; None: nothing."""
        with self._changed:
            if doing is None:
                self._orders.pop(slug, None)
            else:
                self._orders[slug] = doing

    def forget(self, slug: str) -> None:
        """This agent was deleted (T26-6c): it is nobody from now on, and nothing of it stays here
        for whoever comes back with that name. Its Guardian was already taken out (``retire``)."""
        with self._changed:
            self._named.pop(slug, None)
            self._desks.pop(slug, None)
            self._stopped.discard(slug)  # its count of orders in flight ends by itself
            self._kinds.pop(slug, None)
            self._orders.pop(slug, None)

    def set_deleted(self, items: Sequence[Mapping[str, Any]]) -> None:
        """What the list says of the deleted agents: never something an order can reach."""
        with self._changed:
            self._deleted = [dict(item) for item in items]

    def deleted(self) -> list[dict[str, Any]]:
        with self._changed:
            return [dict(item) for item in self._deleted]

    def clear_order(self, slug: str, doing: str) -> None:
        """The order ``doing`` is over: another's word stays."""
        with self._changed:
            if self._orders.get(slug) == doing:
                del self._orders[slug]

    def knows(self, slug: object) -> bool:
        """Whether ``slug`` names an agent of this installation. A lookup: never the disk."""
        with self._changed:
            return isinstance(slug, str) and slug in self._named

    def watched(self, slug: str) -> bool:
        with self._changed:
            return slug in self._desks

    def mark_stopped(self, slug: str, *, stopped: bool) -> None:
        """Stopped by the owner, or not any more: what the list says of one that is not watched."""
        with self._changed:
            if stopped:
                self._stopped.add(slug)
            else:
                self._stopped.discard(slug)

    def publish(self, desk: Desk) -> None:
        """This agent is up: orders about it reach it from now on."""
        with self._changed:
            self._desks[desk.slug] = desk

    def retire(self, slug: str, *, wait: float = RETIRE_WAIT) -> None:
        """This agent is about to stop: no new order, and those in flight end first."""
        deadline = time.monotonic() + wait
        with self._changed:
            self._desks.pop(slug, None)
            while self._busy.get(slug):
                left = deadline - time.monotonic()
                if left <= 0:
                    logger.error("an order about the agent %s is still running at its stop", slug)
                    return
                self._changed.wait(left)

    def listing(self) -> list[dict[str, Any]]:
        """Each agent and whether it is watched, the main one first. No secret and no path.
        ``notice`` is what the web's rewind confirmation says of this agent, from its profile;
        ``kind`` and ``version`` which agent it is, ``in_use`` whether a task runs in it (D42) and
        ``order`` what an order is doing to it now, from whoever (T26-6b)."""
        with self._changed:
            desks = {self._main.slug: self._main, **self._desks}
            named = dict(self._named)
            stopped = set(self._stopped)
            kinds = dict(self._kinds)
            orders = dict(self._orders)
        found = []
        for slug, name in named.items():
            desk = desks.get(slug)
            state = STOPPED_BY_OWNER if slug in stopped else None
            kind = kinds.get(slug)
            found.append(
                {
                    "slug": slug,
                    "name": name,
                    "main": slug == self._main.slug,
                    "watched": desk is not None,
                    "state": state if desk is None else _state_of(desk),
                    "notice": [] if desk is None else list(desk.notice),
                    "kind": None if kind is None else kind.profile,
                    "version": None if kind is None else kind.version,
                    "in_use": None if desk is None else _in_use_of(desk),
                    "order": orders.get(slug),
                }
            )
        return found

    @contextmanager
    def using(self, named: object = _MAIN) -> Iterator[Desk]:
        """The desk of the agent ``named``, counted as in use, with this thread working for it.
        Raises AgentRefused, with nobody touched, if it cannot be."""
        desk = self._desk_of(named)
        if desk is self._main:
            yield desk
            return
        try:
            with scope.working_for(desk.slug):
                yield desk
        finally:
            with self._changed:
                self._busy[desk.slug] -= 1
                self._changed.notify_all()

    def _desk_of(self, named: object) -> Desk:
        if named is _MAIN or named == self._main.slug:
            return self._main
        if not isinstance(named, str) or named not in self._named:
            logger.warning("refused an order about an agent this installation does not have")
            raise AgentRefused(NOBODY)
        with self._changed:
            desk = self._desks.get(named)
            if desk is not None:
                self._busy[named] = self._busy.get(named, 0) + 1
        if desk is None:
            logger.warning("refused an order about the agent %s, which is not being watched", named)
            raise AgentRefused(
                f"El agente {named} no se está vigilando ahora mismo (no ha arrancado, ha fallado "
                "o se está parando): no se ha hecho nada."
            )
        return desk


def _state_of(desk: Desk) -> str | None:
    state = getattr(desk.guardian, "agent_state", None)
    return None if state is None else str(state)


def _in_use_of(desk: Desk) -> str | None:
    running = getattr(desk.guardian, "task_running", None)
    return IN_USE_TASK if callable(running) and running() is True else None
