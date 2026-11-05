"""Managing the agents from the web (T26-6b; docs/47, section 8): who it asks, what a page draws of
each agent, and an order that takes minutes without a page that hangs.

The web decides nothing here. It asks the service over the narrow socket (``--gestionar``), where
each order has its closed shape, its session and, to create or delete, a key just touched
(``backtide.service.web_control``). It never asks over root's socket: ``ControlAgentOrders`` is
off without the narrow one. The form only has fields of a list and a checked slug: no path, no image
and no text reaches an order. The main agent gets no button, and the service refuses it anyway.

An order takes as long as it takes: an agent's start, up to 240 s, or its stop, up to two minutes.
So a POST never waits for it. ``OrderBook`` runs it on a thread of its own, and the POST goes on
to a page that looks at how it goes. That page says what the service answered and nothing else:
"stopped" only once the service said so, which is Docker's word. If nobody knows how it ended (the
reply was lost, the web restarted), it says that, and the list, which is what the service says now,
is where to look. A web that restarts forgets its orders, never the service's: ``order`` in the list
comes from the service, whoever asked.
"""

import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    PeerCredentials,
    ask_agent_order,
    peer_credentials,
)
from backtide.service.roster import DELETING, STARTING, STOP_FAILED, STOPPED_BY_OWNER, STOPPING
from backtide.web.agents import Agent, AgentFacts, Listing
from backtide.web.rewind import WAIT_FOR_SERVICE, Availability, availability_of

logger = logging.getLogger(__name__)

# What a person can ask of an agent that exists, by the word its form says. The order is the
# service's; the word is never more than a key of this list.
VERBS: Mapping[str, str] = {
    "arrancar": "agent_start",
    "parar": "agent_stop",
    "pausar": "agent_pause",
    "seguir": "agent_resume",
    "borrar": "agent_delete",
}
CREATE = "crear"
ORDER_COMMAND = "agent_create"
TYPED_VERB = "borrar"  # the name written again, and a key just touched (docs/47, section 5.3)
MAX_RUNNING = 4  # threads here: the service takes two long orders at once, and refuses the rest
MAX_KEPT = 32  # orders whose end a page may still ask for
QUICK = 2.0  # seconds a POST waits, so that a pause says how it went without a page in between
LONG_AFTER = 30.0  # seconds after which the page says it may take a few minutes
# While an order of this web runs, what the row says, before the service's list says it.
ASKED_WORDS: Mapping[str, str] = {
    "arrancar": STARTING,
    "parar": STOPPING,
    "pausar": "pausing",
    "seguir": "resuming",
    "borrar": DELETING,
}
ORDER_WORDS = frozenset({STARTING, STOPPING, DELETING, STOP_FAILED})
FROZEN, RUNNING, STOPPED = "frozen", "running", "stopped"


class AgentOrders(Protocol):
    """What the app needs: whether it can ask, what the service says there is, and one order.
    ``ask`` raises what ``ask_agent_order`` raises."""

    enabled: bool

    def availability(self) -> Availability: ...

    def listing(self) -> Listing | None: ...

    def ask(self, request: dict[str, Any], session: str | None) -> dict[str, Any]: ...


class ControlAgentOrders:
    """The real one, on the service's narrow socket: on root's socket an order would carry no
    session and no key, so there it stays off, whatever the flag says. ``listing`` is
    ``LiveAgents``'s: one question for the whole web, every few seconds."""

    def __init__(
        self,
        path: Path,
        listing: Callable[[], Listing | None],
        *,
        enabled: bool = False,
        server_uid: int | None = None,
        wait: float = WAIT_FOR_SERVICE,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
        egid: Callable[[], int] = os.getegid,
    ) -> None:
        self._path = Path(path)
        self._listing = listing
        self.enabled = enabled and server_uid is not None
        self._server_uid = server_uid
        self._wait = wait
        self._peer = peer
        self._euid = euid
        self._egid = egid

    def availability(self) -> Availability:
        return availability_of(
            self._path,
            enabled=self.enabled,
            euid=self._euid,
            server_uid=self._server_uid,
            egid=self._egid,
        )

    def listing(self) -> Listing | None:
        return self._listing()

    def ask(self, request: dict[str, Any], session: str | None) -> dict[str, Any]:
        if not self.enabled:  # the routes do not exist without it: still, never by accident
            raise ControlError("esta web no se lanzó con --gestionar")
        return ask_agent_order(
            self._path,
            {**request, "session": session},
            wait=self._wait,
            peer=self._peer,
            server_uid=self._server_uid,
        )


@dataclass(eq=False)
class Order:
    """One order of this web: ``what`` is how asking went ("" while it runs): "asked" and then
    ``reply`` is the service's, or "no_service", "unknown" or "untrusted"."""

    id: str
    verb: str
    slug: str
    started: float
    fields: Mapping[str, Any]
    done: threading.Event = field(default_factory=threading.Event)
    what: str = ""
    reply: dict[str, Any] | None = None


class OrderBook:
    """The orders this web has asked, each on a thread of its own, which goes to its end whatever
    the browser does: a closed tab stops nothing. One per agent at a time. Thread-safe."""

    def __init__(
        self,
        ask: Callable[[dict[str, Any], str | None], dict[str, Any]],
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ask = ask
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._orders: dict[str, Order] = {}

    def start(
        self, verb: str, slug: str, request: dict[str, Any], session: str | None
    ) -> Order | None:
        """The order running, or None: this agent has one, or there are too many at once. The
        session goes to the thread only, and is in nothing this keeps."""
        order = Order(
            secrets.token_urlsafe(16),
            verb,
            slug,
            self._monotonic(),
            {key: value for key, value in request.items() if key != "cmd"},
        )
        thread = threading.Thread(
            target=self._run,
            args=(order, request, session),
            name=f"backtide-web-order-{slug}",
            daemon=True,  # the order is the service's by now: a stopping web does not wait for it
        )
        with self._lock:
            running = [one for one in self._orders.values() if not one.done.is_set()]
            if len(running) >= MAX_RUNNING or any(one.slug == slug for one in running):
                return None
            self._orders[order.id] = order
            self._forget_the_oldest()
            try:
                thread.start()
            except RuntimeError as error:  # no more threads: it never was an order
                del self._orders[order.id]
                logger.error("an order from the web could not start its thread: %s", error)
                return None
        return order

    def find(self, order_id: str) -> Order | None:
        with self._lock:
            return self._orders.get(order_id)

    def running(self) -> dict[str, str]:
        """Which agents have an order of this web running, and which."""
        with self._lock:
            return {one.slug: one.verb for one in self._orders.values() if not one.done.is_set()}

    def _forget_the_oldest(self) -> None:
        ended = [key for key, one in self._orders.items() if one.done.is_set()]
        for key in ended[: max(0, len(self._orders) - MAX_KEPT)]:
            del self._orders[key]

    def _run(self, order: Order, request: dict[str, Any], session: str | None) -> None:
        try:
            order.reply = self._ask(request, session)
            order.what = "asked"
        except ControlUnavailable:
            logger.warning("an order from the web found no service")
            order.what = "no_service"
        except ControlOutcomeUnknown as error:
            logger.warning("an order from the web has no known outcome: %s", error)
            order.what = "unknown"
        except ControlError as error:
            logger.error("an order from the web was not sent: %s", error)
            order.what = "untrusted"
        except Exception:  # said, with its trace: nobody knows how far it got
            logger.exception("an order from the web failed")
            order.what = "unknown"
        finally:
            order.done.set()


@dataclass(frozen=True)
class Row:
    """One agent, as the list draws it. ``word`` is the key of what it is doing ("agents.state.*"),
    and ``actions`` the verbs it offers: what the service would refuse is not offered, and what it
    offers the service decides again."""

    slug: str
    name: str | None
    main: bool
    colour: int
    base: str | None  # its pages; None: the service has it and this web does not read it yet
    kind: str | None
    version: str | None
    in_use: str | None
    word: str
    actions: tuple[str, ...]


def word_of(facts: AgentFacts | None, asked: str | None) -> str:
    """What is happening to it. An order first, because "stopped" is not true until it ends; then
    what the service says. Not knowing is not knowing."""
    if facts is not None and facts.order in ORDER_WORDS:
        return facts.order
    if asked is not None:
        return ASKED_WORDS.get(asked, STARTING)
    if facts is None:
        return "unknown"
    if not facts.watched:
        return STOPPED if facts.state == STOPPED_BY_OWNER else "unwatched"
    if facts.state in (RUNNING, FROZEN, STARTING, STOPPING):
        return facts.state
    return "still" if facts.state == STOPPED else "unknown"


ACTIONS_OF: Mapping[str, tuple[str, ...]] = {
    RUNNING: ("pausar", "parar", "borrar"),
    FROZEN: ("seguir", "parar", "borrar"),
    "still": ("seguir", "parar", "borrar"),  # watched, and its container stopped: a space pause
    STOPPED: ("arrancar", "borrar"),
    "unwatched": ("arrancar", "borrar"),
    STOP_FAILED: ("parar",),
}


def row_of(
    slug: str,
    name: str | None,
    main: bool,
    colour: int,
    base: str | None,
    facts: AgentFacts | None,
    asked: str | None,
) -> Row:
    word = word_of(facts, asked)
    return Row(
        slug=slug,
        name=name,
        main=main,
        colour=colour,
        base=base,
        kind=None if facts is None else facts.kind,
        version=None if facts is None else facts.version,
        in_use=None if facts is None else facts.in_use,
        word=word,
        actions=() if main else ACTIONS_OF.get(word, ()),
    )


def rows_of(
    agents: Sequence[Agent], listing: Listing | None, running: Mapping[str, str]
) -> list[Row]:
    """Every agent the web reads, in their order, and then those the service has and the web does
    not read yet: it says so a few seconds later, and they are there to be said."""
    facts = {} if listing is None else {one.slug: one for one in listing.agents}
    rows = [
        row_of(
            one.slug,
            one.name,
            one.main,
            one.colour,
            one.base,
            facts.get(one.slug),
            running.get(one.slug),
        )
        for one in agents
    ]
    known = {one.slug for one in agents}
    for one in facts.values():
        if one.slug not in known:
            rows.append(row_of(one.slug, one.name, one.main, 1, None, one, running.get(one.slug)))
    return rows


def restart_command(fields: Mapping[str, Any]) -> str:
    """What the first neighbour takes, which restarts the service, from a form that was checked."""
    return (
        f"sudo backtide agentes crear {fields.get('slug')} --perfil {fields.get('profile')} "
        f"--volumen {fields.get('volume_gib')} --reiniciar"
    )


__all__ = [
    "ACTIONS_OF",
    "CREATE",
    "LONG_AFTER",
    "ORDER_COMMAND",
    "QUICK",
    "TYPED_VERB",
    "VERBS",
    "AgentOrders",
    "ControlAgentOrders",
    "Order",
    "OrderBook",
    "Row",
    "restart_command",
    "row_of",
    "rows_of",
    "word_of",
]
