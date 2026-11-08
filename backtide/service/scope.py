"""Whose thread this is, when one process runs several agents (T26-2b; docs/47, section 6.1).

The service logs through ``logging``, and every WARNING and ERROR of ``backtide.*`` reaches a black
box through the log bridge of a ``Guardian`` (``backtide.notify.LogBridge``). A process has one
logger tree, so with several Guardians every bridge would hear every agent: A's problems in B's
black box, and one alert per agent for each. What tells them apart is the thread: an agent's
Guardian and all that it starts (its reader, its proxy's channel, its watcher, its space thread)
run on threads that descend from that agent's.

``threading`` does not hand anything down to a new thread, so ``hand_down`` wraps
``Thread.start`` for the whole process, once, and only when there is more than one agent: with
one, this module changes nothing and nothing is filtered.

A thread with no scope works for nobody: the start of the service, its sockets, its bot, the orders
of ``Fleet``, and what they start. What one logs still goes to the main agent's box, as it always
has, but it is not the main agent's business, so its alert names nobody and offers no button (fail
closed: what forgets to say whose it is cannot freeze the main agent). The main agent's own threads
say so, like any other agent's: ``serve`` runs its ``Guardian`` under ``working_for``.
"""

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

_here = threading.local()
_lock = threading.Lock()
_handing_down = False


def current() -> str | None:
    """The slug this thread works for, or None for nobody in particular."""
    return getattr(_here, "slug", None)


def is_nobodys() -> bool:
    """This thread works for no agent: what it logs is about the machine, or it cannot be told."""
    return current() is None


def enter(slug: str) -> None:
    """From here on this thread, and what it starts, works for the agent ``slug``."""
    _here.slug = slug


@contextmanager
def working_for(slug: str | None) -> Iterator[None]:
    """For a while this thread works for ``slug`` (None: for nobody). A connection to the sockets
    runs on the sockets' thread whichever agent it is about, and what it logs is that agent's
    (T26-2c)."""
    before = current()
    _here.slug = slug
    try:
        yield
    finally:
        _here.slug = before


def hand_down() -> None:
    """A thread started from now on works for whoever started it. Idempotent, and it stays: the
    process has no use for the plain ``Thread.start`` once it runs several agents."""
    global _handing_down  # noqa: PLW0603 - once per process, by design
    with _lock:
        if _handing_down:
            return
        _handing_down = True
        plain_start = threading.Thread.start

        def start(thread: threading.Thread) -> None:
            slug, run = current(), thread.run

            def scoped() -> None:
                if slug is not None:
                    enter(slug)
                run()

            thread.run = scoped  # type: ignore[method-assign]
            plain_start(thread)

        threading.Thread.start = start  # type: ignore[method-assign]


def belongs_to(
    slug: str | None, *, and_nobodys: bool = False
) -> Callable[[logging.LogRecord], bool]:
    """What a bridge asks of a log record: was it logged by a thread of this agent?
    ``and_nobodys``: the main agent's box also takes the threads of nobody in particular."""

    def accepts(record: logging.LogRecord) -> bool:
        here = current()
        return here == slug or (and_nobodys and here is None)

    return accepts
