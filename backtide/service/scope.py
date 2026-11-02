"""Whose thread this is, when one process runs several agents (T26-2b; docs/47, section 6.1).

The service logs through ``logging``, and every WARNING and ERROR of ``backtide.*`` reaches a black
box through the log bridge of a ``Guardian`` (``backtide.notify.LogBridge``). A process has one
logger tree, so with several Guardians every bridge would hear every agent: A's problems in B's
black box, and one alert per agent for each. What tells them apart is the thread: an agent's
Guardian and all that it starts (its reader, its proxy's channel, its watcher, its space thread)
run on threads that descend from that agent's.

``threading`` does not hand anything down to a new thread, so ``hand_down`` wraps
``Thread.start`` for the whole process, once, and only when there is more than one agent: with
one, this module changes nothing and nothing is filtered. A thread with no scope (the main
thread, and what it starts) is the main agent's, which is where it has always gone.
"""

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

_here = threading.local()
_lock = threading.Lock()
_handing_down = False


def current() -> str | None:
    """The slug this thread works for, or None for the main agent's."""
    return getattr(_here, "slug", None)


def enter(slug: str) -> None:
    """From here on this thread, and what it starts, works for the agent ``slug``."""
    _here.slug = slug


@contextmanager
def working_for(slug: str | None) -> Iterator[None]:
    """For a while this thread works for ``slug`` (None: the main agent's). A connection to the
    sockets runs on the sockets' thread whichever agent it is about, and what it logs is that
    agent's (T26-2c)."""
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


def belongs_to(slug: str | None) -> Callable[[logging.LogRecord], bool]:
    """What a bridge asks of a log record: was it logged by a thread of this agent? ``slug`` None
    is the main agent's, which also takes the threads of nobody in particular."""

    def accepts(record: logging.LogRecord) -> bool:
        return current() == slug

    return accepts
