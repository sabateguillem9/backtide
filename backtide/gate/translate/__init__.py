"""The gate's translators (docs/32, section 8): from a request to an API backtide knows, to a
``Reading`` the gate decides on. Pure: no I/O, bounded cost.

``translate(view, context)`` picks the translator by the connection's host (and, for GitHub, the
``/graphql`` path), never by the ``Host`` header or the body. It returns None when no translator
knows the request (the gate's plain rules apply: reads pass, writes are held), and otherwise
always a ``Reading``: a translator that fails, or a request past the common checks (a method
override header, a body still encoded, trailers, too large), gives ``Effect.UNKNOWN``, which
the gate holds. It never raises for anything the agent sends. A read that a body carries (a
search by POST, a "harmless" write) is held when the body is over 64 KiB, and held with risk 3
when it carries a secret (``base.guard_read``).
"""

import logging
from collections.abc import Callable
from typing import NamedTuple

from backtide.gate.translate import (
    discord,
    github_graphql,
    gmail,
    graph_mail,
    read_post,
    slack,
    telegram,
)
from backtide.gate.translate.base import (
    WAIT_DEFAULT,
    WAIT_DISCORD,
    WAIT_GOG,
    WAIT_TELEGRAM,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    common_refusal,
    guard_read,
    unknown,
)

__all__ = ["Context", "Effect", "Reading", "RequestView", "Shape", "has_translator", "translate"]

logger = logging.getLogger(__name__)


class _Entry(NamedTuple):
    name: str
    claims: Callable[[RequestView, Context], bool]
    read: Callable[[RequestView, Context], Reading]
    shape: Shape  # and wait: for a refusal before the translator reads anything
    wait: int


_TRANSLATORS = (
    _Entry(
        telegram.NAME,
        telegram.claims,
        telegram.read,
        Shape.TELEGRAM,
        WAIT_TELEGRAM,
    ),
    _Entry(gmail.NAME, gmail.claims, gmail.read, Shape.GOOGLE, WAIT_GOG),
    _Entry(
        graph_mail.NAME,
        graph_mail.claims,
        graph_mail.read,
        Shape.GRAPH,
        WAIT_DEFAULT,
    ),
    _Entry(slack.NAME, slack.claims, slack.read, Shape.SLACK, WAIT_DEFAULT),
    _Entry(discord.NAME, discord.claims, discord.read, Shape.DISCORD, WAIT_DISCORD),
    _Entry(
        github_graphql.NAME,
        github_graphql.claims,
        github_graphql.read,
        Shape.PLAIN,
        WAIT_DEFAULT,
    ),
    _Entry(read_post.NAME, read_post.claims, read_post.read, Shape.PLAIN, WAIT_DEFAULT),
)


def has_translator(view: RequestView, context: Context) -> bool:
    """Whether a translator reads this request: then the gate's rule "a GET without a body
    passes" does not apply, the translator decides (docs/32, section 5)."""
    return _pick(view, context) is not None


def _pick(view: RequestView, context: Context) -> _Entry | None:
    for entry in _TRANSLATORS:
        if entry.claims(view, context):
            return entry
    return None


def translate(view: RequestView, context: Context) -> Reading | None:
    entry = _pick(view, context)
    if entry is None:
        return None
    name, _claims, read, shape, wait = entry
    refusal = common_refusal(view)
    if refusal is not None:
        return unknown(name, shape, wait, refusal)
    try:
        reading = read(view, context)
    except Exception as error:  # a bug, or input no check foresaw: held, never let through
        logger.error("the %s translator failed (%s): held", name, type(error).__name__)
        return unknown(name, shape, wait, Note.TRANSLATOR_FAILED)
    # A read carried by a body passes only small and without a secret (never a read with one).
    return guard_read(view, reading, context.scrub)
