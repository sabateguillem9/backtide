"""The agents the service says there are (T26-2d; docs/47, section 6.9): the web's list, read again
while it runs. The service may come up after the web, restart with more agents, or stop watching
one, so this is asked and never remembered from the start.

What it asks is ``{"cmd": "agents"}``, on the same socket as everything else (it also keeps what the
list says of each agent, ``listing``, T26-6b, the main one included): the narrow one on the
installed web, which takes it without a session (it says who exists, which the web's group can read
anyway). Each agent's black box is then read with its own ``BoxReader``, read-only and without the
key (``ServiceConfig.blackbox_db``: the service gives that file to the web's group, as the installer
does with the main one's, ``share_box_with_web``), and its snapshots are asked with ``agent``.

A slug only becomes a path here, and only if it comes from the service's reply and is a slug.
Nothing a browser sends gets here. Not knowing is never "there are none": without an answer the list
stays as it was, and an agent stops being listed only when the service says so. Every order then
goes through the service, which decides for itself (``backtide.service.roster``).
"""

import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from backtide.jail.identity import SLUG
from backtide.service.control import (
    ControlError,
    PeerCredentials,
    ask_fleet,
    ask_snapshots,
    peer_credentials,
)
from backtide.snapshots import Snapshot, SnapshotError
from backtide.web.agents import AgentFacts, AgentSource, Listing, RetiredAgent, RosterError
from backtide.web.reader import BoxReader
from backtide.web.rewind import WAIT_FOR_SERVICE, Availability, availability_of

logger = logging.getLogger(__name__)

ASK_EVERY = 5.0  # seconds: a person sees a new agent this soon, and the socket has its limits


class LiveAgents:
    """A callable: the agents other than the main one as the service last said, or None if it has
    never said (the web then shows what it was started with). Thread-safe, and it never waits for
    a service that is not there: one thread asks at a time, and the others take the last answer."""

    def __init__(
        self,
        control: Path,
        *,
        box_of: Callable[[str], Path],
        server_uid: int | None = None,
        every: float = ASK_EVERY,
        peer: PeerCredentials = peer_credentials,
        euid: Callable[[], int] = os.geteuid,
        egid: Callable[[], int] = os.getegid,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._control = Path(control)
        self._box_of = box_of
        self._server_uid = server_uid
        self._every = every
        self._peer = peer
        self._euid = euid
        self._egid = egid
        self._monotonic = monotonic
        self._asking = threading.Lock()
        self._asked_at: float | None = None
        self._last: tuple[AgentSource, ...] | None = None
        self._listing: Listing | None = None
        self._readers: dict[str, BoxReader] = {}
        self._listings: dict[str, Callable[[], Sequence[Snapshot]]] = {}
        self._failing = False

    def __call__(self) -> Sequence[AgentSource] | None:
        moment = self._monotonic()
        if self._asked_at is not None and moment - self._asked_at < self._every:
            return self._last
        if not self._asking.acquire(blocking=False):
            return self._last
        try:
            self._asked_at = moment
            self._ask()
        finally:
            self._asking.release()
        return self._last

    def listing(self) -> Listing | None:
        """What the service last said of every agent, the main one too (T26-6b); None if it has
        never said. It never asks, so a page may call it anywhere: each request asks first, in a
        thread of its own (``_roster_now``), and that is what keeps this fresh."""
        return self._listing

    def close(self) -> None:
        with self._asking:
            for reader in self._readers.values():
                reader.close()
            self._readers.clear()

    def _ask(self) -> None:
        state = availability_of(
            self._control,
            enabled=True,
            euid=self._euid,
            server_uid=self._server_uid,
            egid=self._egid,
        )
        if state is not Availability.READY:  # a reader, or no service yet: nothing to ask
            return
        try:
            listed, deleted = ask_fleet(
                self._control, wait=0, peer=self._peer, server_uid=self._server_uid
            )
        except ControlError as error:
            if not self._failing:
                logger.warning("the service cannot say which agents there are: %s", error)
            self._failing = True
            return
        if self._failing:
            logger.info("the service says which agents there are again")
        self._failing = False
        self._last = tuple(
            source for item in listed if (source := self._source_of(item)) is not None
        )
        self._listing = _listing_of(listed, deleted)
        self._let_go_of_others({item["slug"] for item in listed})

    def _let_go_of_others(self, listed: set[str]) -> None:
        """An agent no longer listed was deleted (T26-6c): its reader goes, or the service could
        not take its box out of WAL, which a reader that may not write in the folder needs."""
        for slug in [slug for slug in self._readers if slug not in listed]:
            self._readers.pop(slug).close()
            self._listings.pop(slug, None)

    def _source_of(self, item: dict[str, Any]) -> AgentSource | None:
        slug = item["slug"]
        if item["main"]:
            return None
        if not SLUG.fullmatch(slug):  # the service's own list: still, it is about to be a path
            logger.warning("the service listed an agent whose name is not a slug: left out")
            return None
        if slug not in self._readers:
            self._readers[slug] = BoxReader(self._box_of(slug))
            self._listings[slug] = self._snapshots_of(slug)
        try:
            return AgentSource(
                slug,
                item["name"],
                self._readers[slug],
                self._listings[slug],
                watched=item["watched"],
                notice_lines=tuple(item["notice"]),
            )
        except RosterError as error:
            logger.warning("the service listed an agent the web cannot show: %s", error)
            return None

    def _snapshots_of(self, slug: str) -> Callable[[], Sequence[Snapshot]]:
        def listing() -> Sequence[Snapshot]:
            try:
                return ask_snapshots(
                    self._control,
                    server_uid=self._server_uid,
                    wait=WAIT_FOR_SERVICE,
                    peer=self._peer,
                    agent=slug,
                )
            except ControlError as error:  # the pages say the list cannot be read
                raise SnapshotError(str(error)) from None

        return listing


def _listing_of(listed: Sequence[dict[str, Any]], deleted: Sequence[dict[str, Any]]) -> Listing:
    return Listing(
        tuple(
            AgentFacts(
                item["slug"],
                item["name"],
                item["main"],
                item["watched"],
                item["state"],
                item["kind"],
                item["version"],
                item["in_use"],
                item["order"],
            )
            for item in listed
        ),
        tuple(
            RetiredAgent(
                item["slug"],
                item["name"],
                _moment(item["deleted_at"]),
                _moment(item["purge_after"]),
                item["purged"],
            )
            for item in deleted
        ),
    )


def _moment(text: str) -> datetime | None:
    """A date of the service's: one it cannot be is no date, and the page says less."""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.utcoffset() is not None else None


__all__ = ["ASK_EVERY", "LiveAgents"]
