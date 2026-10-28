"""The web's narrow socket (T12c, decision 27): how the installed web acts without the service's
privileges.

The installed web runs as ``backtide-web`` (docs/25, section 3), not as root, so the control
socket (0600, root's, ``SO_PEERCRED`` uid) does not answer it. This second socket does, for that
group only, and only for a closed list of commands. It is a second wall, not the only one: the
web still takes a POST only from its own page, with the session cookie, the CSRF token and a
one-time confirmation (``backtide.web.security``, ``Tickets``), before it asks here.

The socket:
- ``<state_dir>/web.sock`` (``ServiceConfig.web_socket``), root's, mode 0660, group the web's.
  The state folder is 0710 ``root:backtide-web`` (D25), so the group reaches the socket by its
  name and nothing else of the folder. It is never in the volume and never mounted into the
  agent (invariant 1), and opened only when the service is told the group (`backtide vigilar
  --grupo-web`, which the installed unit passes).
- Who: ``SO_PEERCRED`` on every connection; the group the kernel gives (the effective gid at
  connect time) must be the web's, and the agent's and the proxy's ids are refused whatever
  their group. Fails closed: unreadable credentials, no service.
- What (``COMMANDS``): reading the volume's snapshot list, the held requests, the trusted
  recipients and batches, what keys are set (the last four characters at most) and the spending;
  and, as changes, ``rewind`` (to a snapshot id that is in the volume's list right now: checked
  HERE before the Guardian is called), ``decide`` (approve or reject a held request by its id),
  ``trust`` ("aprobar y confiar", only from the web, as on the control socket), ``untrust`` and
  ``end_batch`` (taking a trust away: they only make the gate ask more), ``set_secret`` and
  ``clear_secret`` (a provider's key or Telegram's token and chat: written by the service at
  0600, never sent back), ``set_budget`` (the caps, checked as `backtide tope` checks them) and
  ``accept_prices``. Nothing else: no ``resume``, no ``shell``, ``import`` or ``export`` (no path
  of any kind), no config. Each change is handled by the very code of the control socket, with
  ``via`` forced to ``web``, so the black box records it as the control socket does:
  ``requested_by: "web (uid …, pid …)"`` with the kernel's uid and pid.
- How much: a request is one JSON line of at most 4 KiB within 5 s (the control socket's own
  reading), at most ``MAX_WEB_CONNECTIONS`` at once, and two token buckets: every request, and the
  changes on their own (``REQUESTS_*``, ``CHANGES_*``). Over either, a refusal without calling
  anything. Every refusal of a command or a caller is a WARNING, which the log bridge records in
  the black box (once a minute per kind) and alerts.

The client side is the control socket's (``ask_*`` with ``server_uid=0``: the socket and the
process answering must be root's), plus ``ask_snapshots`` here.
"""

import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from backtide.jail.config import AGENT_GID, AGENT_UID
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.control import (
    MAX_CONNECTIONS,
    MAX_LIST_REPLY_BYTES,
    REPLY_TIMEOUT,
    WAIT_FOR_SERVICE,
    BudgetService,
    ControlError,
    ControlServer,
    PeerCredentials,
    RewindService,
    SettingsService,
    _ask,
    _BadRequest,
    _json_or_none,
    _reply_of,
    peer_credentials,
)
from backtide.service.rewind import RewindOutcome, RewindStatus
from backtide.snapshots import Snapshot

logger = logging.getLogger(__name__)

WEB_SOCKET_MODE = 0o660
MAX_WEB_CONNECTIONS = 4
# What the web may read (it shows them) and change (each behind its own confirmation in the web).
READS = frozenset({"snapshots", "holds", "trusted", "batches", "secrets", "budget"})
CHANGES = frozenset(
    {
        "rewind", "decide", "trust", "untrust", "end_batch", "set_secret", "clear_secret",
        "set_budget", "accept_prices",
    }
)  # fmt: skip
COMMANDS = READS | CHANGES
# Every request: a burst of 120, then 20 a second (the panel's stream asks about once a second
# per open tab). The changes: a burst of 10, then one every 3 s (a person clicks).
REQUESTS_BURST, REQUESTS_PER_SECOND = 120, 20.0
CHANGES_BURST, CHANGES_PER_SECOND = 10, 1 / 3
MAX_LISTED_SNAPSHOTS = 5000
_FORBIDDEN_IDS = frozenset({AGENT_UID, PROXY_UID})
_FORBIDDEN_GIDS = frozenset({0, AGENT_GID, PROXY_GID})


class Bucket:
    """A token bucket: ``capacity`` at most, ``per_second`` back. Thread-safe."""

    def __init__(
        self, capacity: float, per_second: float, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._capacity = float(capacity)
        self._rate = float(per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._at = clock()
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            now = self._clock()
            self._tokens = min(self._capacity, self._tokens + (now - self._at) * self._rate)
            self._at = now
            if self._tokens < 1:
                return False
            self._tokens -= 1
            return True


class WebControlServer(ControlServer):
    """The narrow socket. ``group`` is the web's gid (never root's, the agent's or the proxy's);
    ``snapshots`` lists the volume's snapshots (``SnapshotStore.snapshots``). The rest is the
    control socket's, whose handlers serve the commands of the list."""

    socket_mode = WEB_SOCKET_MODE
    label = "web socket"

    def __init__(
        self,
        guardian: RewindService,
        path: Path,
        *,
        group: int,
        snapshots: Callable[[], Sequence[Snapshot]],
        user: int | None = None,
        peer: PeerCredentials = peer_credentials,
        settings: SettingsService | None = None,
        budget: BudgetService | None = None,
        waiting: Callable[[], Mapping[str, str]] | None = None,
        max_connections: int = MAX_WEB_CONNECTIONS,
        requests: Bucket | None = None,
        changes: Bucket | None = None,
    ) -> None:
        if isinstance(group, bool) or not isinstance(group, int) or group in _FORBIDDEN_GIDS:
            raise ControlError(
                f"el grupo {group} no puede usar el socket de la web (es de root, del agente o "
                "del proxy)"
            )
        super().__init__(
            guardian,
            path,
            peer=peer,
            max_connections=min(max_connections, MAX_CONNECTIONS),
            settings=settings,
            budget=budget,
            waiting=waiting,
        )
        self.socket_group = group
        # The web's own uid, when it is an account (the installed ``backtide-web``): then the
        # group alone is not enough, so a member of the group who switches to it (``sg``,
        # ``newgrp``) is refused too. Root may always ask (it has the control socket anyway).
        self._user = user
        self._list_snapshots = snapshots
        self._requests = requests or Bucket(REQUESTS_BURST, REQUESTS_PER_SECOND)
        self._changes = changes or Bucket(CHANGES_BURST, CHANGES_PER_SECOND)

    def refusal_for(self, pid: int, uid: int, gid: int) -> str | None:
        wrong_user = self._user is not None and uid not in (self._user, 0)
        if (
            uid in _FORBIDDEN_IDS
            or gid in _FORBIDDEN_GIDS
            or gid != self.socket_group
            or wrong_user
        ):
            logger.warning(
                "web socket: refused a connection from uid %d gid %d (pid %d): only the group "
                "%d may ask",
                uid,
                gid,
                pid,
                self.socket_group,
            )
            return "Solo la web de backtide (su grupo) puede pedir por aquí."
        return None

    def _handle(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        command = request.get("cmd")
        if not isinstance(command, str) or command not in COMMANDS:
            shown = command if isinstance(command, str) and command.isidentifier() else "?"
            logger.warning(
                "web socket: refused a command outside its list from uid %d (pid %d): %s",
                uid,
                pid,
                shown[:32],
            )
            raise _BadRequest("Esa orden no se acepta por el socket de la web.")
        if not self._requests.take():
            logger.warning("web socket: too many requests, one from pid %d was refused", pid)
            raise _BadRequest("Demasiadas peticiones seguidas: espera un poco.")
        if command in CHANGES:
            via = request.get("via", "web")
            if via != "web":
                logger.warning(
                    "web socket: refused a %s that said it came from %r (uid %d, pid %d)",
                    command,
                    str(via)[:16],
                    uid,
                    pid,
                )
                raise _BadRequest("Por aquí solo pide la web.")
            if not self._changes.take():
                logger.warning("web socket: too many changes, one from pid %d was refused", pid)
                raise _BadRequest("Demasiados cambios seguidos: espera un poco.")
            request["via"] = "web"
            self._warn_lasting(command, request, pid)
        if command == "snapshots":
            return self._snapshots(request)
        if command == "rewind":
            refused = self._unlisted(request)
            if refused is not None:
                return refused
        return super()._handle(request, pid, uid)

    @staticmethod
    def _warn_lasting(command: str, request: dict[str, Any], pid: int) -> None:
        """Changes that outlast the web (review of T12c, M1): who gets the alerts (Telegram) and
        a recipient trusted for good. A WARNING, which the log bridge records and sends over the
        alert channel there is NOW (a new Telegram only applies at the next restart), so the
        owner hears of it even if it was not them."""
        if command == "trust" or (
            command in ("set_secret", "clear_secret") and request.get("kind") == "telegram"
        ):
            logger.warning(
                "web socket: the web asked %s (pid %d); if it was not you, check Settings and "
                "the trusted recipients",
                "to trust a recipient" if command == "trust" else "to change Telegram",
                pid,
            )

    def _listed_ids(self) -> list[str] | None:
        try:
            return [snapshot.id for snapshot in self._list_snapshots()]
        except Exception as error:  # noqa: BLE001 - said, logged and refused: never a rewind
            logger.error("web socket: the snapshot list cannot be read: %s", type(error).__name__)
            return None

    def _snapshots(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista lleva `cmd` y nada más.")
        listed = self._listed_ids()
        if listed is None:
            return {"ok": False, "outcome": "failed", "snapshots": [],
                    "message": "No se ha podido leer la lista de instantáneas."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "message": "",
                "snapshots": listed[-MAX_LISTED_SNAPSHOTS:]}  # fmt: skip

    def _unlisted(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """A rewind to an id that is not in the volume's list now is answered here, with
        nothing asked of the Guardian. A request of the wrong shape goes on, to be refused by
        the control socket's own checks."""
        if set(request) != {"cmd", "snapshot_id", "via"}:
            return None
        snapshot_id = request["snapshot_id"]
        if not isinstance(snapshot_id, str) or Snapshot.parse(snapshot_id) is None:
            return None
        listed = self._listed_ids()
        if listed is not None and snapshot_id in listed:
            return None
        logger.warning("web socket: refused a rewind to a snapshot that is not in the list")
        message = (
            "No se puede leer la lista de instantáneas: no se ha hecho nada."
            if listed is None
            else "Esa instantánea no está en la lista del volumen: no se ha hecho nada."
        )
        return _reply_of(RewindOutcome(RewindStatus.INVALID, target="", message=message))


def ask_snapshots(
    path: Path,
    *,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[Snapshot]:
    """The volume's snapshots, oldest first, as the service at the narrow socket ``path`` lists
    them; anything that is not a snapshot id is dropped. ControlError if the reply makes no
    sense or the service could not list them."""
    raw = _ask(
        Path(path),
        {"cmd": "snapshots"},
        what="la lista",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        max_reply=MAX_LIST_REPLY_BYTES,
        server_uid=server_uid,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or not isinstance(reply.get("snapshots"), list):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("ok") is not True:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se ha podido listar.")
    found = []
    for item in reply["snapshots"][-MAX_LISTED_SNAPSHOTS:]:
        snapshot = Snapshot.parse(item) if isinstance(item, str) else None
        if snapshot is not None:
            found.append(snapshot)
    return found


def web_group_problem(gid: int) -> str | None:
    """Why ``gid`` cannot be the web's group, or None (for `backtide vigilar --grupo-web`)."""
    if gid in _FORBIDDEN_GIDS:
        return "es el de root, el del agente o el del proxy"
    return None


__all__ = [
    "CHANGES",
    "COMMANDS",
    "READS",
    "Bucket",
    "WebControlServer",
    "ask_snapshots",
    "web_group_problem",
]
