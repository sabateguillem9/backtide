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
- Who is signed in (T26-3a, docs/47 section 5.2): the service keeps the web's sessions
  (``backtide.service.sessions``). ``session_open`` trades the one-time link that root got
  (`sudo backtide enlace`, on the control socket) for a session; ``session_check`` says whether
  a cookie's session is live (and uses it); ``session_end`` ends one ("Salir") and
  ``session_end_all`` all of them, if asked from a live one. Every change carries the session
  of the person who asked (``session``) and is refused, with nothing called, without a live
  one: a web taken over cannot change anything on its own. A WARNING on every refusal; every
  new session and every "close them all" goes to the black box and is alerted, one by one
  (``on_entry``: ``Guardian.web_access``).
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
from backtide.service.sessions import Session, Sessions
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
# The sign-in (T26-3a): opening, checking and ending the web's sessions.
SESSION_COMMANDS = frozenset({"session_open", "session_check", "session_end", "session_end_all"})
COMMANDS = READS | CHANGES | SESSION_COMMANDS
# Every request: a burst of 120, then 20 a second (the panel's stream asks about once a second
# per open tab). The changes: a burst of 10, then one every 3 s (a person clicks).
REQUESTS_BURST, REQUESTS_PER_SECOND = 120, 20.0
CHANGES_BURST, CHANGES_PER_SECOND = 10, 1 / 3
# Every page and fragment checks its session: a bucket of their own, so the stream of an open
# tab never starves a click. Opening a session: a person, with a link, now and then.
CHECKS_BURST, CHECKS_PER_SECOND = 240, 40.0
OPENS_BURST, OPENS_PER_SECOND = 5, 1 / 6
# "Close them all": a bucket of its own, so a stream of made-up links cannot block it.
ENDS_BURST, ENDS_PER_SECOND = 5, 1 / 6
NO_SESSION = "Sin una sesión viva no se cambia nada: vuelve a entrar con `sudo backtide enlace`."
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
        sessions: Sessions | None = None,
        checks: Bucket | None = None,
        opens: Bucket | None = None,
        ends: Bucket | None = None,
        on_entry: Callable[[str, dict[str, Any]], bool] | None = None,
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
            sessions=sessions,
            on_entry=on_entry,
        )
        self.socket_group = group
        # The web's own uid, when it is an account (the installed ``backtide-web``): then the
        # group alone is not enough, so a member of the group who switches to it (``sg``,
        # ``newgrp``) is refused too. Root may always ask (it has the control socket anyway).
        self._user = user
        self._list_snapshots = snapshots
        self._requests = requests or Bucket(REQUESTS_BURST, REQUESTS_PER_SECOND)
        self._changes = changes or Bucket(CHANGES_BURST, CHANGES_PER_SECOND)
        self._checks = checks or Bucket(CHECKS_BURST, CHECKS_PER_SECOND)
        self._opens = opens or Bucket(OPENS_BURST, OPENS_PER_SECOND)
        self._ends = ends or Bucket(ENDS_BURST, ENDS_PER_SECOND)

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
        if command in SESSION_COMMANDS:
            return self._session_command(command, request, pid)
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
            self._signed_in(command, request, pid)
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

    def _signed_in(self, command: str, request: dict[str, Any], pid: int) -> Session:
        """The live session a change carries, taken out of the request (the control socket's
        own checks want exactly their keys); else a refusal, with nothing called."""
        given = request.pop("session", None)
        session = self._sessions.check(given) if self._sessions is not None else None
        if session is None:
            logger.warning("web socket: refused a %s without a live session (pid %d)", command, pid)
            raise _BadRequest(NO_SESSION)
        return session

    def _session_command(self, command: str, request: dict[str, Any], pid: int) -> dict[str, Any]:
        key = "token" if command == "session_open" else "session"
        allowed = {"cmd", key, "use"} if command == "session_check" else {"cmd", key}
        if not {"cmd", key} <= set(request) <= allowed or request.get("use", False) is not False:
            raise _BadRequest(f"Esa orden lleva `cmd` y `{key}`, y nada más.")
        buckets = {"session_open": self._opens, "session_end_all": self._ends}
        bucket = buckets.get(command, self._checks)
        if not bucket.take():
            logger.warning("web socket: too many %s, one from pid %d was refused", command, pid)
            raise _BadRequest("Demasiadas peticiones seguidas: espera un poco.")
        if self._sessions is None:
            raise _BadRequest("Este servicio no lleva sesiones de la web.")
        given = request[key]
        if command == "session_open":
            session = self._sessions.open(given)
            if session is None:
                logger.warning(
                    "web socket: refused a link that is wrong, spent or old (pid %d)", pid
                )
                return {"ok": False, "outcome": "refused", "message": "Ese enlace ya no vale."}
            if self._on_entry is None or not self._on_entry("web_session_opened", {"pid": pid}):
                # An entry that cannot be recorded is not granted: the cookie never leaves.
                self._sessions.end(session.id)
                logger.error("web socket: a web session could not be recorded and was refused")
                return {"ok": False, "outcome": "refused",
                        "message": "No se ha podido apuntar la entrada: no se entra."}  # fmt: skip
            logger.info(
                "web socket: a one-time link was used, a new web session started (pid %d)", pid
            )
            return {"ok": True, "outcome": "opened", "message": "",
                    "session": session.id, "csrf": session.csrf}  # fmt: skip
        if command == "session_check":
            session = self._sessions.check(given, use="use" not in request)
            if session is None:
                return {"ok": False, "outcome": "expired", "message": ""}
            return {"ok": True, "outcome": "live", "message": "", "csrf": session.csrf}
        if command == "session_end":
            ended = self._sessions.end(given)
            return {"ok": True, "outcome": "ended" if ended else "expired", "message": ""}
        if self._sessions.check(given) is None:  # session_end_all, from a live one only
            logger.warning("web socket: refused to close every session without a live one")
            raise _BadRequest(NO_SESSION)
        ended = self._sessions.end_all()
        logger.info("web socket: the web closed every session (%d) (pid %d)", ended, pid)
        if self._on_entry is not None:
            self._on_entry("web_sessions_closed", {"pid": pid, "ended": ended})
        return {"ok": True, "outcome": "ended", "message": "", "ended": ended}

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


def _ask_session(
    path: Path,
    request: dict[str, Any],
    *,
    server_uid: int,
    wait: float,
    peer: PeerCredentials,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    raw = _ask(
        Path(path),
        request,
        what="la sesión",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        server_uid=server_uid,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
        raise ControlError("La respuesta del servicio no es la esperada.")
    return reply


def _session_of(reply: dict[str, Any], session_id: str | None) -> Session | None:
    session_id = reply.get("session", session_id)
    csrf = reply.get("csrf")
    if reply["ok"] is not True or not isinstance(session_id, str) or not isinstance(csrf, str):
        return None
    return Session(session_id, csrf)


def ask_session_open(
    path: Path,
    token: str,
    *,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> Session | None:
    """A new session for the link's ``token`` (T26-3a), or None if the service refused it.
    ControlError if the service cannot be asked or its reply makes no sense."""
    reply = _ask_session(path, {"cmd": "session_open", "token": token}, server_uid=server_uid,
                         wait=wait, peer=peer, sleep=sleep, monotonic=monotonic)  # fmt: skip
    return _session_of(reply, None)


def ask_session_check(
    path: Path,
    session_id: str,
    *,
    use: bool = True,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> Session | None:
    """The live session with this id, or None; with ``use`` it counts as used (a page's own
    stream asks without it). ControlError as above."""
    request: dict[str, Any] = {"cmd": "session_check", "session": session_id}
    if not use:
        request["use"] = False
    reply = _ask_session(path, request,
                         server_uid=server_uid, wait=wait, peer=peer, sleep=sleep,
                         monotonic=monotonic)  # fmt: skip
    return _session_of(reply, session_id)


def ask_session_end(
    path: Path,
    session_id: str,
    *,
    every: bool = False,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """End this session ("Salir"), or, with ``every``, every session ("Cerrar todas", asked
    from this live one). The service's word: "ended", "expired" (it was not a live one) or
    "refused" (it did not do it, or would not say). ControlError if it cannot be asked."""
    command = "session_end_all" if every else "session_end"
    reply = _ask_session(path, {"cmd": command, "session": session_id}, server_uid=server_uid,
                         wait=wait, peer=peer, sleep=sleep, monotonic=monotonic)  # fmt: skip
    outcome = reply.get("outcome")
    if reply["ok"] is True and outcome in ("ended", "expired"):
        return str(outcome)
    return "refused"


def web_group_problem(gid: int) -> str | None:
    """Why ``gid`` cannot be the web's group, or None (for `backtide vigilar --grupo-web`)."""
    if gid in _FORBIDDEN_GIDS:
        return "es el de root, el del agente o el del proxy"
    return None


__all__ = [
    "CHANGES",
    "COMMANDS",
    "READS",
    "SESSION_COMMANDS",
    "Bucket",
    "WebControlServer",
    "ask_session_check",
    "ask_session_end",
    "ask_session_open",
    "ask_snapshots",
    "web_group_problem",
]
