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
- The keys (T26-3b-2, T26-3c, T26-3d): registering, listing and touching them, signing in, and
  ``key_remove`` and ``key_rename`` (``_manage_key``): by the whole id, with a key just touched,
  recorded first, and from here never the last key. Root's own ``passkey_remove``, by the end of
  an id and for any key, stays off this list.
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
from backtide.jail.identity import AGENT_ID_RANGE
from backtide.jail.proxy_config import PROXY_GID, PROXY_UID
from backtide.service.control import (
    LINK_CLOSED,
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
from backtide.service.passkeys import LAST_KEY, PasskeyError, Passkeys, describe, name_problem
from backtide.service.password import Checker, PasswordError, Verdict
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
SESSION_COMMANDS = frozenset(
    {"session_open", "session_password", "session_check", "session_end", "session_end_all"}
)
# The passkeys (T26-3b-2, T26-3c): each from a live session, which they carry.
PASSKEY_COMMANDS = frozenset(
    {
        "passkey_begin", "passkey_finish", "passkey_list",
        "touch_status", "touch_begin", "touch_finish",
        "key_remove", "key_rename",
    }
)  # fmt: skip
# Signing in with a passkey (T26-3c): nobody is signed in yet, and the service checks the signature.
SIGN_IN_COMMANDS = frozenset({"auth_begin", "auth_finish"})
COMMANDS = READS | CHANGES | SESSION_COMMANDS | PASSKEY_COMMANDS | SIGN_IN_COMMANDS
# What asks for the passkey touched a moment ago (docs/47 section 5.3), once there is one: it
# outlasts the session or decides who hears the alerts. Closing every session, and adding, taking
# out or naming a key too, in their own commands; creating agents (T26-6) and the terminal
# (T26-5d) will join.
TOUCH_CHANGES = frozenset({"set_secret", "clear_secret", "trust"})
# Every request: a burst of 120, then 20 a second (the panel's stream asks about once a second
# per open tab). The changes: a burst of 10, then one every 3 s (a person clicks).
REQUESTS_BURST, REQUESTS_PER_SECOND = 120, 20.0
CHANGES_BURST, CHANGES_PER_SECOND = 10, 1 / 3
# Every page and fragment checks its session: a bucket of their own, so the stream of an open
# tab never starves a click. Made-up cookies have another (T26-4a): behind a domain anyone can send
# them, and they must never empty the one of a session that lives. A wrong link spends its bucket
# the same way (a person, with a link, now and then), and the right one goes through whatever came.
CHECKS_BURST, CHECKS_PER_SECOND = 240, 40.0
MADE_UP_BURST, MADE_UP_PER_SECOND = 240, 40.0
OPENS_BURST, OPENS_PER_SECOND = 5, 1 / 6
# "Close them all": a bucket of its own, so a stream of made-up links cannot block it.
ENDS_BURST, ENDS_PER_SECOND = 5, 1 / 6
# Passwords: a bucket of their own (the Checker's own, slower one comes after), so a stream of
# them never empties the pages' checks nor the link's way in (review of T26-3b-1).
PASSWORDS_BURST, PASSWORDS_PER_SECOND = 10, 1.0
# The passkeys: a person registers one now and then (T26-3b-2). Registering two in a row and
# touching one in between, with their pages, takes about 15 at once (T26-3d).
KEYS_BURST, KEYS_PER_SECOND = 20, 1 / 3
# Signing in with one (docs/47 section 5.2): about 10 answers a minute for the whole web, whoever
# sends them, and its challenges apart, so that a stream of them leaves the answers alone.
AUTH_ANSWERS_BURST, AUTH_ANSWERS_PER_SECOND = 10, 1 / 6
AUTH_BEGINS_BURST, AUTH_BEGINS_PER_SECOND = 10, 1 / 3
PASSKEY_KEYS = {
    "passkey_begin": {"cmd", "session"},
    "passkey_list": {"cmd", "session"},
    "passkey_finish": {"cmd", "session", "answer", "name"},
    "touch_status": {"cmd", "session"},
    "touch_begin": {"cmd", "session"},
    "touch_finish": {"cmd", "session", "answer"},
    "key_remove": {"cmd", "session", "key"},
    "key_rename": {"cmd", "session", "key", "name"},
}
SIGN_IN_KEYS = {"auth_begin": {"cmd"}, "auth_finish": {"cmd", "answer"}}
PASSWORD_MESSAGES = {
    Verdict.WRONG: "Esa no es la contraseña.",
    Verdict.SLOW_DOWN: "Demasiados intentos seguidos: espera unos segundos.",
    Verdict.LOCKED: "Demasiadas contraseñas equivocadas: la entrada con contraseña está cerrada "
    "un rato. Para entrar ya, `sudo backtide enlace`.",
    Verdict.UNSET: "Aún no hay contraseña: ponla con `sudo backtide contraseña`, o entra con "
    "`sudo backtide enlace`.",
}
BUSY = "busy"  # a session_check past its bucket: nobody knows yet, and it is not "expired"
NO_SESSION = "Sin una sesión viva no se cambia nada: vuelve a entrar con `sudo backtide enlace`."
NEEDS_TOUCH = "Esto pide volver a tocar tu llave: tócala en la web y prueba otra vez."
FIRST_KEY_TOO_LATE = "La primera llave se registra nada más entrar: vuelve a entrar y regístrala."
MAX_LISTED_SNAPSHOTS = 5000
_FORBIDDEN_IDS = frozenset({AGENT_UID, PROXY_UID, *AGENT_ID_RANGE})
_FORBIDDEN_GIDS = frozenset({0, AGENT_GID, PROXY_GID, *AGENT_ID_RANGE})


class SessionCheckRefused(ControlError):
    """The service would not look at a session right now (its cap, or too many connections): it
    says nothing about that session, which may be alive (T26-4a)."""


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
        made_up: Bucket | None = None,
        opens: Bucket | None = None,
        ends: Bucket | None = None,
        passwords: Bucket | None = None,
        keys: Bucket | None = None,
        auth_answers: Bucket | None = None,
        auth_begins: Bucket | None = None,
        passkeys: Passkeys | None = None,
        on_entry: Callable[[str, dict[str, Any]], bool] | None = None,
        password: Checker | None = None,
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
            password=password,
            passkeys=passkeys,
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
        self._made_up = made_up or Bucket(MADE_UP_BURST, MADE_UP_PER_SECOND)
        self._opens = opens or Bucket(OPENS_BURST, OPENS_PER_SECOND)
        self._ends = ends or Bucket(ENDS_BURST, ENDS_PER_SECOND)
        self._passwords = passwords or Bucket(PASSWORDS_BURST, PASSWORDS_PER_SECOND)
        self._keys = keys or Bucket(KEYS_BURST, KEYS_PER_SECOND)
        self._auth_answers = auth_answers or Bucket(AUTH_ANSWERS_BURST, AUTH_ANSWERS_PER_SECOND)
        self._auth_begins = auth_begins or Bucket(AUTH_BEGINS_BURST, AUTH_BEGINS_PER_SECOND)

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
        if command in PASSKEY_COMMANDS:
            return self._passkey_command(command, request, pid)
        if command in SIGN_IN_COMMANDS:
            return self._sign_in_command(command, request, pid)
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
            session = self._signed_in(command, request, pid)
            if command in TOUCH_CHANGES and self._needs_touch(session.id):
                logger.warning(
                    "web socket: refused a %s without the passkey touched (pid %d)", command, pid
                )
                raise _BadRequest(NEEDS_TOUCH)
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
        key = {"session_open": "token", "session_password": "password"}.get(command, "session")
        allowed = {"cmd", key, "use"} if command == "session_check" else {"cmd", key}
        if not {"cmd", key} <= set(request) <= allowed or request.get("use", False) is not False:
            raise _BadRequest(f"Esa orden lleva `cmd` y `{key}`, y nada más.")
        # A session that lives and the right link are looked at first, so that nobody who only
        # makes them up can keep them out: looking costs a digest, and tells nothing of 256 bits.
        if command == "session_check":
            return self._session_check(request[key], "use" not in request, pid)
        buckets = {
            "session_end_all": self._ends,
            "session_password": self._passwords,
        }
        if command != "session_open" and not buckets.get(command, self._checks).take():
            logger.warning("web socket: too many %s, one from pid %d was refused", command, pid)
            raise _BadRequest("Demasiadas peticiones seguidas: espera un poco.")
        if self._sessions is None:
            raise _BadRequest("Este servicio no lleva sesiones de la web.")
        given = request[key]
        if command == "session_password":
            return self._password(given, pid)
        if command == "session_open":
            if self._link_closed():  # the link is left as it was, whatever it says
                logger.warning("web socket: refused a link behind a domain with keys (pid %d)", pid)
                return {"ok": False, "outcome": "refused", "message": LINK_CLOSED}
            session = self._sessions.open(given)
            if session is None:
                if not self._opens.take():
                    logger.warning(
                        "web socket: too many session_open, one from pid %d was refused", pid
                    )
                    raise _BadRequest("Demasiadas peticiones seguidas: espera un poco.")
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
        if command == "session_end":
            ended = self._sessions.end(given)
            return {"ok": True, "outcome": "ended" if ended else "expired", "message": ""}
        if self._sessions.check(given) is None:  # session_end_all, from a live one only
            logger.warning("web socket: refused to close every session without a live one")
            raise _BadRequest(NO_SESSION)
        if self._needs_touch(given):
            logger.warning(
                "web socket: refused to close every session without the passkey touched (pid %d)",
                pid,
            )
            raise _BadRequest(NEEDS_TOUCH)
        ended = self._sessions.end_all()
        logger.info("web socket: the web closed every session (%d) (pid %d)", ended, pid)
        if self._on_entry is not None:
            self._on_entry("web_sessions_closed", {"pid": pid, "ended": ended})
        return {"ok": True, "outcome": "ended", "message": "", "ended": ended}

    def _session_check(self, given: object, use: bool, pid: int) -> dict[str, Any]:
        """Does this cookie's session live? Each answer spends its own bucket (T26-4a), and past
        the cap the word is ``busy``, never ``expired``: the web then says 503, not "sign in"."""
        if self._sessions is None:
            raise _BadRequest("Este servicio no lleva sesiones de la web.")
        session = self._sessions.check(given, use=use)
        if not (self._made_up if session is None else self._checks).take():
            logger.warning("web socket: too many session_check, one from pid %d was refused", pid)
            return {"ok": False, "outcome": BUSY, "message": "Demasiadas comprobaciones seguidas."}
        if session is None:
            return {"ok": False, "outcome": "expired", "message": ""}
        return {"ok": True, "outcome": "live", "message": "", "csrf": session.csrf}

    def _passkey_command(self, command: str, request: dict[str, Any], pid: int) -> dict[str, Any]:
        """Register a passkey and list them (T26-3b-2): from a live session only; the service
        checks the browser's answer, the web only carries it. A key the black box does not take
        is taken out again (it fails closed)."""
        if set(request) != PASSKEY_KEYS[command]:
            raise _BadRequest("Esa orden de llaves no tiene la forma esperada.")
        if not self._keys.take():
            logger.warning("web socket: too many %s, one from pid %d was refused", command, pid)
            raise _BadRequest("Demasiadas peticiones seguidas: espera un poco.")
        if self._passkeys is None or self._sessions is None:
            raise _BadRequest("Este servicio no lleva llaves de la web.")
        session = self._sessions.check(request["session"])
        if session is None:
            logger.warning("web socket: refused a %s without a live session (pid %d)", command, pid)
            raise _BadRequest(NO_SESSION)
        if command in ("key_remove", "key_rename"):
            return self._manage_key(command, request, session.id, pid)
        if command in ("passkey_begin", "passkey_finish"):
            refusal = self._add_refusal(session.id)
            if refusal is not None:
                logger.warning("web socket: refused a %s (pid %d): %s", command, pid, refusal)
                return {"ok": False, "outcome": "refused", "message": refusal}
        try:
            if command == "passkey_list":
                # Their ids too: not secret (any `auth_begin` lists them), and how the page names
                # the key it wants changed.
                keys = [{**describe(key), "id": key.id} for key in self._passkeys.keys()]
                return {"ok": True, "outcome": "listed", "message": "", "keys": keys}
            if command == "touch_status":
                add = {None: "ok", NEEDS_TOUCH: "touch"}.get(self._add_refusal(session.id), "again")
                return {"ok": True, "outcome": "status", "message": "", "add": add,
                        "needs": self._needs_touch(session.id)}  # fmt: skip
            if command == "touch_begin":
                options = self._passkeys.touch_begin(session.id)
                return {"ok": True, "outcome": "options", "message": "", "options": options}
            if command == "touch_finish":
                key = self._passkeys.touch(session.id, request["answer"])
                # Recorded first: a touch opens five minutes of what lasts, and a web taken over
                # can ask for it with the owner's own finger (docs/47 section 5.2).
                if self._on_entry is None or not self._on_entry(
                    "web_passkey_touched", {"pid": pid, "name": key.name, "tail": key.tail}
                ):
                    logger.error("web socket: a touch could not be recorded and does not count")
                    return {"ok": False, "outcome": "refused",
                            "message": "No se ha podido apuntar el toque: no cuenta."}  # fmt: skip
                self._sessions.touch(session.id)
                logger.info("web socket: a passkey was touched again (pid %d)", pid)
                return {"ok": True, "outcome": "touched", "message": ""}
            if command == "passkey_begin":
                options = self._passkeys.begin(session.id)
                return {"ok": True, "outcome": "options", "message": "", "options": options}
            key = self._passkeys.verify(session.id, request["answer"], request["name"])
        except PasskeyError as error:
            logger.warning("web socket: a passkey was refused (pid %d): %s", pid, error)
            return {"ok": False, "outcome": "refused", "message": str(error)}
        # Recorded first, written after: a key never lives without its event (an event
        # without a key, if the write then fails, is the safe way to fail).
        if self._on_entry is None or not self._on_entry(
            "web_passkey_added", {"pid": pid, "name": key.name, "tail": key.tail}
        ):
            logger.error("web socket: a passkey could not be recorded and was not kept")
            return {"ok": False, "outcome": "refused",
                    "message": "No se ha podido apuntar la llave: no se ha guardado."}  # fmt: skip
        try:
            self._passkeys.keep(key)
        except PasskeyError as error:
            # The event says "added": the ERROR (recorded and alerted by the log bridge) says
            # which key was not kept after all.
            logger.error(
                "web socket: the passkey «%s» …%s was recorded but could not be kept: %s",
                key.name,
                key.tail,
                error,
            )
            return {"ok": False, "outcome": "refused", "message": str(error)}
        logger.info("web socket: a new passkey for the web (pid %d)", pid)
        return {"ok": True, "outcome": "added", "message": "", "key": describe(key)}

    def _manage_key(
        self, command: str, request: dict[str, Any], session_id: str, pid: int
    ) -> dict[str, Any]:
        """Take a key out or give it a new name (T26-3d, docs/47 sections 5.2 and 5.3): a key
        touched a moment ago, the key by its whole id, recorded first and not done if the black
        box does not take it. The last key does not go from here: without keys the table 5.3 asks
        for nothing, so a web taken over would keep what it took (`sudo backtide llaves --quitar`
        can). Taking one out ends every session, this one too: it may be in other hands, and so
        may a session opened with it."""

        def refused(outcome: str, message: str) -> dict[str, Any]:
            logger.warning("web socket: refused a %s (pid %d): %s", command, pid, message)
            return {"ok": False, "outcome": outcome, "message": message}

        if self._needs_touch(session_id):
            return refused("touch", NEEDS_TOUCH)
        try:
            kept = self._passkeys.keys()
        except PasskeyError as error:
            return refused("refused", str(error))
        key = next((k for k in kept if k.id == request["key"]), None)
        if key is None:
            return refused("missing", "Esa llave no está en la lista.")
        renaming = command == "key_rename"
        details: dict[str, Any] = {"pid": pid, "via": "web", "name": key.name, "tail": key.tail}
        if renaming:
            why = name_problem(request["name"])
            if why is not None:
                return refused("name", why)
            details |= {"name": request["name"], "was": key.name}
        elif len(kept) == 1:
            return refused("last", LAST_KEY)
        action = "web_passkey_renamed" if renaming else "web_passkey_removed"
        if self._on_entry is None or not self._on_entry(action, details):
            logger.error("web socket: a %s could not be recorded and was not done", command)
            return {"ok": False, "outcome": "refused",
                    "message": "No se ha podido apuntar el cambio: no se ha hecho."}  # fmt: skip
        try:
            if renaming:
                key = self._passkeys.rename(key.id, request["name"])
            elif not self._passkeys.remove(key.id, keep_one=True):
                raise PasskeyError("Esa llave no está en la lista.")
        except PasskeyError as error:
            # The event says it was done: the ERROR (recorded and alerted by the log bridge) says
            # which key it was not done to after all.
            logger.error(
                "web socket: %s on the passkey …%s was recorded but not done: %s",
                command,
                key.tail,
                error,
            )
            outcome = "last" if str(error) == LAST_KEY else "refused"
            return {"ok": False, "outcome": outcome, "message": str(error)}
        if renaming:
            logger.info("web socket: the passkey …%s has a new name (pid %d)", key.tail, pid)
            return {"ok": True, "outcome": "renamed", "message": "", "key": describe(key)}
        ended = self._sessions.end_all()
        logger.info("web socket: the passkey …%s was taken out (pid %d)", key.tail, pid)
        return {"ok": True, "outcome": "removed", "message": "", "ended": ended,
                "name": key.name, "tail": key.tail}  # fmt: skip

    def _needs_touch(self, session_id: object) -> bool:
        """Does this session have to touch a passkey first (docs/47 section 5.3)? Only once there
        is one: through the tunnel the password is enough without any (D40). Behind a domain,
        always: a session of root's link has the first key to register before anything else (D40,
        T26-4a). A file that cannot be read may hold keys: yes, and the owner hears of it."""
        if self._passkeys is None or self._sessions is None:
            return False
        try:
            kept = self._passkeys.keys()
        except PasskeyError as error:
            logger.error("web socket: the passkeys cannot be read: %s", error)
            return True
        needed = bool(kept) or self._passkeys.on_a_domain
        return needed and not self._sessions.recently_touched(session_id)

    def _add_refusal(self, session_id: str) -> str | None:
        """Why this session may not add a key, or None: with keys, it touches one; the first
        one, right after entering (review of T26-3b-2: whoever adds a key stays inside, even
        after "Cerrar todas" and a new password). Asked at both ends of a registration: two
        sessions may have started before the first key was kept."""
        if self._passkeys is None or self._sessions is None:
            return "Este servicio no lleva llaves de la web."
        try:
            kept = self._passkeys.keys()
        except PasskeyError as error:
            return str(error)
        if kept:
            return None if self._sessions.recently_touched(session_id) else NEEDS_TOUCH
        return None if self._sessions.recently_opened(session_id) else FIRST_KEY_TOO_LATE

    def _sign_in_command(self, command: str, request: dict[str, Any], pid: int) -> dict[str, Any]:
        """Signing in with a passkey (T26-3c): the service makes the challenge and checks the
        signature, and a session only comes out of a right one, recorded first. Every refusal
        is a WARNING: the log bridge records it and alerts."""
        if set(request) != SIGN_IN_KEYS[command]:
            raise _BadRequest("Esa orden de entrada no tiene la forma esperada.")
        bucket = self._auth_begins if command == "auth_begin" else self._auth_answers
        if not bucket.take():
            logger.warning("web socket: too many %s, one from pid %d was refused", command, pid)
            raise _BadRequest("Demasiados intentos seguidos: espera un poco.")
        if self._passkeys is None or self._sessions is None:
            raise _BadRequest("Este servicio no lleva llaves de la web.")
        try:
            if command == "auth_begin":
                options = self._passkeys.sign_in_begin()
                return {"ok": True, "outcome": "options", "message": "", "options": options}
            key = self._passkeys.sign_in(request["answer"])
        except PasskeyError as error:
            logger.warning("web socket: a passkey did not sign in (pid %d): %s", pid, error)
            return {"ok": False, "outcome": "refused", "message": str(error)}
        session = self._sessions.start(touched=True)
        if self._on_entry is None or not self._on_entry(
            "web_session_opened", {"pid": pid, "via": "passkey", "name": key.name, "tail": key.tail}
        ):
            self._sessions.end(session.id)
            logger.error("web socket: a web session could not be recorded and was refused")
            return {"ok": False, "outcome": "refused",
                    "message": "No se ha podido apuntar la entrada: no se entra."}  # fmt: skip
        logger.info("web socket: a passkey signed in, a new web session (pid %d)", pid)
        return {"ok": True, "outcome": "opened", "message": "",
                "session": session.id, "csrf": session.csrf}  # fmt: skip

    def _password(self, given: object, pid: int) -> dict[str, Any]:
        """The web's password (T26-3b-1): the service checks it (a scrypt hash, a bucket for the
        whole web, a lock after many failures) and, if right, gives a new session. Never logged,
        never in a reply."""
        if self._password_checker is None or self._sessions is None:
            raise _BadRequest("Este servicio no lleva contraseña de la web.")
        try:
            verdict = self._password_checker.check(given)
        except PasswordError as error:
            # The file changed hands (an owner, a mode, a link): nobody gets in by it, and the
            # owner hears of it (an ERROR: the log bridge records it and alerts).
            logger.error("web socket: the web's password file cannot be used: %s", error)
            return {"ok": False, "outcome": "refused",
                    "message": "La contraseña no se puede comprobar ahora."}  # fmt: skip
        finally:
            del given
        if verdict is Verdict.RIGHT:
            session = self._sessions.start()
            if self._on_entry is None or not self._on_entry(
                "web_session_opened", {"pid": pid, "via": "password"}
            ):
                self._sessions.end(session.id)
                logger.error("web socket: a web session could not be recorded and was refused")
                return {"ok": False, "outcome": "refused",
                        "message": "No se ha podido apuntar la entrada: no se entra."}  # fmt: skip
            logger.info("web socket: the right password, a new web session (pid %d)", pid)
            return {"ok": True, "outcome": "opened", "message": "",
                    "session": session.id, "csrf": session.csrf}  # fmt: skip
        if verdict is Verdict.LOCKING and self._on_entry is not None:
            self._on_entry("web_password_locked", {"pid": pid})
        if verdict in (Verdict.WRONG, Verdict.LOCKING):
            logger.warning("web socket: a wrong password for the web (pid %d)", pid)
        outcome = Verdict.LOCKED if verdict is Verdict.LOCKING else verdict
        return {"ok": False, "outcome": str(outcome), "message": PASSWORD_MESSAGES[outcome]}

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


def ask_session_password(
    path: Path,
    password: str,
    *,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[Session | None, str]:
    """A new session for the web's password (T26-3b-1), and the service's word: "opened",
    "wrong", "slow_down", "locked", "unset" or "refused". ControlError if it cannot be asked.
    The password is in the request only, never in an error."""
    request: dict[str, Any] = {"cmd": "session_password", "password": password}
    try:
        reply = _ask_session(path, request, server_uid=server_uid, wait=wait, peer=peer,
                             sleep=sleep, monotonic=monotonic)  # fmt: skip
    finally:
        request.clear()
    outcome = reply.get("outcome")
    return _session_of(reply, None), outcome if isinstance(outcome, str) else "refused"


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
    """The live session with this id, or None if the service says it is not one; with ``use`` it
    counts as used (a page's own stream asks without it). SessionCheckRefused if it would not
    look (past a cap, or too many connections: T26-4a); ControlError as above."""
    request: dict[str, Any] = {"cmd": "session_check", "session": session_id}
    if not use:
        request["use"] = False
    reply = _ask_session(path, request,
                         server_uid=server_uid, wait=wait, peer=peer, sleep=sleep,
                         monotonic=monotonic)  # fmt: skip
    if reply["ok"] is not True and reply.get("outcome") != "expired":
        raise SessionCheckRefused("El servicio no ha mirado esa sesión.")
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


def ask_passkey(
    path: Path,
    command: str,
    session_id: str,
    *,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    **fields: str,
) -> dict[str, Any]:
    """One of the passkeys' commands (T26-3b-2) for this session: the service's reply, checked
    to be a dict with ``ok``. ValueError for a command that is not one (nothing sent)."""
    if command not in PASSKEY_COMMANDS:
        raise ValueError("not a passkey command")
    request: dict[str, Any] = {"cmd": command, "session": session_id, **fields}
    return _ask_session(path, request, server_uid=server_uid, wait=wait, peer=peer,
                        sleep=sleep, monotonic=monotonic)  # fmt: skip


def ask_auth(
    path: Path,
    command: str,
    *,
    server_uid: int = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    **fields: str,
) -> dict[str, Any]:
    """Signing in with a passkey (T26-3c): the service's reply, checked to be a dict with ``ok``.
    ValueError for a command that is not one (nothing sent)."""
    if command not in SIGN_IN_COMMANDS:
        raise ValueError("not a sign-in command")
    return _ask_session(path, {"cmd": command, **fields}, server_uid=server_uid, wait=wait,
                        peer=peer, sleep=sleep, monotonic=monotonic)  # fmt: skip


def web_group_problem(gid: int) -> str | None:
    """Why ``gid`` cannot be the web's group, or None (for `backtide vigilar --grupo-web`)."""
    if gid in _FORBIDDEN_GIDS:
        return "es el de root, el del agente o el del proxy"
    return None


__all__ = [
    "CHANGES",
    "COMMANDS",
    "READS",
    "PASSKEY_COMMANDS",
    "SESSION_COMMANDS",
    "SIGN_IN_COMMANDS",
    "TOUCH_CHANGES",
    "Bucket",
    "SessionCheckRefused",
    "WebControlServer",
    "ask_auth",
    "ask_passkey",
    "ask_session_check",
    "ask_session_end",
    "ask_session_open",
    "ask_session_password",
    "ask_snapshots",
    "web_group_problem",
]
