"""The control socket: how `backtide rebobinar` asks a running service to rewind, how
`backtide seguir` asks it to resume after a pause by space (T04d-2), and how `backtide aprobar`,
`backtide rechazar` and `backtide retenidas` decide on the held requests (T10-2).

Design: docs/19-diseno-t04.md, sections 4 ("El socket de control") and "La CLI".

While `backtide vigilar` runs it owns the agent and holds ``backtide.lock``, so a second process
must never rewind on its own: it asks the service, which serialises the request with everything
else through ``agent_lock`` (inside ``Guardian.rewind``).

The server (inside the service):
- ``<state_dir>/control.sock``, mode 0600, in backtide's private state folder. It is never in the
  volume and never mounted into the agent (invariant 1). It is created after the service is up
  (``Guardian.run`` starts it), so "the lock is taken and there is no socket yet" means "the
  service is starting".
- Only the service's own user may talk to it: ``SO_PEERCRED`` is read on every connection and
  another uid gets a refusal before a byte of its request is read. Fails closed: if the
  credentials cannot be read, the connection is refused.
- One JSON object per connection, on one line, at most 4 KiB, and 5 s to send it (a total
  deadline, not per read: a client that sends a byte every 4 s does not get more time):
  ``{"cmd": "rewind", "snapshot_id": ...}`` (plus ``"via": "web"`` from `backtide web`, T12b),
  ``{"cmd": "resume"}``, ``{"cmd": "decide", "hold_id": ..., "verdict": "approve" | "reject"}``
  (plus ``via``; docs/32 section 11) or ``{"cmd": "holds"}``, with exactly those keys. The
  agent never reaches this socket (invariant 1), so it cannot approve its own requests.
  The Settings page (T12e, ``backtide.service.settings``): ``{"cmd": "secrets"}`` (what is set,
  with the last four characters at most), ``{"cmd": "set_secret", "kind": ..., "value": ...}``
  (plus ``chat_id`` for ``telegram``, and ``via``) and ``{"cmd": "clear_secret", "kind": ...}``
  (plus ``via``). A value is checked and written by the service; it is never logged, never put
  in a refusal and never sent back.
  The spending cap (T11, ``backtide.service.spend``): ``{"cmd": "budget"}`` (today's and this
  month's spending, the caps and the prices' date: no secret) and ``{"cmd": "set_budget",
  "daily_usd": ..., "monthly_usd": ...}`` (either may be left out; plus ``via``: ``cli`` or
  ``web``), recorded by the service before it changes anything; ``{"cmd": "accept_prices",
  "digest": ...}`` (plus ``via``) accepts the new prices the page offered that wait for the owner
  (security review of T11, B3), only those whose digest the page showed.
  The web's holds page (T10-5, docs/32 section 11 and decision 9): ``{"cmd": "trust",
  "hold_id": ..., "via": "web"}`` ("aprobar y confiar en este destinatario": only ``web``),
  ``{"cmd": "untrust", "trust_id": ...}`` and ``{"cmd": "end_batch", "rule_id": ...}`` (plus
  ``via``: ``cli`` or ``web``), and the lists ``{"cmd": "trusted"}`` and ``{"cmd": "batches"}``.
  The shell mode (T17a-4, docs/34 section 7, ``backtide.service.shell``): ``{"cmd": "shell",
  "kind": "session" | "task", "continue": bool}`` (`backtide entrar` and `tarea`: recorded, and
  the container, user and folder for ``docker exec`` come back; a task may add ``"prompt"``, at
  most 200 characters, recorded struck), ``{"cmd": "import", "name":
  ..., "source": ..., "files": ..., "bytes": ..., "replace": bool}`` (`backtide importar`, the
  same with the import's counts recorded) and ``{"cmd": "export", "dest": ...}`` (`backtide
  exportar`: the service copies the agent's work folder into the owner's new folder).
  Anything else (too big, slow, not UTF-8, not JSON, unknown command, extra keys, an id that is
  not a snapshot id) is refused WITHOUT calling the Guardian.
  Which agent (T26-2c, ``backtide.service.roster``): what is an agent's (``AGENT_COMMANDS``) may
  carry ``"agent": <slug>``; without it, it is about the main agent. A name that is nobody's is
  refused with no agent touched, and what is the machine's (keys, sessions, passkeys) does not take
  the field. ``{"cmd": "agents"}`` lists them. A new cap with no ``agent`` is the whole
  installation's, which with one agent is that agent's.
  The installed web, which is not the service's user, gets a second socket of its own with a
  closed subset of these commands (``backtide.service.web_control``, T12c): ``WebControlServer``
  reuses this class, with its own peer check (``refusal_for``) and socket mode and group.
- One thread per connection (``socketserver``), at most ``MAX_CONNECTIONS`` at a time, so a
  client that connects and says nothing blocks nobody. A rewind runs on its connection's thread;
  if the client goes away the rewind still finishes (it is the person's safety action), and the
  reply that cannot be delivered is logged.
- The reply never carries the agent's text: it is ``RewindOutcome.message`` (which the Guardian
  keeps free of it) after ``redact``.

The client (``ask_rewind``, ``ask_resume``): checks that the path is a real socket of ours
before connecting (a symbolic link is refused: it could lead to somebody else's server), checks
with ``SO_PEERCRED`` that the server runs as our user before sending anything, retries while the
service is starting, and treats whatever comes back as data.
"""

import errno
import json
import logging
import os
import re
import socket
import socketserver
import stat
import struct
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from backtide.blackbox import redact
from backtide.jail import identity
from backtide.jail.profile import MAX_PROMPT, check_prompt
from backtide.service.holds import (
    BATCH_ID_RE,
    HOLD_ID_RE,
    HoldOutcome,
    HoldStatus,
    TrustOutcome,
    TrustStatus,
)
from backtide.service.password import Checker, PasswordError

if TYPE_CHECKING:
    from backtide.service.passkeys import Passkeys  # webauthn: not for every `backtide` command
from backtide.service.pause import RESUME_EXIT_CODES, PauseStatus, ResumeOutcome, ResumeStatus
from backtide.service.rewind import EXIT_CODES, RewindOutcome, RewindStatus
from backtide.service.roster import AgentRefused, Desk, OrderInvalid, Roster
from backtide.service.sessions import Sessions
from backtide.service.settings import KINDS as SECRET_KINDS
from backtide.service.settings import TELEGRAM as SECRET_TELEGRAM
from backtide.service.settings import Applied, Outcome, SettingsOutcome
from backtide.service.shell import (
    REPO_RE,
    ExportOutcome,
    ExportStatus,
    ShellOutcome,
    ShellStatus,
)
from backtide.service.spend import CAP_SHAPE, CapOutcome, check_cap
from backtide.service.tasks import (
    MAX_TASK_SECONDS,
    TASK_MAX_OUTPUT,
    TaskOutcome,
    TaskStart,
    TaskStatus,
)
from backtide.service.trust import TRUST_ID_RE
from backtide.snapshots import Snapshot

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 4096
REQUEST_TIMEOUT = 5.0  # seconds, in total, to receive a request
REPLY_TIMEOUT = 5.0  # seconds to hand the reply to a client that does not read it
MAX_CONNECTIONS = 8
DRAIN_SECONDS = 1.0  # after replying, read what is left so the reply is not lost to a reset
DRAIN_BYTES = 1 << 20
WAIT_FOR_SERVICE = 10.0  # `backtide rebobinar`: how long to retry while the service starts
RETRY_EVERY = 0.25
CLIENT_REPLY_TIMEOUT = 15 * 60.0  # a rewind takes seconds; this only ends a dead service
MAX_REPLY_BYTES = 64 * 1024
_CREDENTIALS = struct.Struct("iII")  # struct ucred: pid, uid, gid

# What "outcome" can say. The rewind statuses, and "refused" for a request that was not served.
REFUSED = "refused"
OUTCOMES = frozenset({*(str(status) for status in RewindStatus), REFUSED})
RESUME_OUTCOMES = frozenset({*(str(status) for status in ResumeStatus), REFUSED})
# The exit code of `backtide rebobinar` and `backtide seguir` for each outcome (docs/19, "La
# CLI"): a refused request did nothing and was malformed or not allowed, which is a usage error
# like an invalid id. The two commands share "failed" (1) and "problem" (3).
OUTCOME_EXIT_CODES = {
    **{str(status): code for status, code in RESUME_EXIT_CODES.items()},
    **{str(status): code for status, code in EXIT_CODES.items()},
    REFUSED: EXIT_CODES[RewindStatus.INVALID],
}
_RESUME_OK = frozenset({ResumeStatus.RESUMED, ResumeStatus.NOT_PAUSED})
# Where a rewind request may say it comes from (T12b). A label for the black box, from a fixed
# set: any process of the allowed user could claim either, and the uid and pid recorded next to
# it are the kernel's. "cli" is what a request without ``via`` means.
REQUESTERS = frozenset({"cli", "web", "telegram"})  # "telegram": the bot in the service (T09)
DECIDE_VERDICTS = frozenset({"approve", "reject"})
_DECIDED = frozenset({HoldStatus.RELEASED, HoldStatus.PREAPPROVED, HoldStatus.REJECTED})
HOLD_OUTCOMES = frozenset({*(str(status) for status in HoldStatus), REFUSED})
# `backtide aprobar` / `rechazar`: 0 decided; 1 not done (no such hold, not recorded, or the agent
# is paused); 2 a request that was refused (malformed or not allowed), like an invalid id.
HOLD_EXIT_CODES = {
    **{str(status): 0 for status in _DECIDED},
    str(HoldStatus.UNKNOWN): 1,
    str(HoldStatus.FAILED): 1,
    str(HoldStatus.PAUSED): 1,
    REFUSED: 2,
}
MAX_LISTED_HOLDS = 100
# T10-5: the web lists the holds with what it shows of each (``ProxyChannel._web_fields``), the
# batches and the trusted recipients. Lists may be bigger than a decision's reply.
MAX_LIST_REPLY_BYTES = 1024 * 1024
# "Aprobar y confiar" only from the web (decision 9); removing a trusted recipient or revoking a
# batch, from the web or the terminal (the bot revokes in its own process, T10-4).
TRUST_REQUESTERS = frozenset({"web"})
UNTRUST_REQUESTERS = frozenset({"cli", "web"})
TRUST_OUTCOMES = frozenset({*(str(status) for status in TrustStatus), REFUSED})
LIST_OUTCOMES = frozenset({"removed", "ended", "unknown", "failed", REFUSED})
# The Settings page (T12e): who may ask (not the bot: a key is never set from a chat), what a
# change can answer, and how long a value may be (the service checks its shape).
SETTINGS_REQUESTERS = frozenset({"cli", "web"})
SETTINGS_OUTCOMES = frozenset({*(str(status) for status in Outcome), REFUSED})
APPLIED = frozenset(str(applied) for applied in Applied)
MAX_SECRET_CHARS = 256
# The shell mode (T17a-4): what `backtide entrar` and `importar` may say. A task is not on this
# list since T26-5a: the service runs it (`task_start`), so there is nothing to open for the CLI.
SHELL_REQUEST_KINDS = frozenset({"session", "bundle"})
SHELL_OUTCOMES = frozenset({*(str(status) for status in ShellStatus), REFUSED})
EXPORT_OUTCOMES = frozenset({*(str(status) for status in ExportStatus), REFUSED})
IMPORT_KEYS = frozenset(
    {"name", "source", "files", "bytes", "replace", "secrets_left_out", "include_secrets"}
)
MAX_IMPORT_TEXT = 1024
# What a ready reply may name for docker exec: a container, uid:gid, a folder of /workspace.
_CONTAINER_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
_USER_RE = re.compile(r"[0-9]{1,10}:[0-9]{1,10}", re.ASCII)
_WORKDIR_RE = re.compile(r"/workspace(?:/(?!\.\.?(?:/|$))[A-Za-z0-9._-]+)*", re.ASCII)
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
MAX_SKIPPED_NAMES = 20
MAX_SKIPPED_TEXT = 300
# The tasks (T26-5a, backtide/service/tasks.py). The one request that may pass MAX_REQUEST_BYTES:
# it starts like this, as the clients here write it, and carries a prompt of up to MAX_PROMPT
# characters, each up to 12 bytes in JSON. Its reply, an answer: 6 bytes per byte in the worst case.
TASK_REQUEST_START = b'{"cmd": "task_start", '
MAX_TASK_REQUEST_BYTES = 12 * MAX_PROMPT + MAX_REQUEST_BYTES
MAX_TASK_REPLY_BYTES = 6 * TASK_MAX_OUTPUT + MAX_REPLY_BYTES
TASK_REQUESTERS = frozenset({"cli", "web"})
TASK_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
TASK_UNKNOWN = "unknown"
TASK_UNKNOWN_MESSAGE = (
    "Este servicio no conoce esa tarea: las respuestas viven en memoria, se pierden al reiniciar "
    "y solo se guardan las últimas."
)
TASK_START_OUTCOMES = frozenset({"started", REFUSED})
TASK_STATUS_OUTCOMES = frozenset(
    {*(str(outcome) for outcome in TaskOutcome), TASK_UNKNOWN, REFUSED}
)
TASK_STOP_OUTCOMES = frozenset({"stopped", "failed", TASK_UNKNOWN, REFUSED})
MAX_NOTICE_LINES, MAX_NOTICE_LINE = 8, 600  # what `agents` carries of an agent's rewind notice
TASK_STOP_REPLY_TIMEOUT = 2 * 60.0  # up to three ``pkill`` of 30 s each, inside the agent
MAX_LISTED_SNAPSHOTS = 5000
# What is one agent's, and so may say which (T26-2c). The rest is the machine's: a key, a session,
# a passkey, the web's password; each of those refuses a field it does not know.
AGENT_COMMANDS = frozenset(
    {
        "rewind", "resume", "decide", "holds", "trust", "untrust", "end_batch", "trusted",
        "batches", "shell", "import", "task_start", "task_status", "task_stop", "export",
        "budget", "set_budget", "accept_prices", "snapshots", "agent_pause", "agent_resume",
    }
)  # fmt: skip
# Which agents there are (T26-6a, ``backtide.service.fleet``): the service's, on this socket only.
FLEET_COMMANDS = frozenset(
    {"agent_create", "agent_start", "agent_stop", "agent_delete", "agent_restore", "agent_purge"}
)
AGENT_ORDER_REPLY_TIMEOUT = 300.0  # an agent's start: its checks and its first snapshot
DELETED_KEYS = ("slug", "name", "state", "deleted_at", "purge_after", "purged")
AGENT_WORDS = ("kind", "version", "in_use", "order")  # what the list says of an agent: D42, T26-6b
_AGENT_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}", re.ASCII)


class ControlError(Exception):
    """The control socket cannot be opened (server) or cannot be trusted (client). The message
    is for the user, in Spanish."""


class ControlUnavailable(ControlError):
    """Nobody answers at the socket (it does not exist, or refuses connections)."""


class ControlOutcomeUnknown(ControlError):
    """The request was sent but no usable reply came back: the rewind may have been done."""


class RewindService(Protocol):
    """What the server needs from the Guardian."""

    def rewind(self, snapshot_id: str, *, requested_by: str) -> RewindOutcome: ...

    def resume(self, *, requested_by: str) -> ResumeOutcome: ...

    def decide_hold(
        self, hold_id: str, verdict: str, *, via: str, requested_by: str
    ) -> HoldOutcome: ...

    def pending_holds(self) -> list[dict[str, Any]]: ...

    def trust_hold(self, hold_id: str, *, via: str, requested_by: str) -> TrustOutcome: ...

    def trusted(self) -> list[dict[str, Any]]: ...

    def untrust(self, trust_id: str, *, via: str, requested_by: str) -> bool | None: ...

    def batches(self) -> list[dict[str, Any]]: ...

    def end_batch(self, rule_id: str, *, via: str) -> bool: ...

    def open_shell(
        self,
        kind: str,
        *,
        resume: bool = False,
        requested_by: str,
        details: dict[str, Any] | None = None,
    ) -> ShellOutcome: ...

    def task_start(
        self, prompt: str, *, resume: bool = False, seconds: int | None = None, requested_by: str
    ) -> TaskStart: ...

    def task_status(self, task_id: str) -> TaskStatus | None: ...

    def task_stop(self, task_id: str) -> bool | None: ...

    def export(
        self,
        destination: str,
        *,
        requested_by: str,
        bundle: str | None = None,
        repo: str | None = None,
        include_config: bool = False,
    ) -> ExportOutcome: ...


class FleetOrders(Protocol):
    """What the control socket calls for ``FLEET_COMMANDS`` (``backtide.service.fleet.Fleet``).
    Each may raise ``OrderInvalid``, with nothing touched."""

    def create(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...

    def start(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...

    def stop(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...

    def delete(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...

    def restore(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...

    def purge(self, request: Mapping[str, Any], requested_by: str) -> dict[str, Any]: ...


class SettingsService(Protocol):
    """What the server needs for the Settings page (``backtide.service.settings.Settings``)."""

    def status(self) -> dict[str, dict[str, Any]]: ...

    def set_secret(
        self, kind: str, value: str, *, chat_id: str = "", requested_by: str
    ) -> SettingsOutcome: ...

    def clear_secret(self, kind: str, *, requested_by: str) -> SettingsOutcome: ...


class BudgetService(Protocol):
    """What the server needs for the spending cap (``backtide.service.spend.Budget``)."""

    def status(self) -> dict[str, Any]: ...

    def set_caps(
        self, daily: Decimal | None, monthly: Decimal | None, *, requested_by: str
    ) -> CapOutcome: ...


class WholeBudget(Protocol):
    """The cap of the whole installation (``backtide.service.spend_total.InstallationSpend``)."""

    def set_caps(
        self, daily: Decimal | None, monthly: Decimal | None, *, requested_by: str
    ) -> CapOutcome: ...


BUDGET_OUTCOMES = frozenset({"saved", "invalid", "failed", REFUSED})

PeerCredentials = Callable[[socket.socket], tuple[int, int, int]]


def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """``(pid, uid, gid)`` of the process at the other end of a Unix socket, as the kernel
    recorded them when it connected (``SO_PEERCRED``; Linux only, which is where backtide runs).
    Raises ControlError where the option does not exist: callers fail closed."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ControlError("este sistema no ofrece SO_PEERCRED: no se puede saber quién llama")
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, option, _CREDENTIALS.size)
    except OSError as error:
        raise ControlError(f"no se pueden leer las credenciales del otro lado: {error}") from error
    pid, uid, gid = _CREDENTIALS.unpack(raw)
    return pid, uid, gid


LINK_CLOSED = (
    "Por el dominio, con llaves registradas, se entra con la llave: el enlace no vale. Si las has "
    "perdido, `sudo backtide llaves --quitar <id>` y luego `sudo backtide enlace`."
)


class _BadRequest(Exception):
    """A request the server refuses without calling the Guardian. Carries the reply text."""


class ControlServer:
    """The socket of the service. ``start()`` binds it and answers in a thread of its own;
    ``close()`` stops accepting, waits for the requests in flight (a rewind finishes and is
    answered) and removes the socket file.

    ``allowed_uid`` is the one user it serves (the service's own, by default). ``peer`` reads the
    credentials of a connection and is replaceable so a test can play another user.

    ``socket_mode`` and ``socket_group`` are what the socket file is left with: 0600 and the
    service's own group here; the web's narrow socket (``backtide.service.web_control``, T12c)
    is 0660 with the web's group, and decides who it serves in ``refusal_for``."""

    socket_mode = 0o600
    socket_group: int | None = None
    label = "control socket"  # how the log names it (the web's narrow socket: "web socket")
    asks_as = "cli"  # who the box says asked an order about the agents (the narrow socket: "web")

    def __init__(
        self,
        guardian: RewindService,
        path: Path,
        *,
        allowed_uid: int | None = None,
        peer: PeerCredentials = peer_credentials,
        request_timeout: float = REQUEST_TIMEOUT,
        max_connections: int = MAX_CONNECTIONS,
        settings: SettingsService | None = None,
        budget: BudgetService | None = None,
        waiting: Callable[[], Mapping[str, str]] | None = None,
        sessions: Sessions | None = None,
        on_entry: Callable[[str, dict[str, Any]], bool] | None = None,
        password: Checker | None = None,
        passkeys: "Passkeys | None" = None,
        snapshots: Callable[[], Sequence[Snapshot]] | None = None,
        roster: Roster | None = None,
        whole_budget: WholeBudget | None = None,
        fleet: FleetOrders | None = None,
    ) -> None:
        self._fleet = fleet
        if sessions is not None and on_entry is None:
            # Never a way into the web that leaves no trace (review of T26-3a).
            raise ControlError("las sesiones de la web necesitan dónde apuntar cada entrada")
        # Who an order is about (T26-2c): with one agent, the one handed in here. With several,
        # the service hands in a Roster that both sockets share.
        self._roster = roster or Roster(
            Desk(identity.MAIN_SLUG, guardian, budget, waiting, snapshots)
        )
        # The cap of the whole installation, when there are several agents to add up.
        self._whole_budget = whole_budget
        # The web's sign-in (T26-3a): root asks here for a one-time link (`sudo backtide
        # enlace`); the web's narrow socket opens and checks the sessions it gives. Every link
        # given and every session opened goes to ``on_entry`` (``Guardian.web_access``: the black
        # box and an alert, one by one), never through the log bridge alone, which lets one
        # message of a kind by per minute.
        self._sessions = sessions
        self._on_entry = on_entry
        # The web's password (T26-3b-1): checked on the narrow socket, set here by root.
        self._password_checker = password
        # The web's passkeys (T26-3c): root lists and takes them out here (`sudo backtide llaves`).
        self._passkeys = passkeys
        self._settings = settings
        self._path = Path(path)
        self._allowed_uid = allowed_uid if allowed_uid is not None else os.geteuid()
        self._peer = peer
        self._request_timeout = request_timeout
        self._max_connections = max_connections
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._identity: tuple[int, int] | None = None  # (st_dev, st_ino) of our socket file
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> None:
        """Bind and listen. Raises ControlError, with nothing left behind, if the path holds
        something that is not a stale socket of ours, or the socket cannot be made."""
        with self._lock:
            if self._server is not None:
                raise ControlError("el socket de control ya está abierto")
            server = _Server(self, self._path)
            try:
                self._identity = server.bind_checked()
                server.server_activate()
            except BaseException:
                self._remove_socket_file()
                server.server_close()
                raise
            thread = threading.Thread(target=self._serve, args=(server,), name="backtide-control")
            self._server, self._thread = server, thread
            thread.start()

    def _serve(self, server: "_Server") -> None:
        try:
            server.serve_forever(poll_interval=0.05)
        except Exception:  # nothing is silent: the log reaches the black box
            logger.exception("the control socket stopped answering")
            # Close the listener, so a client is refused at once instead of queueing for 15 min.
            server.socket.close()

    def close(self) -> None:
        """Stop accepting, wait for the requests in flight, remove the socket file. Idempotent."""
        with self._lock:
            server, thread = self._server, self._thread
            self._server = self._thread = None
        if server is None or thread is None:
            return
        server.shutdown()  # ends serve_forever
        thread.join()
        server.server_close()  # waits for the connection threads
        self._remove_socket_file()

    def _remove_socket_file(self) -> None:
        """Remove ``control.sock`` only if it is still the socket this server made."""
        identity, self._identity = self._identity, None
        if identity is None:
            return
        try:
            info = os.lstat(self._path)
        except FileNotFoundError:
            return
        except OSError as error:
            logger.error("cannot look at the control socket %s to remove it: %s", self._path, error)
            return
        if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            logger.warning("%s is no longer the socket this service made: left alone", self._path)
            return
        try:
            os.unlink(self._path)
        except OSError as error:
            logger.error("cannot remove the control socket %s: %s", self._path, error)

    # One connection

    def serve_connection(self, sock: socket.socket) -> None:
        """Answer one connection. Runs on the connection's own thread; nothing raised here is
        lost (``_Handler`` logs it). The Guardian is called only for a well-formed rewind of a
        valid snapshot id, asked by the allowed user."""
        try:
            pid, uid, gid = self._peer(sock)
        except ControlError as error:
            logger.error("%s: refused a connection, cannot tell who it is: %s", self.label, error)
            self._reply(sock, _refusal("No se puede saber quién llama: no se atiende."))
            return
        refused = self.refusal_for(pid, uid, gid)
        if refused is not None:
            self._reply(sock, _refusal(refused))
            return
        try:
            request = self._receive(sock)
            reply = self._handle(request, pid, uid)
        except _BadRequest as bad:
            reply = _refusal(str(bad))
        self._reply(sock, reply)

    def refusal_for(self, pid: int, uid: int, gid: int) -> str | None:
        """None if the process ``pid`` (``uid``, ``gid``, as the kernel says) may ask; else the
        reply's text, and the refusal is logged. Here: only the service's own user."""
        if uid == self._allowed_uid:
            return None
        logger.warning(
            "control socket: refused a connection from uid %d (pid %d): only uid %d may ask",
            uid,
            pid,
            self._allowed_uid,
        )
        return "Solo el usuario que ejecuta backtide puede pedir esto."

    def _receive(self, sock: socket.socket) -> dict[str, Any]:
        """The request: one JSON object on a line of at most 4 KiB, within the deadline."""
        deadline = time.monotonic() + self._request_timeout
        buffer = b""
        limit = MAX_REQUEST_BYTES
        while b"\n" not in buffer:
            if len(buffer) > limit:
                # Only a task may be longer: the owner's prompt (T26-5a). All else stops here.
                if limit == MAX_TASK_REQUEST_BYTES or not buffer.startswith(TASK_REQUEST_START):
                    break
                limit = MAX_TASK_REQUEST_BYTES
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _BadRequest("La petición ha tardado demasiado en llegar.")
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(limit + 1 - len(buffer))
            except TimeoutError:
                raise _BadRequest("La petición ha tardado demasiado en llegar.") from None
            except OSError as error:
                raise _BadRequest(f"No se ha podido leer la petición: {error.strerror}") from None
            if not chunk:
                break  # the client closed its side: what it sent is the request
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        if len(line) > limit:
            raise _BadRequest(f"La petición pasa de {limit} bytes: no se atiende.")
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _BadRequest("La petición no es un JSON válido.") from None
        if not isinstance(request, dict):
            raise _BadRequest("La petición tiene que ser un objeto JSON.")
        if len(line) > MAX_REQUEST_BYTES and request.get("cmd") != "task_start":  # a repeated key
            raise _BadRequest(f"La petición pasa de {MAX_REQUEST_BYTES} bytes: no se atiende.")
        return request

    def _handle(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """One order. What is an agent's is answered with that agent's desk; the field that names
        it leaves the request here, before anything looks at the request's keys."""
        command = request.get("cmd")
        if not isinstance(command, str) or command not in AGENT_COMMANDS:
            return self._machine_command(command, request, pid, uid)
        named = "agent" in request
        try:
            with self._roster.using(*([request.pop("agent")] if named else [])) as desk:
                return self._agent_command(command, request, pid, uid, desk, named=named)
        except AgentRefused as refused:
            raise _BadRequest(str(refused)) from None

    def _agent_command(
        self, command: str, request: dict[str, Any], pid: int, uid: int, desk: Desk, *, named: bool
    ) -> dict[str, Any]:
        """``named``: the order said which agent, which only a new cap tells from not saying."""
        guardian = desk.guardian
        if command == "rewind":
            return self._rewind(guardian, request, pid, uid)
        if command == "resume":
            return self._resume(guardian, request, pid, uid)
        if command == "decide":
            return self._decide(guardian, request, pid, uid)
        if command == "holds":
            return self._holds(guardian, request)
        if command == "trust":
            return self._trust(guardian, request, pid, uid)
        if command == "untrust":
            return self._untrust(guardian, request, pid, uid)
        if command == "end_batch":
            return self._end_batch(guardian, request, pid, uid)
        if command in ("trusted", "batches"):
            return self._listing(guardian, request)
        if command in ("budget", "set_budget", "accept_prices"):
            return self._budget_command(desk, request, pid, uid, named=named)
        if command in ("shell", "import"):
            return self._shell(guardian, request, pid, uid)
        if command == "task_start":
            return self._task_start(guardian, request, pid, uid)
        if command == "task_status":
            return self._task_status(guardian, request)
        if command == "task_stop":
            return self._task_stop(guardian, request, pid, uid)
        if command == "snapshots":
            return self._snapshots(desk, request)
        if command in ("agent_pause", "agent_resume"):
            return self._pause_or_resume(command, guardian, request, pid, uid, named=named)
        return self._export(guardian, request, pid, uid)

    def _pause_or_resume(
        self,
        command: str,
        guardian: RewindService,
        request: dict[str, Any],
        pid: int,
        uid: int,
        *,
        named: bool,
    ) -> dict[str, Any]:
        """Freezing a whole agent says which, always: a slip must not freeze the main one."""
        if not named or set(request) != {"cmd"}:
            raise _BadRequest("Esa orden lleva `cmd` y `agent`, y nada más.")
        if command == "agent_resume":
            return self._resume(guardian, request, pid, uid)
        outcome = guardian.pause_by_user(requested_by=self._requester(pid, uid))
        return {
            "ok": outcome.status in (PauseStatus.FROZEN, PauseStatus.STOPPED, PauseStatus.KILLED),
            "outcome": str(outcome.status),
            "message": redact(outcome.message),
            "agent_state": outcome.agent_state,
        }

    def _requester(self, pid: int, uid: int) -> str:
        """Who asked an order about the agents, as the box says it: the kernel's ids."""
        return f"{self.asks_as} (uid {uid}, pid {pid})"

    def _fleet_order(
        self, command: str, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        """Which agents there are. Nothing here is a path or an image: see ``fleet``."""
        if self._fleet is None:
            logger.warning("%s: refused %s: it takes no such order", self.label, command)
            raise _BadRequest("Este servicio no atiende esa orden.")
        order = {
            "agent_create": self._fleet.create,
            "agent_start": self._fleet.start,
            "agent_stop": self._fleet.stop,
            "agent_delete": self._fleet.delete,
            "agent_restore": self._fleet.restore,
            "agent_purge": self._fleet.purge,
        }[command]
        try:
            return order(request, self._requester(pid, uid))
        except OrderInvalid as bad:
            logger.warning("%s: refused %s outside its shape", self.label, command)
            return {"ok": False, "outcome": "invalid", "message": str(bad)}
        except Exception:  # said, with its trace in the log: the box says how far it got
            logger.exception("%s failed", command)
            return {
                "ok": False,
                "outcome": "failed",
                "message": "Ha fallado algo inesperado: mira la caja de la instalación y el "
                "registro del servicio antes de repetirlo.",
            }

    def _machine_command(
        self, command: object, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if command == "agents":
            return self._agents(request)
        if command in FLEET_COMMANDS:
            return self._fleet_order(str(command), request, pid, uid)
        if command in ("secrets", "set_secret", "clear_secret"):
            return self._settings_command(request, pid, uid)
        if command == "web_link":
            return self._web_link(request, pid, uid)
        if command == "web_end_all":
            return self._web_end_all(request, pid, uid)
        if command == "set_password":
            return self._set_password(request, pid, uid)
        if command == "passkeys":
            return self._list_passkeys(request)
        if command == "passkey_remove":
            return self._remove_passkey(request, pid, uid)
        if command == "passkey_rename":
            return self._rename_passkey(request, pid, uid)
        raise _BadRequest("Orden desconocida.")

    def _link_closed(self) -> bool:
        """Behind a domain it takes a passkey (D40): the link is only there for the first key
        (T26-4a), and through the internet it would open a session that approves and rewinds
        without one. A file that cannot be read may hold keys: closed, and the owner hears of it."""
        if self._passkeys is None or not self._passkeys.on_a_domain:
            return False
        from backtide.service.passkeys import PasskeyError

        try:
            return bool(self._passkeys.keys())
        except PasskeyError as error:
            logger.error("%s: the passkeys cannot be read: %s", self.label, error)
            return True

    def _web_link(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """A new one-time link for the installed web (`sudo backtide enlace`): the unspent one,
        if any, dies. Only here, on root's socket: the web cannot mint its own way in."""
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de enlace lleva `cmd` y nada más.")
        if self._sessions is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay enlace que dar.")
        if self._link_closed():
            logger.warning("%s: refused a link behind a domain with keys (uid %d, pid %d)",
                           self.label, uid, pid)  # fmt: skip
            raise _BadRequest(LINK_CLOSED)
        token = self._sessions.new_link()
        logger.info("%s: a new one-time link for the web was given to uid %d (pid %d)",
                    self.label, uid, pid)  # fmt: skip
        if self._on_entry is not None:
            # The token reaches only root; if the box missed it, the alert says so and the
            # session it opens is refused anyway (``session_open``).
            self._on_entry("web_link_given", {"uid": uid, "pid": pid})
        return {"ok": True, "outcome": "link", "message": "", "token": token}

    def _set_password(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """A new password for the web (`sudo backtide contraseña`, T26-3b-1): only its hash is
        kept. Recorded and alerted; never logged, never in a reply."""
        if set(request) != {"cmd", "password"}:
            raise _BadRequest("Una petición de contraseña lleva `cmd` y `password`, y nada más.")
        if self._password_checker is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay contraseña que poner.")
        try:
            self._password_checker.set(request.pop("password"))
        except PasswordError as error:
            return {"ok": False, "outcome": "invalid", "message": str(error)}
        # A password is changed when the old one may be known: every session ends with it,
        # the owner signs in again with the new one (review of T26-3b-1).
        ended = self._sessions.end_all() if self._sessions is not None else 0
        logger.info("%s: the web's password was changed by uid %d", self.label, uid)
        if self._on_entry is not None:
            self._on_entry("web_password_set", {"uid": uid, "pid": pid, "ended": ended})
        return {"ok": True, "outcome": "saved", "ended": ended,
                "message": "Contraseña guardada."}  # fmt: skip

    def _list_passkeys(self, request: dict[str, Any]) -> dict[str, Any]:
        """The web's passkeys (`sudo backtide llaves`): their ids too, which are not secret and
        are how `--quitar` tells two keys apart."""
        from backtide.service.passkeys import PasskeyError, describe

        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista de llaves lleva `cmd` y nada más.")
        if self._passkeys is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay llaves.")
        try:
            keys = [{**describe(key), "id": key.id} for key in self._passkeys.keys()]
        except PasskeyError as error:
            return {"ok": False, "outcome": "refused", "message": str(error), "keys": []}
        return {"ok": True, "outcome": "listed", "message": "", "keys": keys}

    def _remove_passkey(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """Take a passkey out (`sudo backtide llaves --quitar`): by its id or the end of it, one
        key and no doubt. Every session ends too, as with a new password: it is taken out when
        it may be in other hands. A lost key must be able to go: if the black box does not take
        it, the alert says so and it goes anyway."""
        from backtide.service.passkeys import PasskeyError, matching

        if set(request) != {"cmd", "key"} or not isinstance(request["key"], str):
            raise _BadRequest("Quitar una llave lleva `cmd` y `key`, y nada más.")
        if self._passkeys is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay llaves.")
        try:
            found = matching(self._passkeys.keys(), request["key"])
            if len(found) != 1:
                why = "Ninguna llave acaba así." if not found else "Varias llaves acaban así."
                return {"ok": False, "outcome": "invalid", "ended": 0, "message": why}
            key = found[0]
            if self._on_entry is not None:
                self._on_entry("web_passkey_removed", {"uid": uid, "pid": pid, "name": key.name,
                                                       "tail": key.tail})  # fmt: skip
            self._passkeys.remove(key.id)
        except PasskeyError as error:
            logger.error("%s: a passkey could not be taken out: %s", self.label, error)
            return {"ok": False, "outcome": "failed", "ended": 0, "message": str(error)}
        ended = self._sessions.end_all() if self._sessions is not None else 0
        logger.info("%s: the passkey …%s was taken out by uid %d", self.label, key.tail, uid)
        try:
            left = len(self._passkeys.keys())
        except PasskeyError:
            left = None  # it went: what cannot be read now is for the next list to say
        return {"ok": True, "outcome": "removed", "ended": ended, "message": "",
                "name": key.name, "tail": key.tail, "left": left}  # fmt: skip

    def _rename_passkey(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """A key's new name (`sudo backtide llaves --renombrar`, T26-3d): by its id or the end of
        it. Unlike a lost key, a name can wait for the black box: not recorded, not done."""
        from backtide.service.passkeys import PasskeyError, matching, name_problem

        if set(request) != {"cmd", "key", "name"} or not isinstance(request["key"], str):
            raise _BadRequest("Cambiar el nombre de una llave lleva `cmd`, `key` y `name`.")
        if self._passkeys is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay llaves.")
        why = name_problem(request["name"])
        if why is not None:
            return {"ok": False, "outcome": "invalid", "message": why}
        try:
            found = matching(self._passkeys.keys(), request["key"])
            if len(found) != 1:
                why = "Ninguna llave acaba así." if not found else "Varias llaves acaban así."
                return {"ok": False, "outcome": "invalid", "message": why}
            key = found[0]
            details = {"uid": uid, "pid": pid, "name": request["name"], "was": key.name,
                       "tail": key.tail}  # fmt: skip
            if self._on_entry is None or not self._on_entry("web_passkey_renamed", details):
                logger.error("%s: a passkey's new name could not be recorded", self.label)
                said = "No se ha podido apuntar el cambio: no se ha hecho."
                return {"ok": False, "outcome": "failed", "message": said}
            renamed = self._passkeys.rename(key.id, request["name"])
        except PasskeyError as error:
            logger.error("%s: a passkey could not get its new name: %s", self.label, error)
            return {"ok": False, "outcome": "failed", "message": str(error)}
        logger.info("%s: the passkey …%s has a new name, by uid %d", self.label, key.tail, uid)
        return {"ok": True, "outcome": "renamed", "message": "",
                "name": renamed.name, "tail": renamed.tail}  # fmt: skip

    def _web_end_all(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """Close every web session and the unspent link (`sudo backtide enlace --cerrar-todas`):
        on root's socket, for when the web itself cannot be trusted or does not answer."""
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de cerrar las sesiones lleva `cmd` y nada más.")
        if self._sessions is None:
            raise _BadRequest("Este servicio no tiene web instalada: no hay sesiones.")
        ended = self._sessions.end_all()
        logger.info("%s: every web session was closed (%d) by uid %d", self.label, ended, uid)
        if self._on_entry is not None:
            self._on_entry("web_sessions_closed", {"uid": uid, "pid": pid, "ended": ended})
        return {"ok": True, "outcome": "ended", "message": "", "ended": ended}

    def _shell(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        details: dict[str, Any] | None = None
        if request["cmd"] == "shell":
            if set(request) != {"cmd", "kind", "continue"}:
                raise _BadRequest("Una petición de shell lleva `cmd`, `kind` y `continue`.")
            kind, resume = request["kind"], request["continue"]
            if kind not in SHELL_REQUEST_KINDS or not isinstance(resume, bool):
                raise _BadRequest("`kind` es session o bundle, y `continue` es true o false.")
        else:
            if set(request) != {"cmd", *IMPORT_KEYS}:
                raise _BadRequest(
                    "Una petición de importar lleva `cmd`, " + ", ".join(sorted(IMPORT_KEYS)) + "."
                )
            details = _import_details(request)
            kind, resume = "import", False
        try:
            outcome = guardian.open_shell(
                kind, resume=resume, requested_by=f"cli (uid {uid}, pid {pid})", details=details
            )
        except Exception:
            logger.exception("opening a shell raised instead of answering")
            outcome = ShellOutcome(ShellStatus.FAILED, "Ha fallado algo inesperado: no se abre.")
        return {
            "ok": outcome.ready,
            "outcome": str(outcome.status),
            "message": redact(outcome.message),
            "container": outcome.container,
            "container_id": outcome.container_id,
            "user": outcome.user,
            "workdir": outcome.workdir,
        }

    def _task_start(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        """Take a task (T26-5a, backtide/service/tasks.py). Its id comes back at once: nothing of
        the task runs on this thread. The prompt never reaches a message or a log here."""
        if not {"cmd", "prompt"} <= set(request) <= {"cmd", "prompt", "continue", "seconds", "via"}:
            raise _BadRequest("Una tarea lleva `cmd` y `prompt`, y quizá `continue` y `seconds`.")
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in TASK_REQUESTERS:
            raise _BadRequest("`via` es cli o web.")
        resume, seconds = request.get("continue", False), request.get("seconds")
        if not isinstance(resume, bool):
            raise _BadRequest("`continue` es true o false.")
        if seconds is not None and (
            type(seconds) is not int or not 1 <= seconds <= MAX_TASK_SECONDS
        ):
            raise _BadRequest(f"`seconds` va de 1 a {MAX_TASK_SECONDS}.")
        try:
            prompt = check_prompt(request["prompt"])
            prompt.encode()  # a lone surrogate of JSON's \\u is not an argument of docker exec
        except (ValueError, UnicodeEncodeError):
            raise _BadRequest(
                f"`prompt` es un texto de {MAX_PROMPT} caracteres como mucho, y no vacío."
            ) from None
        try:
            started = guardian.task_start(
                prompt, resume=resume, seconds=seconds, requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception as error:  # its type alone: its text could carry the prompt
            logger.error("starting a task raised %s instead of answering", type(error).__name__)
            return _refusal("Ha fallado algo inesperado: no se empieza la tarea.")
        if started.task_id is None:
            return _refusal(started.message)
        return {"ok": True, "outcome": "started", "message": "", "task": started.task_id}

    def _task_status(self, guardian: RewindService, request: dict[str, Any]) -> dict[str, Any]:
        """How a task goes, with its answer when it ended: the agent's text, as it came. On the
        web's socket it takes a live session (``WebControlServer``): it is not in the black box."""
        task_id = self._task_id_of(request)
        try:
            status = guardian.task_status(task_id)
        except Exception as error:
            logger.error("reading a task raised %s instead of answering", type(error).__name__)
            return _refusal("Ha fallado algo inesperado: no se sabe cómo va la tarea.")
        if status is None:
            return {"ok": False, "outcome": TASK_UNKNOWN, "message": TASK_UNKNOWN_MESSAGE}
        return {
            "ok": True,
            "outcome": str(status.outcome),
            "message": status.message,
            "task": task_id,
            "answer": status.answer,
            "code": status.code,
            "seconds": status.seconds,
        }

    def _task_stop(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        """Ctrl-C in `backtide tarea`: stop the task inside the agent. Not on the web's list."""
        task_id = self._task_id_of(request)
        try:
            stopped = guardian.task_stop(task_id)
        except Exception as error:
            logger.error("stopping a task raised %s instead of answering", type(error).__name__)
            stopped = False
        if stopped is None:
            return {"ok": False, "outcome": TASK_UNKNOWN, "message": TASK_UNKNOWN_MESSAGE}
        logger.info("task %s: uid %d (pid %d) asked to stop it", task_id[:8], uid, pid)
        return {"ok": stopped, "outcome": "stopped" if stopped else "failed", "message": ""}

    @staticmethod
    def _task_id_of(request: dict[str, Any]) -> str:
        if set(request) != {"cmd", "task"}:
            raise _BadRequest("Esa orden lleva `cmd` y `task`, y nada más.")
        task_id = request["task"]
        if not _is_task_id(task_id):
            raise _BadRequest("Eso no es el identificador de una tarea.")
        return task_id

    def _export(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        keys = set(request)
        if keys not in (
            {"cmd", "dest"},
            {"cmd", "dest", "include_config"},
            {"cmd", "dest", "bundle", "repo"},
        ):
            raise _BadRequest(
                "Una petición de exportar lleva `cmd` y `dest` (y, con --git, `bundle` y `repo`; "
                "sin --git, quizá `include_config`), y nada más."
            )
        if "include_config" in request and request["include_config"] is not True:
            raise _BadRequest("`include_config` solo puede ser true.")
        destination = request["dest"]
        if not isinstance(destination, str):
            raise _BadRequest("`dest` tiene que ser una ruta.")
        bundle, repo = request.get("bundle"), request.get("repo")
        if "bundle" in request and (
            not isinstance(bundle, str)
            or not isinstance(repo, str)
            or len(bundle) > 100
            or not REPO_RE.fullmatch(repo)
        ):
            raise _BadRequest("`bundle` y `repo` no tienen la forma esperada.")
        try:
            outcome = guardian.export(
                destination,
                requested_by=f"cli (uid {uid}, pid {pid})",
                **({"bundle": bundle, "repo": repo} if "bundle" in request else {}),
                **({"include_config": True} if "include_config" in request else {}),
            )
        except Exception:
            logger.exception("an export raised instead of answering")
            outcome = ExportOutcome(
                ExportStatus.FAILED,
                "Ha fallado algo inesperado al exportar: mira la carpeta de destino y la caja "
                "negra.",
            )
        return {
            "ok": outcome.done,
            "outcome": str(outcome.status),
            "message": redact(outcome.message),
            "destination": outcome.destination,
            "snapshot": outcome.snapshot,
            "details": {k: v for k, v in outcome.details.items() if isinstance(v, int)},
            "skipped": _skipped_names(outcome.details.get("skipped")),
        }

    def _budget_command(
        self, desk: Desk, request: dict[str, Any], pid: int, uid: int, *, named: bool
    ) -> dict[str, Any]:
        """The spending cap (T11): what it says, or new caps (checked here and by the budget). A
        new cap that names no agent is the whole installation's (T26-2c), with one agent its own."""
        if desk.budget is None:
            raise _BadRequest("Este servicio no cuenta el gasto.")
        if request["cmd"] == "budget":
            if set(request) != {"cmd"}:
                raise _BadRequest("Una petición de gasto lleva `cmd` y nada más.")
            try:
                status = dict(desk.budget.status())
                if desk.waiting is not None:
                    status["models_waiting"] = sorted(desk.waiting())
            except Exception as error:
                logger.error("reading the spending raised: %s", type(error).__name__)
                return {"ok": False, "outcome": "failed", "message": "No se ha podido leer."}
            return {"ok": True, "outcome": "listed", "budget": status, "message": ""}
        if request["cmd"] == "accept_prices":
            return self._accept_prices(desk, request, pid, uid)
        if set(request) - {"cmd", "daily_usd", "monthly_usd", "via"}:
            raise _BadRequest("La petición de tope no lleva lo que debe.")
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in SETTINGS_REQUESTERS:
            raise _BadRequest("El tope solo se cambia desde la web o la terminal.")
        caps: dict[str, Decimal | None] = {}
        for name in ("daily_usd", "monthly_usd"):
            value = request.get(name)
            caps[name] = None if value is None else check_cap(value)
            if value is not None and caps[name] is None:
                return {"ok": False, "outcome": "invalid", "message": CAP_SHAPE}
        target = self._whole_budget if self._whole_budget is not None and not named else desk.budget
        try:
            outcome = target.set_caps(
                caps["daily_usd"], caps["monthly_usd"], requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception as error:
            logger.error("changing the spending cap raised: %s", type(error).__name__)
            return {"ok": False, "outcome": "failed", "message": "Ha fallado algo inesperado."}
        return {"ok": outcome.ok, "outcome": outcome.outcome, "message": outcome.message}

    def _accept_prices(
        self, desk: Desk, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        """B3: the owner's yes to the new prices waiting (the digest says which ones)."""
        if set(request) - {"cmd", "digest", "via"} or not isinstance(request.get("digest"), str):
            raise _BadRequest("La petición de precios no lleva lo que debe.")
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in SETTINGS_REQUESTERS:
            raise _BadRequest("Los precios solo se aceptan desde la web o la terminal.")
        try:
            outcome = desk.budget.accept_prices(
                request["digest"][:64], requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception as error:
            logger.error("accepting the new prices raised: %s", type(error).__name__)
            return {"ok": False, "outcome": "failed", "message": "Ha fallado algo inesperado."}
        return {"ok": outcome.ok, "outcome": outcome.outcome, "message": outcome.message}

    def _settings_command(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """The Settings page (T12e). The value is taken out of the request at once, checked and
        written by ``Settings``, and never put in a reply, a refusal or a log line."""
        command = request["cmd"]
        value = request.pop("value", None)
        chat_id = request.pop("chat_id", None)
        try:
            if self._settings is None:
                raise _BadRequest("Este servicio no tiene ajustes que cambiar desde aquí.")
            if command == "secrets":
                if set(request) != {"cmd"} or value is not None or chat_id is not None:
                    raise _BadRequest("Una petición de ajustes lleva `cmd` y nada más.")
                return self._secrets_status()
            allowed = {"cmd", "kind", "via"}
            if set(request) - allowed or not {"cmd", "kind"} <= set(request):
                raise _BadRequest("La petición de ajustes no lleva lo que debe.")
            via = request.get("via", "cli")
            if not isinstance(via, str) or via not in SETTINGS_REQUESTERS:
                raise _BadRequest("Los ajustes solo se cambian desde la web o la terminal.")
            kind = request["kind"]
            if not isinstance(kind, str) or kind not in SECRET_KINDS:
                raise _BadRequest("Ese tipo de clave no existe aquí.")
            requested_by = f"{via} (uid {uid}, pid {pid})"
            if command == "clear_secret":
                if value is not None or chat_id is not None:
                    raise _BadRequest("Para quitar una clave no se manda ninguna.")
                outcome = self._settings_call(
                    kind, lambda: self._settings.clear_secret(kind, requested_by=requested_by)
                )
                return _settings_reply(kind, outcome)
            if not isinstance(value, str) or len(value) > MAX_SECRET_CHARS:
                raise _BadRequest("La clave tiene que ser un texto corto.")
            if chat_id is not None and (
                kind != SECRET_TELEGRAM or not isinstance(chat_id, str) or len(chat_id) > 32
            ):
                raise _BadRequest("Solo Telegram lleva un chat, y es un texto corto.")
            settings = self._settings
            outcome = self._settings_call(
                kind,
                lambda: settings.set_secret(
                    kind, value, chat_id=chat_id or "", requested_by=requested_by
                ),
            )
            return _settings_reply(kind, outcome)
        finally:
            value = chat_id = None  # nothing here keeps the key once it is handed on
            request.clear()

    def _secrets_status(self) -> dict[str, Any]:
        try:
            shown = self._settings.status() if self._settings is not None else {}
        except Exception as error:
            logger.error("listing the settings raised instead of answering: %s",
                         type(error).__name__)  # fmt: skip
            return {"ok": False, "outcome": "failed", "secrets": {},
                    "message": "No se han podido leer los ajustes."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "secrets": shown, "message": ""}

    @staticmethod
    def _settings_call(kind: str, call: Callable[[], SettingsOutcome]) -> SettingsOutcome:
        """``call``, which should not raise; if it does, its text is not logged (it might hold
        the value): only its type."""
        try:
            return call()
        except Exception as error:
            logger.error("changing the %s setting raised instead of answering: %s", kind,
                         type(error).__name__)  # fmt: skip
            return SettingsOutcome(
                Outcome.FAILED,
                "Ha fallado algo inesperado: mira el registro del servicio y la caja negra.",
            )

    def _decide(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "hold_id", "verdict"}:
            raise _BadRequest(
                "Una decisión lleva `cmd`, `hold_id`, `verdict` y quizá `via`, y nada más."
            )
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in REQUESTERS:
            raise _BadRequest("`via` tiene que ser uno de: " + ", ".join(sorted(REQUESTERS)) + ".")
        if via == "telegram" and pid != os.getpid():  # the bot lives in this very process (T09)
            raise _BadRequest("Solo el bot de backtide, dentro del servicio, pide como `telegram`.")
        hold_id, verdict = request["hold_id"], request["verdict"]
        if not isinstance(hold_id, str) or not HOLD_ID_RE.fullmatch(hold_id):
            raise _BadRequest("Eso no es el identificador de una petición retenida (h-…).")
        if verdict not in DECIDE_VERDICTS:
            raise _BadRequest("`verdict` tiene que ser `approve` o `reject`.")
        try:
            outcome = guardian.decide_hold(
                hold_id, verdict, via=via, requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception:  # the Guardian should not raise; if it does, nothing was approved
            logger.exception("deciding on %s raised instead of answering", hold_id)
            outcome = HoldOutcome(HoldStatus.FAILED, hold_id)
        return {
            "ok": outcome.status in _DECIDED,
            "outcome": str(outcome.status),
            "message": outcome.message,
            "hold_id": hold_id,
        }

    def _holds(self, guardian: RewindService, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de retenidas lleva `cmd` y nada más.")
        try:
            holds = guardian.pending_holds()
        except Exception:
            logger.exception("listing the held requests raised instead of answering")
            return {"ok": False, "outcome": "failed", "holds": [],
                    "message": "No se han podido leer las peticiones retenidas."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "holds": redact(holds), "message": ""}

    # T10-5: the web's holds page (docs/32, section 11 and decision 9)

    def _trust(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) != {"cmd", "hold_id", "via"}:
            raise _BadRequest("«Aprobar y confiar» lleva `cmd`, `hold_id` y `via`, y nada más.")
        via, hold_id = request["via"], request["hold_id"]
        if not isinstance(via, str) or via not in TRUST_REQUESTERS:
            raise _BadRequest("Un destinatario de confianza solo se añade desde la web.")
        if not isinstance(hold_id, str) or not HOLD_ID_RE.fullmatch(hold_id):
            raise _BadRequest("Eso no es el identificador de una petición retenida (h-…).")
        try:
            outcome = guardian.trust_hold(
                hold_id, via=via, requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception:  # the Guardian should not raise; if it does, nothing changed
            logger.exception("trusting the recipient of %s raised instead of answering", hold_id)
            outcome = TrustOutcome(TrustStatus.FAILED, hold_id)
        return {
            "ok": outcome.status is TrustStatus.TRUSTED,
            "outcome": str(outcome.status),
            "message": outcome.message,
            "hold_id": hold_id,
            "hold": None if outcome.hold is None else str(outcome.hold),
        }

    def _untrust(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "trust_id"}:
            raise _BadRequest("Quitar la confianza lleva `cmd`, `trust_id` y quizá `via`.")
        via, trust_id = request.get("via", "cli"), request["trust_id"]
        if not isinstance(via, str) or via not in UNTRUST_REQUESTERS:
            raise _BadRequest("La confianza se quita desde la web o la terminal.")
        if not isinstance(trust_id, str) or not TRUST_ID_RE.fullmatch(trust_id):
            raise _BadRequest("Eso no es el identificador de un destinatario de confianza (t-…).")
        try:
            done = guardian.untrust(trust_id, via=via, requested_by=f"{via} (uid {uid}, pid {pid})")
        except Exception:
            logger.exception("removing the trusted recipient %s raised", trust_id)
            done = None
        if done is None:
            outcome, message = (
                "failed",
                ("No se ha podido guardar el cambio: ese destinatario sigue siendo de confianza."),
            )
        elif done:
            outcome, message = (
                "removed",
                ("Ya no es de confianza: lo que vaya a ese destinatario vuelve a preguntar."),
            )
        else:
            outcome, message = "unknown", "Ese destinatario ya no estaba en la lista."
        return {"ok": done is True, "outcome": outcome, "message": message}

    def _end_batch(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "rule_id"}:
            raise _BadRequest("Revocar un lote lleva `cmd`, `rule_id` y quizá `via`.")
        via, rule_id = request.get("via", "cli"), request["rule_id"]
        if not isinstance(via, str) or via not in UNTRUST_REQUESTERS:
            raise _BadRequest("Por aquí un lote se revoca desde la web o la terminal.")
        if not isinstance(rule_id, str) or not BATCH_ID_RE.fullmatch(rule_id):
            raise _BadRequest("Eso no es el identificador de un lote (b-…).")
        try:
            done = guardian.end_batch(rule_id, via=via)
        except Exception:
            logger.exception("revoking the batch %s raised", rule_id)
            done = False
        if done:
            return {"ok": True, "outcome": "ended",
                    "message": "Lote revocado: lo que cubría vuelve a preguntar."}  # fmt: skip
        return {"ok": False, "outcome": "unknown",
                "message": "Ese lote ya no está activo (caducó, se revocó o backtide se "
                "reinició)."}  # fmt: skip

    def _listing(self, guardian: RewindService, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista lleva `cmd` y nada más.")
        command = request["cmd"]
        try:
            items = guardian.trusted() if command == "trusted" else guardian.batches()
        except Exception:
            logger.exception("listing %s raised instead of answering", command)
            return {"ok": False, "outcome": "failed", "items": [],
                    "message": "No se ha podido leer la lista."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "items": redact(items), "message": ""}

    def _resume(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de seguir lleva `cmd` y nada más.")
        try:
            outcome = guardian.resume(requested_by=self._requester(pid, uid))
        except Exception:  # the Guardian should not raise; if it does, say so without its text
            logger.exception("resuming raised instead of answering")
            outcome = ResumeOutcome(
                ResumeStatus.PROBLEM,
                "Ha fallado algo inesperado al reanudar. Mira el estado del agente y la caja "
                "negra antes de repetirlo.",
            )
        return {
            "ok": outcome.status in _RESUME_OK,
            "outcome": str(outcome.status),
            "message": redact(outcome.message),
            "agent_state": outcome.agent_state,
        }

    def _rewind(
        self, guardian: RewindService, request: dict[str, Any], pid: int, uid: int
    ) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "snapshot_id"}:
            raise _BadRequest(
                "Una petición de rebobinar lleva `cmd`, `snapshot_id` y quizá `via`, y nada más."
            )
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in REQUESTERS:
            raise _BadRequest("`via` tiene que ser uno de: " + ", ".join(sorted(REQUESTERS)) + ".")
        if via == "telegram" and pid != os.getpid():  # the bot lives in this very process (T09)
            raise _BadRequest("Solo el bot de backtide, dentro del servicio, pide como `telegram`.")
        snapshot_id = request["snapshot_id"]
        if not isinstance(snapshot_id, str) or Snapshot.parse(snapshot_id) is None:
            return _reply_of(
                RewindOutcome(
                    RewindStatus.INVALID,
                    target="",
                    message="Eso no es el identificador de una instantánea: no se ha hecho nada.",
                )
            )
        try:
            outcome = guardian.rewind(snapshot_id, requested_by=f"{via} (uid {uid}, pid {pid})")
        except (
            Exception
        ):  # the Guardian should not raise; if it does, nobody can tell what happened
            logger.exception("the rewind %s raised instead of answering", snapshot_id)
            outcome = RewindOutcome(
                RewindStatus.UNKNOWN,
                target=snapshot_id,
                message=(
                    "Ha fallado algo inesperado al rebobinar y no se sabe en qué punto. "
                    "Comprueba el estado con `backtide instantaneas`; backtide lo concilia al "
                    "volver a arrancar."
                ),
            )
        return _reply_of(outcome)

    def _agents(self, request: dict[str, Any]) -> dict[str, Any]:
        """Every agent of the installation and whether it is watched (T26-2c; docs/47 section
        6.9): what the CLI, the web and the bot go through. Names of its own config, no path."""
        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista de agentes lleva `cmd` y nada más.")
        return {
            "ok": True,
            "outcome": "listed",
            "message": "",
            "agents": self._roster.listing(),
            "deleted": self._roster.deleted(),  # T26-6c: what the trash has, and no order reaches
        }

    def _snapshots(self, desk: Desk, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista lleva `cmd` y nada más.")
        listed = self._listed_ids(desk)
        if listed is None:
            return {"ok": False, "outcome": "failed", "snapshots": [],
                    "message": "No se ha podido leer la lista de instantáneas."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "message": "",
                "snapshots": listed[-MAX_LISTED_SNAPSHOTS:]}  # fmt: skip

    def _listed_ids(self, desk: Desk) -> list[str] | None:
        if desk.snapshots is None:
            logger.error("%s: there is no snapshot list for the agent %s", self.label, desk.slug)
            return None
        try:
            return [snapshot.id for snapshot in desk.snapshots()]
        except Exception as error:  # noqa: BLE001 - said, logged and refused: never a rewind
            logger.error("%s: the snapshot list cannot be read: %s", self.label,
                         type(error).__name__)  # fmt: skip
            return None

    def _reply(self, sock: socket.socket, reply: dict[str, Any]) -> None:
        """Send the reply and close the conversation properly: our side is shut down, and what
        the client still sends is read for a moment, so a reset does not eat the reply."""
        data = json.dumps(reply).encode() + b"\n"
        try:
            sock.settimeout(REPLY_TIMEOUT)
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            self._drain(sock)
        except OSError as error:
            logger.warning(
                "%s: the client went away before the reply (%s): %s",
                self.label,
                reply.get("outcome"),
                error,
            )

    @staticmethod
    def _drain(sock: socket.socket) -> None:
        deadline = time.monotonic() + DRAIN_SECONDS
        seen = 0
        while seen < DRAIN_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(65536)
            except (TimeoutError, OSError):
                return
            if not chunk:
                return
            seen += len(chunk)


def _settings_reply(kind: str, outcome: SettingsOutcome) -> dict[str, Any]:
    return {
        "ok": outcome.ok,
        "outcome": str(outcome.status),
        "message": outcome.message,
        "applied": str(outcome.applied),
        "kind": kind,
    }


def _refusal(message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "outcome": REFUSED,
        "undo": None,
        "message": message,
        "target": None,
        "request_id": None,
        "agent_started": False,
    }


def _reply_of(outcome: RewindOutcome) -> dict[str, Any]:
    """The reply for ``outcome``. ``ok`` means the workspace WAS rewound (also when something
    went wrong afterwards: ``outcome`` says "problem")."""
    return {
        "ok": outcome.rewound,
        "outcome": str(outcome.status),
        "undo": outcome.undo,
        "message": redact(outcome.message),
        "target": outcome.target or None,
        "request_id": outcome.request_id,
        "agent_started": outcome.agent_started,
    }


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """``socketserver`` with a thread per connection, joined on close (a rewind in flight is
    waited for), and at most ``max_connections`` at once."""

    daemon_threads = False
    block_on_close = True
    request_queue_size = 16

    def __init__(self, control: ControlServer, path: Path) -> None:
        self.control = control
        self._path = path
        self._active = 0
        self._active_lock = threading.Lock()
        super().__init__(str(path), _Handler, bind_and_activate=False)

    def bind_checked(self) -> tuple[int, int]:
        """Bind at the path without following anything and check what was made. Returns the
        (device, inode) of the socket file."""
        self._clear_stale_socket()
        try:
            self.socket.bind(str(self._path))
        except OSError as error:
            raise ControlError(
                f"no se puede crear el socket de control {self._path}: "
                f"{os.strerror(error.errno or 0)}"
            ) from None
        # Nobody can connect before ``listen()``, which comes after this check, so there is no
        # window with another mode (and ``umask`` is process-wide: not touched).
        mode, group = self.control.socket_mode, self.control.socket_group
        try:
            if group is not None:
                os.chown(self._path, -1, group, follow_symlinks=False)
            os.chmod(self._path, mode)
        except OSError as error:
            self._unlink_own_socket()
            raise ControlError(
                f"no se puede dejar el socket {self._path} en {mode:04o}: "
                f"{os.strerror(error.errno or 0)}"
            ) from None
        info = os.lstat(self._path)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != mode
            or (group is not None and info.st_gid != group)
        ):
            self._unlink_own_socket()
            raise ControlError(
                f"el socket {self._path} no ha quedado como debe (de backtide y {mode:04o})"
            )
        return info.st_dev, info.st_ino

    def _unlink_own_socket(self) -> None:
        """We just bound ``self._path``: remove it again (a failed start leaves nothing)."""
        try:
            info = os.lstat(self._path)
            if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid():
                os.unlink(self._path)
        except OSError as error:
            logger.error("cannot remove the control socket %s: %s", self._path, error)

    def _clear_stale_socket(self) -> None:
        """A socket file left by a service that died is removed; anything else at the path is
        refused and left alone (a symbolic link, a file, a folder). The caller holds the
        service lock, so no live service owns a socket here."""
        try:
            info = os.lstat(self._path)
        except FileNotFoundError:
            return
        except OSError as error:
            raise ControlError(
                f"no se puede mirar {self._path}: {os.strerror(error.errno or 0)}"
            ) from None
        if not stat.S_ISSOCK(info.st_mode):
            raise ControlError(
                f"{self._path} existe y no es un socket (¿un enlace simbólico?): no se toca"
            )
        if info.st_uid != os.geteuid():
            raise ControlError(f"{self._path} es de otro usuario: no se toca")
        try:
            os.unlink(self._path)
        except OSError as error:
            raise ControlError(
                f"no se puede quitar el socket viejo {self._path}: {os.strerror(error.errno or 0)}"
            ) from None

    def server_bind(self) -> None:  # not used: start() binds with ``bind_checked``
        raise NotImplementedError

    def process_request(self, request: Any, client_address: Any) -> None:
        with self._active_lock:
            full = self._active >= self.control._max_connections  # noqa: SLF001
            if not full:
                self._active += 1
        if full:
            logger.warning("%s: too many open connections, one was refused", self.control.label)
            try:  # best effort, never blocking: the client then knows nothing was done
                request.setblocking(False)
                request.send(
                    json.dumps(_refusal("Demasiadas conexiones abiertas.")).encode() + b"\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_done()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_done()

    def _connection_done(self) -> None:
        with self._active_lock:
            self._active -= 1

    def handle_error(self, request: Any, client_address: Any) -> None:
        logger.exception("%s: a connection failed", self.control.label)


class _Handler(socketserver.BaseRequestHandler):
    server: _Server

    def handle(self) -> None:
        self.server.control.serve_connection(self.request)


# --- the client --------------------------------------------------------------------------------


def ask_rewind(
    path: Path,
    snapshot_id: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    reply_timeout: float = CLIENT_REPLY_TIMEOUT,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    via: str = "cli",
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service at ``path`` to rewind to ``snapshot_id`` and return its reply, checked:
    a dict whose ``outcome`` is known, ``ok`` a bool, ``message`` a str and ``undo`` a str or
    None. Everything else in it is ignored.

    While nobody answers (no socket yet, or a refused connection: the service is starting) it
    retries for ``wait`` seconds and then raises ControlUnavailable. Raises ControlError if the
    path is not a socket of ours, the server is not our user, or the reply makes no sense.
    Waits for the reply as long as ``reply_timeout``: a rewind takes seconds, and a client that
    gives up early would leave the person guessing whether it happened. ``via`` says who asks
    (one of ``REQUESTERS``; ValueError otherwise, nothing sent); "cli" is not sent, so the CLI's
    request is the one it always was."""
    if via not in REQUESTERS:
        raise ValueError(f"via must be one of {sorted(REQUESTERS)}")
    request: dict[str, Any] = {"cmd": "rewind", "snapshot_id": snapshot_id}
    if via != "cli":
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="el rebobinado",
        wait=wait,
        reply_timeout=reply_timeout,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    return _checked_reply(raw)


def ask_resume(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    reply_timeout: float = CLIENT_REPLY_TIMEOUT,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service at ``path`` to resume after a pause by space (`backtide seguir`) and return
    its reply, checked like ``ask_rewind``'s: ``ok`` (the agent may run), ``outcome`` (a
    ``ResumeStatus`` or "refused"), ``message`` and ``agent_state``. Same retries and errors."""
    raw = _ask(
        Path(path),
        {"cmd": "resume"},
        what="la reanudación",
        wait=wait,
        reply_timeout=reply_timeout,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        reply = None
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in RESUME_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si el agente se ha "
            "reanudado: mira la caja negra."
        )
    state = reply.get("agent_state")
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "message": reply["message"],
        "agent_state": state if isinstance(state, str) else "",
    }


def ask_decide(
    path: Path,
    hold_id: str,
    verdict: str,
    *,
    via: str | None = None,
    wait: float = WAIT_FOR_SERVICE,
    reply_timeout: float = REPLY_TIMEOUT * 6,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service at ``path`` to approve or reject the held request ``hold_id`` (`backtide
    aprobar` / `rechazar`; ``via="telegram"`` from the bot inside the service, T10-4). Returns
    its reply, checked: ``ok``, ``outcome`` (a ``HoldStatus`` or "refused") and ``message``.
    ValueError for a verdict or a ``via`` that is not one (nothing sent)."""
    if verdict not in DECIDE_VERDICTS:
        raise ValueError("verdict is approve or reject")
    if via is not None and via not in REQUESTERS:
        raise ValueError("via is cli, web or telegram")
    request: dict[str, Any] = {"cmd": "decide", "hold_id": hold_id, "verdict": verdict}
    if via is not None:
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="la decisión",
        wait=wait,
        reply_timeout=reply_timeout,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in HOLD_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si se ha decidido: mira "
            "`backtide retenidas` y la caja negra."
        )
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def ask_holds(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    agent: str | None = None,
) -> list[dict[str, Any]]:
    """The held requests the service at ``path`` is waiting on (`backtide retenidas`), checked:
    each a dict with its ``hold_id`` and the texts the CLI shows. ControlError if the reply makes
    no sense or the service could not list them."""
    raw = _ask(
        Path(path),
        {"cmd": "holds"},
        what="la lista",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
        max_reply=MAX_LIST_REPLY_BYTES,
        agent=agent,
    )
    reply = _listed_reply(raw, "holds")
    holds = []
    for item in reply["holds"][:MAX_LISTED_HOLDS]:
        if not isinstance(item, dict) or not isinstance(item.get("hold_id"), str):
            continue
        if not HOLD_ID_RE.fullmatch(item["hold_id"]):
            continue
        holds.append(item)
    return holds


def ask_trust(
    path: Path,
    hold_id: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """ "Aprobar y confiar en este destinatario" from the web (T10-5): the reply, checked:
    ``ok``, ``outcome`` (a ``TrustStatus`` or "refused"), ``message`` and ``hold`` (what
    approving did: a ``HoldStatus`` or None)."""
    raw = _ask(
        Path(path),
        {"cmd": "trust", "hold_id": hold_id, "via": "web"},
        what="la decisión",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in TRUST_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si se ha aprobado ni si el "
            "destinatario es de confianza: mira la caja negra."
        )
    hold = reply.get("hold")
    statuses = {str(status) for status in HoldStatus}
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "message": reply["message"],
        "hold": hold if hold in statuses else None,
    }


def _ask_change(
    path: Path,
    request: dict[str, Any],
    *,
    wait: float,
    peer: PeerCredentials,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    raw = _ask(
        Path(path),
        request,
        agent=agent,
        what="el cambio",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in LIST_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si ha cambiado: mira la "
            "caja negra."
        )
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def ask_untrust(
    path: Path,
    trust_id: str,
    *,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Stop trusting the recipient ``trust_id`` (T10-5). ValueError for a ``via`` that cannot
    ask (nothing sent)."""
    if via not in UNTRUST_REQUESTERS:
        raise ValueError("via is cli or web")
    request = {"cmd": "untrust", "trust_id": trust_id, "via": via}
    return _ask_change(
        path,
        request,
        wait=wait,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        server_uid=server_uid,
        session=session,
        agent=agent,
    )


def ask_end_batch(
    path: Path,
    rule_id: str,
    *,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Revoke the batch ``rule_id`` (T10-5, the web; T10-4's bot does it in its process)."""
    if via not in UNTRUST_REQUESTERS:
        raise ValueError("via is cli or web")
    request = {"cmd": "end_batch", "rule_id": rule_id, "via": via}
    return _ask_change(
        path,
        request,
        wait=wait,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        server_uid=server_uid,
        session=session,
        agent=agent,
    )


def ask_list(
    path: Path,
    what: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    agent: str | None = None,
) -> list[dict[str, Any]]:
    """``what`` is "trusted" (the recipients trusted from the web) or "batches" (the active
    batch rules): each item a dict with its id (``trust_id`` t-…, ``rule_id`` b-…); anything
    else is dropped. ControlError if the reply makes no sense or the list could not be read."""
    if what not in ("trusted", "batches"):
        raise ValueError("what is trusted or batches")
    raw = _ask(
        Path(path),
        {"cmd": what},
        what="la lista",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
        max_reply=MAX_LIST_REPLY_BYTES,
        agent=agent,
    )
    reply = _listed_reply(raw, "items")
    key, pattern = ("trust_id", TRUST_ID_RE) if what == "trusted" else ("rule_id", BATCH_ID_RE)
    return [
        item
        for item in reply["items"][:MAX_LISTED_HOLDS]
        if isinstance(item, dict)
        and isinstance(item.get(key), str)
        and pattern.fullmatch(item[key])
    ]


def ask_web_link(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> str:
    """A new one-time link token for the installed web (`sudo backtide enlace`, T26-3a); the
    unspent one dies. ControlError if the service has no web or its reply makes no sense."""
    raw = _ask(
        Path(path),
        {"cmd": "web_link"},
        what="el enlace",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict):
        raise ControlError("La respuesta del servicio no es la esperada.")
    token = reply.get("token")
    if reply.get("ok") is not True or not isinstance(token, str) or not token:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se ha podido dar.")
    return token


def ask_passkeys(
    path: Path,
    key: str | None = None,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> dict[str, Any]:
    """The web's passkeys (`sudo backtide llaves`), or, with ``key``, take that one out: the
    reply, with its ``ok`` and ``message`` checked. ControlError if it makes no sense."""
    request: dict[str, Any] = {"cmd": "passkeys"}
    if key is not None:
        request = {"cmd": "passkey_remove", "key": key}
    return _ask_keys(path, request, wait, peer, sleep, monotonic, server_uid)


def ask_passkey_rename(
    path: Path,
    key: str,
    name: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> dict[str, Any]:
    """Give that key a new name (`sudo backtide llaves --renombrar`): the reply, as above."""
    request = {"cmd": "passkey_rename", "key": key, "name": name}
    return _ask_keys(path, request, wait, peer, sleep, monotonic, server_uid)


def _ask_keys(
    path: Path,
    request: dict[str, Any],
    wait: float,
    peer: PeerCredentials,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    server_uid: int | None,
) -> dict[str, Any]:
    raw = _ask(
        Path(path),
        request,
        what="las llaves",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlError("La respuesta del servicio no es la esperada.")
    return reply


def ask_web_end_all(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> int:
    """Close every web session (`sudo backtide enlace --cerrar-todas`); how many were open.
    ControlError if the service has no web or its reply makes no sense."""
    raw = _ask(
        Path(path),
        {"cmd": "web_end_all"},
        what="el cierre de las sesiones",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict):
        raise ControlError("La respuesta del servicio no es la esperada.")
    ended = reply.get("ended")
    if reply.get("ok") is not True or isinstance(ended, bool) or not isinstance(ended, int):
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se han podido cerrar.")
    return ended


def ask_set_password(
    path: Path,
    password: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> dict[str, Any]:
    """A new password for the web (`sudo backtide contraseña`): the reply's ``ok``, ``outcome``
    ("saved" or "invalid") and ``message``. ControlError if the service has no web or its reply
    makes no sense. The password is in the request only, never in an error."""
    request: dict[str, Any] = {"cmd": "set_password", "password": password}
    try:
        raw = _ask(
            Path(path),
            request,
            what="la contraseña",
            wait=wait,
            reply_timeout=REPLY_TIMEOUT * 6,
            peer=peer,
            server_uid=server_uid,
            sleep=sleep,
            monotonic=monotonic,
        )
    finally:
        request.clear()
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("outcome") not in ("saved", "invalid"):
        raise ControlError(reply["message"] or "No se ha podido guardar.")
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def ask_secrets(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> dict[str, dict[str, Any]]:
    """What the service at ``path`` has set (the Settings page, T12e): per kind, as
    ``Settings.status`` says it. ControlError if the reply makes no sense or it could not
    read them. The caller checks each field before showing it."""
    raw = _ask(
        Path(path),
        {"cmd": "secrets"},
        what="la lectura de los ajustes",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or not isinstance(reply.get("secrets"), dict):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("ok") is not True:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se han podido leer.")
    return {
        kind: entry
        for kind, entry in reply["secrets"].items()
        if kind in SECRET_KINDS and isinstance(entry, dict)
    }


def ask_set_secret(
    path: Path,
    kind: str,
    value: str,
    *,
    chat_id: str | None = None,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
) -> dict[str, Any]:
    """Ask the service at ``path`` to put ``value`` as the key of ``kind`` (and, for Telegram,
    ``chat_id``). Returns its reply, checked: ``ok``, ``outcome``, ``message``, ``applied``.
    ValueError (nothing sent) for an unknown kind or ``via``; neither error ever holds the
    value."""
    if kind not in SECRET_KINDS or via not in SETTINGS_REQUESTERS:
        raise ValueError("unknown kind or via")
    request: dict[str, Any] = {"cmd": "set_secret", "kind": kind, "value": value}
    if chat_id is not None:
        request["chat_id"] = chat_id
    if via != "cli":
        request["via"] = via
    del value
    try:
        raw = _ask(
            Path(path),
            request,
            what="el cambio",
            wait=wait,
            reply_timeout=REPLY_TIMEOUT * 6,
            peer=peer,
            server_uid=server_uid,
            session=session,
            sleep=sleep,
            monotonic=monotonic,
        )
    finally:
        request.clear()
    return _checked_settings_reply(raw)


def ask_clear_secret(
    path: Path,
    kind: str,
    *,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
) -> dict[str, Any]:
    """Ask the service at ``path`` to remove the key of ``kind``. Checked like
    ``ask_set_secret``'s reply."""
    if kind not in SECRET_KINDS or via not in SETTINGS_REQUESTERS:
        raise ValueError("unknown kind or via")
    request: dict[str, Any] = {"cmd": "clear_secret", "kind": kind}
    if via != "cli":
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="el cambio",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
    )
    return _checked_settings_reply(raw)


def ask_budget(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """What the service says of the spending (``Budget.status``). ControlError if it makes no
    sense. The caller checks each field before showing it."""
    raw = _ask(
        Path(path),
        {"cmd": "budget"},
        what="la lectura del gasto",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        message = reply.get("message") if isinstance(reply, dict) else None
        raise ControlError(message if isinstance(message, str) else "Respuesta inesperada.")
    status = reply.get("budget")
    if not isinstance(status, dict):
        raise ControlError("La respuesta del servicio no es la esperada.")
    return status


def ask_set_budget(
    path: Path,
    *,
    daily_usd: str | None,
    monthly_usd: str | None,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service for new spending caps (texts as a person typed them). Its reply, checked:
    ``ok``, ``outcome``, ``message``. ValueError (nothing sent) for an unknown ``via``."""
    if via not in SETTINGS_REQUESTERS:
        raise ValueError("unknown via")
    request: dict[str, Any] = {"cmd": "set_budget"}
    if daily_usd is not None:
        request["daily_usd"] = daily_usd
    if monthly_usd is not None:
        request["monthly_usd"] = monthly_usd
    if via != "cli":
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="el cambio del tope",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in BUDGET_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si el tope ha cambiado: "
            "mira la página de Ajustes y la caja negra."
        )
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def ask_accept_prices(
    path: Path,
    *,
    digest: str,
    via: str = "cli",
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Accept the new prices waiting whose digest is ``digest`` (B3). The reply, checked: ``ok``,
    ``outcome``, ``message``. ValueError (nothing sent) for an unknown ``via``."""
    if via not in SETTINGS_REQUESTERS:
        raise ValueError("unknown via")
    request: dict[str, Any] = {"cmd": "accept_prices", "digest": digest}
    if via != "cli":
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="la aceptación de los precios nuevos",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in BUDGET_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si los precios han "
            "cambiado: mira la página de Ajustes y la caja negra."
        )
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def _checked_settings_reply(raw: bytes) -> dict[str, Any]:
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in SETTINGS_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si la clave ha cambiado: "
            "mira la página de Ajustes y la caja negra."
        )
    applied = reply.get("applied")
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "message": reply["message"],
        "applied": applied if applied in APPLIED else str(Applied.NONE),
    }


def _listed_reply(raw: bytes, key: str) -> dict[str, Any]:
    """A reply that lists under ``key``. If the service refused or could not, ControlError says
    what it said: an agent that is nobody's, say, comes with a message and no list."""
    reply = _json_or_none(raw)
    if not isinstance(reply, dict):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("ok") is not True:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se ha podido listar.")
    if not isinstance(reply.get(key), list):
        raise ControlError("La respuesta del servicio no es la esperada.")
    return reply


def ask_agent_order(
    path: Path,
    request: dict[str, Any],
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> dict[str, Any]:
    """An order about which agents there are, or freezing one (T26-6a). Its ``ok``, ``outcome`` and
    ``message``. ControlOutcomeUnknown if the reply makes no sense: it may have been done."""
    raw = _ask(
        Path(path),
        request,
        what="la orden",
        wait=wait,
        reply_timeout=AGENT_ORDER_REPLY_TIMEOUT,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("outcome"), str)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si se ha hecho: mira la caja "
            "de la instalación."
        )
    return {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}


def ask_agents(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> list[dict[str, Any]]:
    """The agents the service at ``path`` has (T26-2c), checked: see ``ask_fleet``."""
    return ask_fleet(
        path, wait=wait, peer=peer, sleep=sleep, monotonic=monotonic, server_uid=server_uid
    )[0]


def ask_deleted(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> list[dict[str, Any]]:
    """The deleted agents the service at ``path`` still has (T26-6c), checked: see ``ask_fleet``."""
    return ask_fleet(
        path, wait=wait, peer=peer, sleep=sleep, monotonic=monotonic, server_uid=server_uid
    )[1]


def ask_fleet(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """What the service at ``path`` says in one reply. The agents (T26-2c), each a dict with its
    ``slug``, ``name`` (None or a text), ``main``, ``watched``, ``state``, ``notice`` (the lines of
    the rewind notice about it, T26-2d), ``kind``, ``version``, ``in_use`` (D42) and ``order``
    (T26-6b). And the deleted ones (T26-6c), each with its ``slug``, ``name``, ``state``,
    ``deleted_at``, ``purge_after`` and ``purged``. What does not look like one is dropped.
    ControlError if the reply makes no sense."""
    raw = _ask(
        Path(path),
        {"cmd": "agents"},
        what="la lista",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        sleep=sleep,
        monotonic=monotonic,
    )
    reply = _listed_reply(raw, "agents")
    found = []
    for item in reply["agents"]:
        if (
            isinstance(item, dict)
            and _is_agent_name(item.get("slug"))
            and isinstance(item.get("name"), str | None)
            and isinstance(item.get("main"), bool)
            and isinstance(item.get("watched"), bool)
            and isinstance(item.get("state"), str | None)
        ):
            found.append(
                {key: item[key] for key in ("slug", "name", "main", "watched", "state")}
                | {"notice": _notice_lines(item.get("notice"))}
                | {key: _short_word(item.get(key)) for key in AGENT_WORDS}
            )
    return found, _deleted_of(reply.get("deleted"))


def _short_word(value: object) -> str | None:
    """A word of the service's about an agent, or None if it does not look like one."""
    return value if isinstance(value, str) and _AGENT_WORD.fullmatch(value) else None


def _deleted_of(listed: object) -> list[dict[str, Any]]:
    return [
        {key: item[key] for key in DELETED_KEYS}
        for item in (listed if isinstance(listed, list) else [])
        if isinstance(item, dict)
        and _is_agent_name(item.get("slug"))
        and isinstance(item.get("name"), str | None)
        and all(isinstance(item.get(key), str) for key in ("state", "deleted_at", "purge_after"))
        and isinstance(item.get("purged"), bool)
    ]


def _notice_lines(value: object) -> list[str]:
    """The lines of a rewind notice as the service sent them, or none if they make no sense."""
    if not isinstance(value, list) or len(value) > MAX_NOTICE_LINES:
        return []
    if not all(isinstance(line, str) and len(line) <= MAX_NOTICE_LINE for line in value):
        return []
    return list(value)


def _is_agent_name(value: object) -> bool:
    if value == identity.MAIN_SLUG:
        return True
    try:
        identity.check_slug(value)
    except identity.SlugError:
        return False
    return True


def ask_snapshots(
    path: Path,
    *,
    server_uid: int | None = 0,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    agent: str | None = None,
) -> list[Snapshot]:
    """The agent's snapshots, oldest first, as the service at ``path`` lists them; anything that
    is not a snapshot id is dropped. ControlError if the reply makes no sense or the service could
    not list them. ``server_uid`` 0: the web's narrow socket, root's; None: our own user's."""
    raw = _ask(
        Path(path),
        {"cmd": "snapshots"},
        agent=agent,
        what="la lista",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        max_reply=MAX_LIST_REPLY_BYTES,
        server_uid=server_uid,
    )
    found = []
    for item in _listed_reply(raw, "snapshots")["snapshots"][-MAX_LISTED_SNAPSHOTS:]:
        snapshot = Snapshot.parse(item) if isinstance(item, str) else None
        if snapshot is not None:
            found.append(snapshot)
    return found


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _ask(
    path: Path,
    request: dict[str, Any],
    *,
    what: str,
    wait: float,
    reply_timeout: float,
    peer: PeerCredentials,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    max_reply: int = MAX_REPLY_BYTES,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> bytes:
    """One conversation: connect (retrying while nobody answers), send ``request``, read the
    whole reply (``max_reply`` bytes at most). ``what`` names the request in the messages ("el
    rebobinado"). ``session`` is the web's (T26-3a): the narrow socket takes no change without
    a live one; it rides in the request, never in a log. ``agent`` says who it is about (T26-2c);
    without it the request is what it always was."""
    if session is not None:
        request["session"] = session
    if agent is not None:
        request["agent"] = agent
    deadline = monotonic() + wait
    while True:
        try:
            sock = _connect(path, peer, server_uid)
        except ControlUnavailable:
            if monotonic() >= deadline:
                raise
            sleep(RETRY_EVERY)
            continue
        break
    with sock:
        data = json.dumps(request).encode() + b"\n"
        try:
            sock.settimeout(REPLY_TIMEOUT)
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(reply_timeout)
            return _read_all(sock, max_reply)
        except TimeoutError:
            raise ControlOutcomeUnknown(
                f"El servicio no ha contestado a tiempo. {what.capitalize()} puede seguir en "
                "marcha: mira `backtide instantaneas` y la caja negra antes de repetirlo."
            ) from None
        except OSError as error:
            raise ControlOutcomeUnknown(
                f"Se ha perdido la conexión con el servicio ({error.strerror or error}). "
                f"No se sabe si {what} se hizo: mira `backtide instantaneas`."
            ) from None


def _connect(path: Path, peer: PeerCredentials, server_uid: int | None = None) -> socket.socket:
    """Connect to the socket at ``path`` once it is checked: a real socket (never through a
    link), owned by ``server_uid`` (our own user by default; root for the web's narrow socket,
    T12c), and the process answering runs as that user (``SO_PEERCRED``)."""
    expected = os.geteuid() if server_uid is None else server_uid
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise ControlUnavailable(f"No existe el socket de control {path}.") from None
    except OSError as error:
        raise ControlError(
            f"No se puede mirar el socket de control {path}: {os.strerror(error.errno or 0)}"
        ) from None
    if not stat.S_ISSOCK(info.st_mode):
        raise ControlError(f"{path} no es un socket (¿un enlace simbólico?): no me conecto.")
    if info.st_uid != expected:
        raise ControlError(f"El socket {path} es del usuario {info.st_uid}: no me conecto.")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(REPLY_TIMEOUT)
        try:
            sock.connect(str(path))
        except OSError as error:
            if error.errno in (errno.ECONNREFUSED, errno.ENOENT):
                raise ControlUnavailable(
                    f"Nadie contesta en el socket de control {path}."
                ) from None
            raise ControlError(
                f"No se puede conectar al socket de control {path}: {os.strerror(error.errno or 0)}"
            ) from None
        _, uid, _ = peer(sock)  # ControlError if unreadable: nothing is sent
        if uid != expected:
            raise ControlError(
                f"El que contesta en {path} es el usuario {uid}, no el que ejecuta backtide: "
                "no le envío nada."
            )
    except BaseException:
        sock.close()
        raise
    return sock


def _read_all(sock: socket.socket, limit: int = MAX_REPLY_BYTES) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(data)
        data += chunk
    raise ControlOutcomeUnknown(
        "La respuesta del servicio es demasiado grande: no se usa. No se sabe si el rebobinado "
        "se hizo: mira `backtide instantaneas`."
    )


def _checked_reply(raw: bytes) -> dict[str, Any]:
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        reply = None
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
        or not (reply.get("undo") is None or isinstance(reply.get("undo"), str))
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si el rebobinado se hizo: "
            "mira `backtide instantaneas`."
        )
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "undo": reply["undo"],
        "message": reply["message"],
        "agent_started": reply.get("agent_started") is True,
    }


def _import_details(request: dict[str, Any]) -> dict[str, Any]:
    """The counts of `backtide importar`, for the black box: checked shapes, nothing more."""
    name, source = request["name"], request["source"]
    files, size, replace = request["files"], request["bytes"], request["replace"]
    left_out, include = request["secrets_left_out"], request["include_secrets"]
    if (
        not isinstance(name, str)
        or not isinstance(source, str)
        or not 0 < len(name) <= MAX_IMPORT_TEXT
        or not 0 < len(source) <= MAX_IMPORT_TEXT
        or any(
            isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in (files, size, left_out)
        )
        or not isinstance(replace, bool)
        or not isinstance(include, bool)
    ):
        raise _BadRequest("Los datos de la importación no tienen la forma esperada.")
    return {
        "name": name,
        "source": source,
        "files": files,
        "bytes": size,
        "replace": replace,
        "secrets_left_out": left_out,
        "include_secrets": include,
    }


def _skipped_names(value: object) -> list[list[str]]:
    """What an export skipped, by name: ``[why, path]`` pairs of short printable text (the
    paths are the agent's, escaped by export.py; checked again on both sides)."""
    if not isinstance(value, list):
        return []
    named = []
    for item in value[:MAX_SKIPPED_NAMES]:
        if (
            isinstance(item, list | tuple)
            and len(item) == 2
            and all(isinstance(part, str) for part in item)
            and item[0] in ("git", "name", "case", "config")
            and 0 < len(item[1]) <= MAX_SKIPPED_TEXT
            and item[1].isprintable()
        ):
            named.append([item[0], item[1]])
    return named


def ask_shell(
    path: Path,
    kind: str,
    *,
    resume: bool = False,
    import_details: Mapping[str, Any] | None = None,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service whether `backtide entrar` (``kind`` "session"), `importar` ("import", with
    ``import_details``: name, source, files, bytes, replace, and the secrets it left out or took)
    or `exportar --git` ("bundle": the agent makes it) may run now, recorded. Returns ``ok``,
    ``outcome``, ``message`` and, when ``ok``, the ``container``, ``user`` and ``workdir`` for
    docker exec, checked. Same retries and errors as ask_rewind. A task is ``ask_task_start``."""
    if kind == "import":
        request: dict[str, Any] = {"cmd": "import", **dict(import_details or {})}
    elif kind in SHELL_REQUEST_KINDS:
        request = {"cmd": "shell", "kind": kind, "continue": resume}
    else:
        raise ValueError(f"unknown kind {kind!r}")
    raw = _ask(
        Path(path),
        request,
        what="la petición",
        wait=wait,
        reply_timeout=CLIENT_REPLY_TIMEOUT,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in SHELL_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown("La respuesta del servicio no es la esperada: no se abre nada.")
    checked = {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}
    if reply["ok"]:
        container, user, workdir = reply.get("container"), reply.get("user"), reply.get("workdir")
        container_id = reply.get("container_id")
        if (
            not isinstance(container, str)
            or not _CONTAINER_RE.fullmatch(container)
            or not isinstance(container_id, str)
            or not _CONTAINER_ID_RE.fullmatch(container_id)
            or not isinstance(user, str)
            or not _USER_RE.fullmatch(user)
            or not isinstance(workdir, str)
            or not _WORKDIR_RE.fullmatch(workdir)
        ):
            raise ControlOutcomeUnknown(
                "La respuesta del servicio no es la esperada: no se abre nada."
            )
        checked |= {
            "container": container,
            "container_id": container_id,
            "user": user,
            "workdir": workdir,
        }
    return checked


def ask_task_start(
    path: Path,
    prompt: str,
    *,
    resume: bool = False,
    seconds: int | None = None,
    via: str | None = None,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """Give the agent a task (`backtide tarea`, the web's chat). Returns ``ok``, ``outcome``
    ("started" or "refused"), ``message`` and, when ``ok``, its id as ``task``: at once, whatever
    the task takes. ``ask_task_status`` says how it goes. Same retries and errors as ask_rewind."""
    request: dict[str, Any] = {"cmd": "task_start", "prompt": prompt, "continue": resume}
    if seconds is not None:
        request["seconds"] = seconds
    if via is not None:
        request["via"] = via
    raw = _ask(
        Path(path),
        request,
        what="la tarea",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in TASK_START_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
        or (reply["ok"] and not _is_task_id(reply.get("task")))
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. La tarea puede estar en marcha: mira la "
            "caja negra."
        )
    checked = {"ok": reply["ok"], "outcome": reply["outcome"], "message": reply["message"]}
    return {**checked, "task": reply["task"]} if reply["ok"] else checked


def ask_task_status(
    path: Path,
    task_id: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    server_uid: int | None = None,
    session: str | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    """How a task goes: ``ok`` (False if it is not known here, or refused), ``outcome`` (a
    ``TaskOutcome``, "unknown" or "refused"), ``message``, and its ``answer``, ``code`` and
    ``seconds`` once it ended. The answer and the message can carry the agent's text, as it came:
    whoever shows them escapes them."""
    raw = _ask(
        Path(path),
        {"cmd": "task_status", "task": task_id},
        what="la pregunta",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
        session=session,
        sleep=sleep,
        monotonic=monotonic,
        max_reply=MAX_TASK_REPLY_BYTES,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in TASK_STATUS_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
        or not isinstance(reply.get("answer"), str | None)
        or not (reply.get("code") is None or type(reply.get("code")) is int)
        or not (reply.get("seconds") is None or type(reply.get("seconds")) in (int, float))
    ):
        raise ControlOutcomeUnknown("La respuesta del servicio no es la esperada.")
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "message": reply["message"],
        "answer": reply.get("answer"),
        "code": reply.get("code"),
        "seconds": reply.get("seconds"),
    }


def ask_task_stop(
    path: Path,
    task_id: str,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    agent: str | None = None,
) -> bool:
    """Ctrl-C in `backtide tarea`: stop the task inside the agent. True if nothing of it is left or
    it was signalled; False if it may run on, or the service did not say."""
    raw = _ask(
        Path(path),
        {"cmd": "task_stop", "task": task_id},
        what="la orden de parar",
        wait=wait,
        reply_timeout=TASK_STOP_REPLY_TIMEOUT,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or reply.get("outcome") not in TASK_STOP_OUTCOMES:
        raise ControlOutcomeUnknown("La respuesta del servicio no es la esperada.")
    return reply.get("ok") is True


def _is_task_id(value: object) -> bool:
    return isinstance(value, str) and TASK_ID_RE.fullmatch(value) is not None


def ask_export(
    path: Path,
    destination: str,
    *,
    bundle: str | None = None,
    repo: str | None = None,
    include_config: bool = False,
    wait: float = WAIT_FOR_SERVICE,
    reply_timeout: float = CLIENT_REPLY_TIMEOUT,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    agent: str | None = None,
) -> dict[str, Any]:
    """Ask the service to export the agent's work folder into ``destination`` (`backtide
    exportar`). Returns ``ok``, ``outcome``, ``message``, ``destination``, ``snapshot`` and
    ``details`` (counts) and ``skipped`` (what it skipped by name: ``[why, path]``), checked.
    With ``bundle`` (and ``repo``, the folder it came from), only that git bundle of the agent's
    HOME is exported, into the new file ``destination`` (`backtide exportar --git`). With
    ``include_config`` (not with a bundle), what the owner's tools run or read by themselves is
    copied too (`backtide exportar --incluir-config`)."""
    if include_config and bundle is not None:
        raise ValueError("include_config is for a folder export, not a bundle")
    request: dict[str, Any] = {"cmd": "export", "dest": destination}
    if bundle is not None:
        request |= {"bundle": bundle, "repo": repo or "."}
    if include_config:
        request["include_config"] = True
    raw = _ask(
        Path(path),
        request,
        what="la exportación",
        wait=wait,
        reply_timeout=reply_timeout,
        peer=peer,
        sleep=sleep,
        monotonic=monotonic,
        agent=agent,
    )
    reply = _json_or_none(raw)
    if (
        not isinstance(reply, dict)
        or reply.get("outcome") not in EXPORT_OUTCOMES
        or not isinstance(reply.get("ok"), bool)
        or not isinstance(reply.get("message"), str)
    ):
        raise ControlOutcomeUnknown(
            "La respuesta del servicio no es la esperada. No se sabe si se exportó: mira la "
            "carpeta de destino y la caja negra."
        )
    details = reply.get("details")
    snapshot = reply.get("snapshot")
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "message": reply["message"],
        "destination": reply.get("destination")
        if isinstance(reply.get("destination"), str)
        else "",
        "snapshot": snapshot if isinstance(snapshot, str) and Snapshot.parse(snapshot) else "",
        "details": {
            key: value
            for key, value in (details if isinstance(details, dict) else {}).items()
            if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool)
        },
        "skipped": _skipped_names(reply.get("skipped")),
    }
