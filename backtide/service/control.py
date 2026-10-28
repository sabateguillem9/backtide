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
from collections.abc import Callable, Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import redact
from backtide.service.holds import (
    BATCH_ID_RE,
    HOLD_ID_RE,
    HoldOutcome,
    HoldStatus,
    TrustOutcome,
    TrustStatus,
)
from backtide.service.pause import RESUME_EXIT_CODES, ResumeOutcome, ResumeStatus
from backtide.service.rewind import EXIT_CODES, RewindOutcome, RewindStatus
from backtide.service.settings import KINDS as SECRET_KINDS
from backtide.service.settings import TELEGRAM as SECRET_TELEGRAM
from backtide.service.settings import Applied, Outcome, SettingsOutcome
from backtide.service.shell import (
    PROMPT_RECORDED,
    REPO_RE,
    ExportOutcome,
    ExportStatus,
    ShellOutcome,
    ShellStatus,
    recorded_prompt,
)
from backtide.service.spend import CAP_SHAPE, CapOutcome, check_cap
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
# The shell mode (T17a-4): what `backtide entrar`/`tarea` and `importar` may say.
SHELL_REQUEST_KINDS = frozenset({"session", "task", "bundle"})
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

    def export(
        self,
        destination: str,
        *,
        requested_by: str,
        bundle: str | None = None,
        repo: str | None = None,
        include_config: bool = False,
    ) -> ExportOutcome: ...


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
    ) -> None:
        self._guardian = guardian
        self._settings = settings
        self._budget = budget
        # The providers that wait for their key (``Egress.waiting``): the panel says so, next
        # to the spending. Only names of [proxy], never a key.
        self._waiting = waiting
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
        while b"\n" not in buffer:
            if len(buffer) > MAX_REQUEST_BYTES:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _BadRequest("La petición ha tardado demasiado en llegar.")
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(MAX_REQUEST_BYTES + 1 - len(buffer))
            except TimeoutError:
                raise _BadRequest("La petición ha tardado demasiado en llegar.") from None
            except OSError as error:
                raise _BadRequest(f"No se ha podido leer la petición: {error.strerror}") from None
            if not chunk:
                break  # the client closed its side: what it sent is the request
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        if len(line) > MAX_REQUEST_BYTES:
            raise _BadRequest(f"La petición pasa de {MAX_REQUEST_BYTES} bytes: no se atiende.")
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _BadRequest("La petición no es un JSON válido.") from None
        if not isinstance(request, dict):
            raise _BadRequest("La petición tiene que ser un objeto JSON.")
        return request

    def _handle(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        command = request.get("cmd")
        if command == "rewind":
            return self._rewind(request, pid, uid)
        if command == "resume":
            return self._resume(request, pid, uid)
        if command == "decide":
            return self._decide(request, pid, uid)
        if command == "holds":
            return self._holds(request)
        if command == "trust":
            return self._trust(request, pid, uid)
        if command == "untrust":
            return self._untrust(request, pid, uid)
        if command == "end_batch":
            return self._end_batch(request, pid, uid)
        if command in ("trusted", "batches"):
            return self._listing(request)
        if command in ("secrets", "set_secret", "clear_secret"):
            return self._settings_command(request, pid, uid)
        if command in ("budget", "set_budget", "accept_prices"):
            return self._budget_command(request, pid, uid)
        if command in ("shell", "import"):
            return self._shell(request, pid, uid)
        if command == "export":
            return self._export(request, pid, uid)
        raise _BadRequest("Orden desconocida.")

    def _shell(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        details: dict[str, Any] | None = None
        if request["cmd"] == "shell":
            if set(request) - {"prompt"} != {"cmd", "kind", "continue"}:
                raise _BadRequest(
                    "Una petición de shell lleva `cmd`, `kind` y `continue` (y, una tarea, "
                    "`prompt`)."
                )
            kind, resume = request["kind"], request["continue"]
            if kind not in SHELL_REQUEST_KINDS or not isinstance(resume, bool):
                raise _BadRequest("`kind` es session o task, y `continue` es true o false.")
            if "prompt" in request:
                prompt = request["prompt"]
                if kind != "task" or not isinstance(prompt, str) or len(prompt) > PROMPT_RECORDED:
                    raise _BadRequest(
                        f"`prompt` es de una tarea: un texto de {PROMPT_RECORDED} caracteres "
                        "como mucho."
                    )
                details = recorded_prompt(prompt)  # struck again here: the record is ours
        else:
            if set(request) != {"cmd", *IMPORT_KEYS}:
                raise _BadRequest(
                    "Una petición de importar lleva `cmd`, " + ", ".join(sorted(IMPORT_KEYS)) + "."
                )
            details = _import_details(request)
            kind, resume = "import", False
        try:
            outcome = self._guardian.open_shell(
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

    def _export(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
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
            outcome = self._guardian.export(
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

    def _budget_command(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """The spending cap (T11): what it says, or new caps (checked here and by the budget)."""
        if self._budget is None:
            raise _BadRequest("Este servicio no cuenta el gasto.")
        if request["cmd"] == "budget":
            if set(request) != {"cmd"}:
                raise _BadRequest("Una petición de gasto lleva `cmd` y nada más.")
            try:
                status = dict(self._budget.status())
                if self._waiting is not None:
                    status["models_waiting"] = sorted(self._waiting())
            except Exception as error:
                logger.error("reading the spending raised: %s", type(error).__name__)
                return {"ok": False, "outcome": "failed", "message": "No se ha podido leer."}
            return {"ok": True, "outcome": "listed", "budget": status, "message": ""}
        if request["cmd"] == "accept_prices":
            return self._accept_prices(request, pid, uid)
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
        try:
            outcome = self._budget.set_caps(
                caps["daily_usd"], caps["monthly_usd"], requested_by=f"{via} (uid {uid}, pid {pid})"
            )
        except Exception as error:
            logger.error("changing the spending cap raised: %s", type(error).__name__)
            return {"ok": False, "outcome": "failed", "message": "Ha fallado algo inesperado."}
        return {"ok": outcome.ok, "outcome": outcome.outcome, "message": outcome.message}

    def _accept_prices(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        """B3: the owner's yes to the new prices waiting (the digest says which ones)."""
        if set(request) - {"cmd", "digest", "via"} or not isinstance(request.get("digest"), str):
            raise _BadRequest("La petición de precios no lleva lo que debe.")
        via = request.get("via", "cli")
        if not isinstance(via, str) or via not in SETTINGS_REQUESTERS:
            raise _BadRequest("Los precios solo se aceptan desde la web o la terminal.")
        try:
            outcome = self._budget.accept_prices(  # type: ignore[union-attr]
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

    def _decide(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
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
            outcome = self._guardian.decide_hold(
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

    def _holds(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de retenidas lleva `cmd` y nada más.")
        try:
            holds = self._guardian.pending_holds()
        except Exception:
            logger.exception("listing the held requests raised instead of answering")
            return {"ok": False, "outcome": "failed", "holds": [],
                    "message": "No se han podido leer las peticiones retenidas."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "holds": redact(holds), "message": ""}

    # T10-5: the web's holds page (docs/32, section 11 and decision 9)

    def _trust(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        if set(request) != {"cmd", "hold_id", "via"}:
            raise _BadRequest("«Aprobar y confiar» lleva `cmd`, `hold_id` y `via`, y nada más.")
        via, hold_id = request["via"], request["hold_id"]
        if not isinstance(via, str) or via not in TRUST_REQUESTERS:
            raise _BadRequest("Un destinatario de confianza solo se añade desde la web.")
        if not isinstance(hold_id, str) or not HOLD_ID_RE.fullmatch(hold_id):
            raise _BadRequest("Eso no es el identificador de una petición retenida (h-…).")
        try:
            outcome = self._guardian.trust_hold(
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

    def _untrust(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "trust_id"}:
            raise _BadRequest("Quitar la confianza lleva `cmd`, `trust_id` y quizá `via`.")
        via, trust_id = request.get("via", "cli"), request["trust_id"]
        if not isinstance(via, str) or via not in UNTRUST_REQUESTERS:
            raise _BadRequest("La confianza se quita desde la web o la terminal.")
        if not isinstance(trust_id, str) or not TRUST_ID_RE.fullmatch(trust_id):
            raise _BadRequest("Eso no es el identificador de un destinatario de confianza (t-…).")
        try:
            done = self._guardian.untrust(
                trust_id, via=via, requested_by=f"{via} (uid {uid}, pid {pid})"
            )
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

    def _end_batch(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        if set(request) - {"via"} != {"cmd", "rule_id"}:
            raise _BadRequest("Revocar un lote lleva `cmd`, `rule_id` y quizá `via`.")
        via, rule_id = request.get("via", "cli"), request["rule_id"]
        if not isinstance(via, str) or via not in UNTRUST_REQUESTERS:
            raise _BadRequest("Por aquí un lote se revoca desde la web o la terminal.")
        if not isinstance(rule_id, str) or not BATCH_ID_RE.fullmatch(rule_id):
            raise _BadRequest("Eso no es el identificador de un lote (b-…).")
        try:
            done = self._guardian.end_batch(rule_id, via=via)
        except Exception:
            logger.exception("revoking the batch %s raised", rule_id)
            done = False
        if done:
            return {"ok": True, "outcome": "ended",
                    "message": "Lote revocado: lo que cubría vuelve a preguntar."}  # fmt: skip
        return {"ok": False, "outcome": "unknown",
                "message": "Ese lote ya no está activo (caducó, se revocó o backtide se "
                "reinició)."}  # fmt: skip

    def _listing(self, request: dict[str, Any]) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una lista lleva `cmd` y nada más.")
        command = request["cmd"]
        try:
            items = self._guardian.trusted() if command == "trusted" else self._guardian.batches()
        except Exception:
            logger.exception("listing %s raised instead of answering", command)
            return {"ok": False, "outcome": "failed", "items": [],
                    "message": "No se ha podido leer la lista."}  # fmt: skip
        return {"ok": True, "outcome": "listed", "items": redact(items), "message": ""}

    def _resume(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
        if set(request) != {"cmd"}:
            raise _BadRequest("Una petición de seguir lleva `cmd` y nada más.")
        try:
            outcome = self._guardian.resume(requested_by=f"cli (uid {uid}, pid {pid})")
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

    def _rewind(self, request: dict[str, Any], pid: int, uid: int) -> dict[str, Any]:
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
            outcome = self._guardian.rewind(
                snapshot_id, requested_by=f"{via} (uid {uid}, pid {pid})"
            )
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
        sleep=sleep,
        monotonic=monotonic,
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
        sleep=sleep,
        monotonic=monotonic,
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
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or not isinstance(reply.get("holds"), list):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("ok") is not True:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se ha podido listar.")
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
        sleep=sleep,
        monotonic=monotonic,
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
) -> dict[str, Any]:
    raw = _ask(
        Path(path),
        request,
        what="el cambio",
        wait=wait,
        reply_timeout=REPLY_TIMEOUT * 6,
        peer=peer,
        server_uid=server_uid,
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
    )
    reply = _json_or_none(raw)
    if not isinstance(reply, dict) or not isinstance(reply.get("items"), list):
        raise ControlError("La respuesta del servicio no es la esperada.")
    if reply.get("ok") is not True:
        message = reply.get("message")
        raise ControlError(message if isinstance(message, str) else "No se ha podido listar.")
    key, pattern = ("trust_id", TRUST_ID_RE) if what == "trusted" else ("rule_id", BATCH_ID_RE)
    return [
        item
        for item in reply["items"][:MAX_LISTED_HOLDS]
        if isinstance(item, dict)
        and isinstance(item.get(key), str)
        and pattern.fullmatch(item[key])
    ]


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
        sleep=sleep,
        monotonic=monotonic,
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
        sleep=sleep,
        monotonic=monotonic,
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
) -> bytes:
    """One conversation: connect (retrying while nobody answers), send ``request``, read the
    whole reply (``max_reply`` bytes at most). ``what`` names the request in the messages ("el
    rebobinado")."""
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
    data = b""
    while len(data) <= limit:
        chunk = sock.recv(65536)
        if not chunk:
            return data
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
    prompt: str | None = None,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Ask the service whether `backtide entrar` (``kind`` "session"), `tarea` ("task") or
    `importar` ("import", with ``import_details``: name, source, files, bytes, replace, and the
    secrets it left out or took) or `exportar --git` ("bundle": the agent makes it) may run
    now, recorded. A task's ``prompt`` goes into the record struck and cut
    (``backtide.service.shell.recorded_prompt``, on both sides). Returns ``ok``, ``outcome``,
    ``message`` and, when ``ok``, the ``container``, ``user`` and ``workdir`` for docker exec,
    checked. Same retries and errors as ask_rewind."""
    if kind == "import":
        request: dict[str, Any] = {"cmd": "import", **dict(import_details or {})}
    elif kind in SHELL_REQUEST_KINDS:
        request = {"cmd": "shell", "kind": kind, "continue": resume}
        if kind == "task" and prompt is not None:
            request["prompt"] = recorded_prompt(prompt)["prompt"]
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
