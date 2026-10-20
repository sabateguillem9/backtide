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
  Anything else (too big, slow, not UTF-8, not JSON, unknown command, extra keys, an id that is
  not a snapshot id) is refused WITHOUT calling the Guardian.
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
import socket
import socketserver
import stat
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from backtide.blackbox import redact
from backtide.service.holds import HOLD_ID_RE, HoldOutcome, HoldStatus
from backtide.service.pause import RESUME_EXIT_CODES, ResumeOutcome, ResumeStatus
from backtide.service.rewind import EXIT_CODES, RewindOutcome, RewindStatus
from backtide.service.settings import KINDS as SECRET_KINDS
from backtide.service.settings import TELEGRAM as SECRET_TELEGRAM
from backtide.service.settings import Applied, Outcome, SettingsOutcome
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
# The Settings page (T12e): who may ask (not the bot: a key is never set from a chat), what a
# change can answer, and how long a value may be (the service checks its shape).
SETTINGS_REQUESTERS = frozenset({"cli", "web"})
SETTINGS_OUTCOMES = frozenset({*(str(status) for status in Outcome), REFUSED})
APPLIED = frozenset(str(applied) for applied in Applied)
MAX_SECRET_CHARS = 256


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


class SettingsService(Protocol):
    """What the server needs for the Settings page (``backtide.service.settings.Settings``)."""

    def status(self) -> dict[str, dict[str, Any]]: ...

    def set_secret(
        self, kind: str, value: str, *, chat_id: str = "", requested_by: str
    ) -> SettingsOutcome: ...

    def clear_secret(self, kind: str, *, requested_by: str) -> SettingsOutcome: ...


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
    credentials of a connection and is replaceable so a test can play another user."""

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
    ) -> None:
        self._guardian = guardian
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
            pid, uid, _gid = self._peer(sock)
        except ControlError as error:
            logger.error("control socket: refused a connection, cannot tell who it is: %s", error)
            self._reply(sock, _refusal("No se puede saber quién llama: no se atiende."))
            return
        if uid != self._allowed_uid:
            logger.warning(
                "control socket: refused a connection from uid %d (pid %d): only uid %d may ask",
                uid,
                pid,
                self._allowed_uid,
            )
            self._reply(sock, _refusal("Solo el usuario que ejecuta backtide puede pedir esto."))
            return
        try:
            request = self._receive(sock)
            reply = self._handle(request, pid, uid)
        except _BadRequest as bad:
            reply = _refusal(str(bad))
        self._reply(sock, reply)

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
        if command in ("secrets", "set_secret", "clear_secret"):
            return self._settings_command(request, pid, uid)
        raise _BadRequest("Orden desconocida.")

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
                "control socket: the client went away before the reply (%s): %s",
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
        try:
            os.chmod(self._path, 0o600)
        except OSError as error:
            self._unlink_own_socket()
            raise ControlError(
                f"no se puede dejar el socket de control {self._path} en 0600: "
                f"{os.strerror(error.errno or 0)}"
            ) from None
        info = os.lstat(self._path)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            self._unlink_own_socket()
            raise ControlError(
                f"el socket de control {self._path} no ha quedado como debe (de backtide y 0600)"
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
            logger.warning("control socket: too many open connections, one was refused")
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
        logger.exception("control socket: a connection failed")


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
        sleep=sleep,
        monotonic=monotonic,
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


def ask_secrets(
    path: Path,
    *,
    wait: float = WAIT_FOR_SERVICE,
    peer: PeerCredentials = peer_credentials,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
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
        sleep=sleep,
        monotonic=monotonic,
    )
    return _checked_settings_reply(raw)


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
) -> bytes:
    """One conversation: connect (retrying while nobody answers), send ``request``, read the
    whole reply. ``what`` names the request in the messages ("el rebobinado")."""
    deadline = monotonic() + wait
    while True:
        try:
            sock = _connect(path, peer)
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
            return _read_all(sock)
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


def _connect(path: Path, peer: PeerCredentials) -> socket.socket:
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
    if info.st_uid != os.geteuid():
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
        if uid != os.geteuid():
            raise ControlError(
                f"El que contesta en {path} es el usuario {uid}, no el que ejecuta backtide: "
                "no le envío nada."
            )
    except BaseException:
        sock.close()
        raise
    return sock


def _read_all(sock: socket.socket) -> bytes:
    data = b""
    while len(data) <= MAX_REPLY_BYTES:
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
