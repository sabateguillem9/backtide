"""The control socket: how `vigia rebobinar` asks a running service to rewind, and how
`vigia seguir` asks it to resume after a pause by space (T04d-2).

Design: docs/19-diseno-t04.md, sections 4 ("El socket de control") and "La CLI".

While `vigia vigilar` runs it owns the agent and holds ``vigia.lock``, so a second process must
never rewind on its own: it asks the service, which serialises the request with everything else
through ``agent_lock`` (inside ``Guardian.rewind``).

The server (inside the service):
- ``<state_dir>/control.sock``, mode 0600, in Vigía's private state folder. It is never in the
  volume and never mounted into the agent (invariant 1). It is created after the service is up
  (``Guardian.run`` starts it), so "the lock is taken and there is no socket yet" means "the
  service is starting".
- Only the service's own user may talk to it: ``SO_PEERCRED`` is read on every connection and
  another uid gets a refusal before a byte of its request is read. Fails closed: if the
  credentials cannot be read, the connection is refused.
- One JSON object per connection, on one line, at most 4 KiB, and 5 s to send it (a total
  deadline, not per read: a client that sends a byte every 4 s does not get more time):
  ``{"cmd": "rewind", "snapshot_id": ...}`` or ``{"cmd": "resume"}``, with exactly those keys.
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

from vigia.blackbox import redact
from vigia.service.pause import RESUME_EXIT_CODES, ResumeOutcome, ResumeStatus
from vigia.service.rewind import EXIT_CODES, RewindOutcome, RewindStatus
from vigia.snapshots import Snapshot

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 4096
REQUEST_TIMEOUT = 5.0  # seconds, in total, to receive a request
REPLY_TIMEOUT = 5.0  # seconds to hand the reply to a client that does not read it
MAX_CONNECTIONS = 8
DRAIN_SECONDS = 1.0  # after replying, read what is left so the reply is not lost to a reset
DRAIN_BYTES = 1 << 20
WAIT_FOR_SERVICE = 10.0  # `vigia rebobinar`: how long to retry while the service starts
RETRY_EVERY = 0.25
CLIENT_REPLY_TIMEOUT = 15 * 60.0  # a rewind takes seconds; this only ends a dead service
MAX_REPLY_BYTES = 64 * 1024
_CREDENTIALS = struct.Struct("iII")  # struct ucred: pid, uid, gid

# What "outcome" can say. The rewind statuses, and "refused" for a request that was not served.
REFUSED = "refused"
OUTCOMES = frozenset({*(str(status) for status in RewindStatus), REFUSED})
RESUME_OUTCOMES = frozenset({*(str(status) for status in ResumeStatus), REFUSED})
# The exit code of `vigia rebobinar` and `vigia seguir` for each outcome (docs/19, "La CLI"): a
# refused request did nothing and was malformed or not allowed, which is a usage error like an
# invalid id. The two commands share "failed" (1) and "problem" (3).
OUTCOME_EXIT_CODES = {
    **{str(status): code for status, code in RESUME_EXIT_CODES.items()},
    **{str(status): code for status, code in EXIT_CODES.items()},
    REFUSED: EXIT_CODES[RewindStatus.INVALID],
}
_RESUME_OK = frozenset({ResumeStatus.RESUMED, ResumeStatus.NOT_PAUSED})


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


PeerCredentials = Callable[[socket.socket], tuple[int, int, int]]


def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """``(pid, uid, gid)`` of the process at the other end of a Unix socket, as the kernel
    recorded them when it connected (``SO_PEERCRED``; Linux only, which is where Vigía runs).
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
    ) -> None:
        self._guardian = guardian
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
            thread = threading.Thread(target=self._serve, args=(server,), name="vigia-control")
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
            self._reply(sock, _refusal("Solo el usuario que ejecuta Vigía puede pedir esto."))
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
        raise _BadRequest("Orden desconocida.")

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
        if set(request) != {"cmd", "snapshot_id"}:
            raise _BadRequest("Una petición de rebobinar lleva `cmd` y `snapshot_id`, y nada más.")
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
            outcome = self._guardian.rewind(snapshot_id, requested_by=f"cli (uid {uid}, pid {pid})")
        except (
            Exception
        ):  # the Guardian should not raise; if it does, nobody can tell what happened
            logger.exception("the rewind %s raised instead of answering", snapshot_id)
            outcome = RewindOutcome(
                RewindStatus.UNKNOWN,
                target=snapshot_id,
                message=(
                    "Ha fallado algo inesperado al rebobinar y no se sabe en qué punto. "
                    "Comprueba el estado con `vigia instantaneas`; Vigía lo concilia al "
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
                f"el socket de control {self._path} no ha quedado como debe (de Vigía y 0600)"
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
) -> dict[str, Any]:
    """Ask the service at ``path`` to rewind to ``snapshot_id`` and return its reply, checked:
    a dict whose ``outcome`` is known, ``ok`` a bool, ``message`` a str and ``undo`` a str or
    None. Everything else in it is ignored.

    While nobody answers (no socket yet, or a refused connection: the service is starting) it
    retries for ``wait`` seconds and then raises ControlUnavailable. Raises ControlError if the
    path is not a socket of ours, the server is not our user, or the reply makes no sense.
    Waits for the reply as long as ``reply_timeout``: a rewind takes seconds, and a client that
    gives up early would leave the person guessing whether it happened."""
    raw = _ask(
        Path(path),
        {"cmd": "rewind", "snapshot_id": snapshot_id},
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
    """Ask the service at ``path`` to resume after a pause by space (`vigia seguir`) and return
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
                "marcha: mira `vigia instantaneas` y la caja negra antes de repetirlo."
            ) from None
        except OSError as error:
            raise ControlOutcomeUnknown(
                f"Se ha perdido la conexión con el servicio ({error.strerror or error}). "
                f"No se sabe si {what} se hizo: mira `vigia instantaneas`."
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
                f"El que contesta en {path} es el usuario {uid}, no el que ejecuta Vigía: "
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
        "se hizo: mira `vigia instantaneas`."
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
            "mira `vigia instantaneas`."
        )
    return {
        "ok": reply["ok"],
        "outcome": reply["outcome"],
        "undo": reply["undo"],
        "message": reply["message"],
        "agent_started": reply.get("agent_started") is True,
    }
