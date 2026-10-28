"""Run the web: bind 127.0.0.1 only, make the access token, serve until Ctrl-C.

Who runs it. Two ways, and the web tells which one it is (in the terminal and on the snapshots
page). Writes are explicit: without ``--rebobinar`` (``can_rewind``) and ``--ajustes``
(``can_set``, the Settings page of T12e, which works the same way: by asking the service) the web
only watches, whoever runs it, and as root it refuses to start (to watch, use a reader).

- As a lower-privileged READER (the safe default for watching): not root, not the service's
  user. The web reads one file, ``blackbox.db`` (plus its ``-wal`` and ``-shm``), and the
  volume's snapshot list: no key, no gateway token. Give an ordinary user read access to the
  state directory and those files (for example a ``backtide`` group with ``chmod g+rx`` on the
  directory and ``g+r`` on ``blackbox.db``, ``blackbox.db-wal`` and ``blackbox.db-shm``, which
  the service creates 0600 today) and run ``backtide web`` as that user. NEVER give the group ``w``
  on any of them, not even on ``-shm``: a writable ``-shm`` lets a lower-privileged reader
  corrupt the WAL index, and with it the black box. With a read-only ``-shm``, SQLite 3.22 or
  newer reads while the service holds the database open; without the service running, the page
  says the box cannot be read (``BoxUnavailable``), which is correct. If the volume cannot be
  listed, the snapshots page falls back to the black box's own ``snapshot/take`` events. A
  reader CANNOT rewind: the control socket is 0600 and the service answers only its own uid
  (``SO_PEERCRED``), so the buttons are disabled and say why. That is on purpose: nothing gives
  the reader a way to change the agent's workspace.
- As the SERVICE'S USER with ``--rebobinar`` (T12b): then the web can also rewind, by asking the
  service through its control socket, exactly like `backtide rebobinar` (``backtide.web.rewind``).
  The honest price: the web process then has every privilege of that user. It still never opens the
  key or the token (``WebPaths`` does not even know where they are), but a bug in it would be a bug
  with those privileges, and in production the service runs as root. Everything a browser can send
  it goes through ``Guard`` first (``backtide.web.security``): a single POST path, from our own
  page, with the session cookie, the CSRF token and a one-time confirmation. As root,
  `backtide web --rebobinar` starts, and says so.
- As a READER given the service's NARROW SOCKET (``--socket-web``, T12c, decision 27): what the
  installed web does (``backtide-web.service``, as ``backtide-web``). The service (root) opens
  ``<state_dir>/web.sock`` for that group only (``backtide.service.web_control``), and takes there
  a closed list: the snapshot list and a rewind to one in it, the held requests and approving or
  rejecting one, the Settings page's keys and caps. Everything ``--rebobinar``, ``--aprobar`` and
  ``--ajustes`` turn on goes through it (each still needs its flag), and so does the snapshot list
  (the volume is root's 0700): no privilege of the service's comes into this process. The socket
  is a second wall, not the only one: the ``Guard``, the CSRF token and the confirmations are the
  same.

Not done yet: the data through the control socket (so a reader needs no file at all), and a
"verified up to event N" that the SERVICE publishes (it holds the key and is the only one that
can say the chain is intact). Until then the web shows events as written and says nothing about
integrity.

The socket is bound HERE, to the loopback address and nothing else, and handed to uvicorn: there
is no setting that could make it listen on a network interface, and with ``--port 0`` we learn
the real port before the app is built (its ``Host`` check needs it).
"""

import logging
import re
import socket
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType

import uvicorn

from backtide.service.control import ControlError
from backtide.service.web_control import ask_snapshots
from backtide.snapshots import Snapshot, SnapshotError, SnapshotStore
from backtide.web.agents import AgentSource, PendingRequest
from backtide.web.app import create_app
from backtide.web.approve import Approver, ControlApprover
from backtide.web.paths import WebPaths
from backtide.web.reader import BoxReader
from backtide.web.rewind import WAIT_FOR_SERVICE, ControlRewinder
from backtide.web.security import make_prefix, make_run_name, make_token
from backtide.web.settings import ControlSettings, ControlSpend, SettingsClient

# The installed service runs as root: the narrow socket and the process behind it must be root's.
SERVICE_UID = 0

logger = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8765
GRACEFUL_SECONDS = 2  # Ctrl-C must not wait for an open event stream


def bind(port: int) -> socket.socket:
    """A listening socket on 127.0.0.1:``port`` (0: any free port). Raises OSError if taken."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOOPBACK, port))
        sock.listen(64)
        sock.set_inheritable(True)
    except OSError:
        sock.close()
        raise
    return sock


class _Server(uvicorn.Server):
    """uvicorn, except that a stop signal ends the run instead of killing the process.

    After a graceful shutdown uvicorn re-raises each signal it caught (so a parent sees "died of
    SIGINT"), which with Python's own handler back in place means a ``KeyboardInterrupt``
    traceback, or death by SIGTERM, before ``backtide web`` can print its closing line and exit
    0. The signal has done its job once the server has stopped: we forget it.

    ``_captured_signals`` is uvicorn's own (0.54.0, locked in uv.lock; pyproject only asks for
    0.54 or newer): if an upgrade renames it, nothing is cleared, we say so in the log, and
    tests/test_web_server.py fails, rather than this going quiet."""

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        super().handle_exit(sig, frame)
        captured = getattr(self, "_captured_signals", None)
        if isinstance(captured, list):
            captured.clear()
        else:
            logger.warning("uvicorn changed: a stop signal may end `backtide web` by itself")


def make_server(app: Callable) -> uvicorn.Server:  # type: ignore[type-arg]
    """A uvicorn server for ``app`` (it is given the socket when it runs). No access log: the
    first request's address carries the token."""
    config = uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        server_header=False,
        date_header=False,
        proxy_headers=False,
        ws="none",
        lifespan="off",
        timeout_graceful_shutdown=GRACEFUL_SECONDS,
        limit_concurrency=64,
    )
    return _Server(config)


def web_url(port: int, prefix: str, token: str) -> str:
    return f"http://{LOOPBACK}:{port}/s/{prefix}/?t={token}"


_WEB_URL = re.compile(
    rf"http://{re.escape(LOOPBACK)}:(?P<port>[0-9]{{1,5}})/s/[A-Za-z0-9_-]{{8,64}}/\?t=[A-Za-z0-9_-]{{16,128}}",
    re.ASCII,
)


def web_url_problem(text: str) -> str | None:
    """None if ``text`` is a link exactly as ``web_url`` makes it (`backtide enlace` prints
    nothing else), else why not."""
    match = _WEB_URL.fullmatch(text)
    if match is None:
        return "it is not a link of this web"
    if not 0 < int(match["port"]) <= 65535:
        return "its port is out of range"
    return None


def run_web(
    paths: WebPaths,
    port: int,
    announce: Callable[[str, str], None],
    *,
    snapshots: Callable[[], list[Snapshot]] | None = None,
    can_rewind: bool = False,
    can_set: bool = False,
    can_approve: bool = False,
    settings: SettingsClient | None = None,
    approver: Approver | None = None,
    agent_name: str | None = None,
    others: Sequence[AgentSource] = (),
    pending: Callable[[], Sequence[PendingRequest]] | None = None,
    web_socket: Path | None = None,
) -> None:
    """Serve the web of ``paths`` on 127.0.0.1:``port`` until the process is stopped.
    ``announce`` gets the link with the token (printed once, never logged) and the name of
    this run, to compare with the one on the page. ``snapshots`` lists the snapshots; it is
    the volume's own list (``SnapshotStore``) unless given, which only the Mac's demo does
    (scripts/web-demo/serve.py: there is no btrfs there). ``can_rewind`` is `--rebobinar`:
    without it the rewind buttons stay disabled whoever runs the web. ``can_set`` is `--ajustes`
    (T12e): without it the Settings page only says how to turn it on, and its POST does not
    exist; ``settings`` replaces the control socket's client (the Mac's demo). ``can_approve`` is
    `--aprobar` (T10-5): without it the held requests are listed from the black box with their
    buttons disabled, and the POST that decides does not exist; ``approver`` replaces the
    control socket's client (the demo). ``agent_name``,
    ``others`` (more agents, each read by its own ``BoxReader``) and ``pending`` (the gate's
    requests) are only given by the demo today: T17 and T10 will fill them for real.
    ``web_socket`` is `--socket-web` (T12c): the service's narrow socket for the web's group,
    asked instead of the control socket for everything, the snapshot list included."""
    sock = bind(port)
    real_port = sock.getsockname()[1]
    token, prefix, run_name = make_token(), make_prefix(), make_run_name()
    reader = BoxReader(paths.blackbox_db)

    def from_volume() -> list[Snapshot]:
        return SnapshotStore(paths.volume).snapshots()

    control, server_uid = paths.control_socket, None
    if web_socket is not None:
        control, server_uid = web_socket, SERVICE_UID

    def from_service() -> list[Snapshot]:
        try:
            return ask_snapshots(control, server_uid=SERVICE_UID, wait=WAIT_FOR_SERVICE)
        except ControlError as error:  # the pages say the list cannot be read
            raise SnapshotError(str(error)) from None

    app = create_app(
        reader=reader,
        port=real_port,
        token=token,
        prefix=prefix,
        run_name=run_name,
        snapshots=snapshots or (from_volume if web_socket is None else from_service),
        rewinder=ControlRewinder(control, enabled=can_rewind, server_uid=server_uid),
        settings=settings or ControlSettings(control, enabled=can_set, server_uid=server_uid),
        approver=approver or ControlApprover(control, enabled=can_approve, server_uid=server_uid),
        spend=ControlSpend(control, server_uid=server_uid),
        agent_name=agent_name,
        others=others,
        pending=pending,
        agent_lines=paths.agent_lines,
    )
    server = make_server(app)
    announce(web_url(real_port, prefix, token), run_name)
    try:
        server.run(sockets=[sock])
    finally:
        reader.close()
        for other in others:
            other.reader.close()
        sock.close()
