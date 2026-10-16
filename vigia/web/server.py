"""Run the web: bind 127.0.0.1 only, make the access token, serve until Ctrl-C.

Who runs it: NOT root, and not as the service. The web reads one file, ``blackbox.db`` (plus its
``-wal`` and ``-shm``), and the volume's snapshot list: no key, no gateway token, no socket. Give
an ordinary user read access to the state directory and those files (for example a ``vigia``
group with ``chmod g+rx`` on the directory and ``g+r`` on the database, which the service creates
0600 today) and run ``vigia web`` as that user. Reading a WAL database needs the ``-shm`` file
too; if the volume cannot be listed, the snapshots page falls back to the black box's own
``snapshot/take`` events.

T12b: the data should come through the control socket instead, so the web needs no file at all,
together with a "verified up to seq N" that the SERVICE publishes (it holds the key and is the
only one that can say the chain is intact). Until then the web shows events as written and says
nothing about integrity.

The socket is bound HERE, to the loopback address and nothing else, and handed to uvicorn: there
is no setting that could make it listen on a network interface, and with ``--port 0`` we learn
the real port before the app is built (its ``Host`` check needs it).
"""

import socket
from collections.abc import Callable

import uvicorn

from vigia.snapshots import Snapshot, SnapshotStore
from vigia.web.app import create_app
from vigia.web.paths import WebPaths
from vigia.web.reader import BoxReader
from vigia.web.security import make_prefix, make_run_name, make_token

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
    return uvicorn.Server(config)


def web_url(port: int, prefix: str, token: str) -> str:
    return f"http://{LOOPBACK}:{port}/s/{prefix}/?t={token}"


def run_web(
    paths: WebPaths,
    port: int,
    announce: Callable[[str, str], None],
) -> None:
    """Serve the web of ``paths`` on 127.0.0.1:``port`` until the process is stopped.
    ``announce`` gets the link with the token (printed once, never logged) and the name of
    this run, to compare with the one on the page."""
    sock = bind(port)
    real_port = sock.getsockname()[1]
    token, prefix, run_name = make_token(), make_prefix(), make_run_name()
    reader = BoxReader(paths.blackbox_db)

    def snapshots() -> list[Snapshot]:
        return SnapshotStore(paths.volume).snapshots()

    app = create_app(
        reader=reader,
        port=real_port,
        token=token,
        prefix=prefix,
        run_name=run_name,
        snapshots=snapshots,
    )
    server = make_server(app)
    announce(web_url(real_port, prefix, token), run_name)
    try:
        server.run(sockets=[sock])
    finally:
        reader.close()
        sock.close()
