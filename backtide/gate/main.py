"""The egress proxy's process: mitmproxy built from Python, with the gate's addon.

What the proxy container runs (``python3 -m backtide.gate.main``, backtide/jail/proxy_config.py).
Design: docs/21-diseno-t06-proxy.md, sections 1 and 5.

- A ``DumpMaster`` with the options of docs/21 written here, never ``mitmdump -s``: with ``-s``
  an addon that fails to load is logged and mitmproxy goes on without it, letting everything
  through. Here a failed import kills the process, and a dead proxy lets nothing out. An
  unknown option raises too (KeyError), and so the process dies (T06-1, P1).
- No ``dumper`` addon: nothing prints a flow (URLs carry secrets in their queries).
- The channel's socket (``/run/backtide/events.sock``, backtide/gate/client.py) listens BEFORE
  the ready line is printed, so backtide can connect as soon as ``ProxyJail.wait_ready`` returns.
  Until backtide has connected and sent its config, every request gets a 503 (addon.py).
- Only the agent's side may use it. mitmproxy listens on every interface, the egress one too,
  where the host (any local user) and whatever else reaches that network could connect. So a
  client is let in only if it connected to the proxy's own address on the agent's network,
  which the proxy learns by resolving its alias there; if that fails, nobody is let in.

Its environment (proxy_config.proxy_env): ``BACKTIDE_UID``, the only uid allowed to connect to
the channel (missing: the process dies). The VM tests add two concessions that backtide's own
config can never set: ``BACKTIDE_TEST_PUBLIC`` (addresses of their fake internet, let through as
if public) and ``BACKTIDE_TEST_UPSTREAM_CA`` (the PEM of their fake internet's CA).

Imports the standard library, mitmproxy and ``backtide.gate`` (which brings
``backtide.blackbox.redact``); never the service.
"""

import asyncio
import logging
import os
import socket
from collections.abc import Mapping
from typing import Any

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

import backtide
from backtide.gate.addon import Gate
from backtide.gate.client import Channel

logger = logging.getLogger(__name__)

# backtide/jail/proxy_config.py waits for this line in the logs (a unit test keeps both equal).
READY_LOG_LINE = "backtide-proxy ready"
AGENT_SIDE_ALIAS = "backtide-proxy"  # backtide/jail/config.py PROXY_ALIAS: only on that network
CHANNEL_DIR = "/run/backtide"  # proxy_config.CONTAINER_CHANNEL_DIR
TEST_CA_FILE = "/tmp/backtide-test-upstream-ca.pem"  # noqa: S108 - the proxy's own tmpfs

# docs/21, section 1 ("Opciones de mitmproxy"). Every name must exist, or the process dies.
OPTIONS = {
    "mode": ["regular@8080"],
    "confdir": "/ca",  # mitmproxy-ca.pem and mitmproxy-dhparam.pem, read-only (ca.py)
    "connection_strategy": "lazy",  # no connection to a server before the request hook
    "upstream_cert": False,  # never connect to copy a server's certificate first
    "ssl_insecure": False,  # the proxy checks the real servers' certificates
    "http3": False,
    "rawtcp": False,
    "tcp_hosts": [],
    "udp_hosts": [],
    "ignore_hosts": [],  # nothing passes without being intercepted
    "onboarding": False,  # no mitm.it page
    # No "stream_large_bodies": mitmproxy applies it to REQUESTS too, and a streamed request
    # goes out before the request hook (T06-4's review). Responses stream through the gate's own
    # tap (addon.py), every one of them.
    "body_size_limit": "16m",
    "termlog_verbosity": "warn",
    "block_global": True,  # serve only clients with a private address
    # Refuse malformed requests before any hook: h2 >= 4.3.0 then rejects CR, LF and NUL in an
    # HTTP/2 header (CVE-2025-57804), which mitmproxy would otherwise write as is to an HTTP/1.1
    # server (request smuggling). On by default in mitmproxy 12.2.3; pinned so it stays on. The
    # gate checks the same itself (addon.py, ``malformed_framing``).
    "validate_inbound_headers": True,
}


def agent_side_addresses() -> frozenset[str]:
    """The proxy's own addresses on the agent's network: its alias resolves only there."""
    try:
        infos = socket.getaddrinfo(AGENT_SIDE_ALIAS, None, type=socket.SOCK_STREAM)
    except OSError:
        return frozenset()
    return frozenset(str(info[4][0]).removeprefix("::ffff:") for info in infos)


def respond(status: int, content: bytes, headers: Mapping[str, str]) -> http.Response:
    return http.Response.make(status, content, dict(headers))


class Ready:
    """Prints the ready line once mitmproxy listens (the channel listens already)."""

    def running(self) -> None:
        print(READY_LOG_LINE, flush=True)  # noqa: T201 - the one line ProxyJail waits for


def grants_from_env(env: Mapping[str, str]) -> tuple[frozenset[str], dict[str, Any]]:
    """The VM tests' concessions: addresses taken as public, and mitmproxy options."""
    public = frozenset(a for a in env.get("BACKTIDE_TEST_PUBLIC", "").split(",") if a)
    extra: dict[str, Any] = {}
    pem = env.get("BACKTIDE_TEST_UPSTREAM_CA")
    if pem:
        with open(TEST_CA_FILE, "w") as file:
            file.write(pem)
        extra["ssl_verify_upstream_trusted_ca"] = TEST_CA_FILE
    return public, extra


async def main() -> None:
    backtide_uid = int(os.environ["BACKTIDE_UID"])  # missing: the process dies
    public, extra = grants_from_env(os.environ)
    channel = Channel(
        CHANNEL_DIR, backtide_uid=backtide_uid, version=backtide.__version__, pid=os.getpid()
    )
    await channel.start()
    opts = options.Options(confdir=OPTIONS["confdir"])
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    opts.update(**OPTIONS, **extra)  # KeyError on an unknown option: the process dies
    gate = Gate(channel, respond=respond, agent_side=agent_side_addresses, public=public)
    master.addons.add(gate, Ready())
    await master.run()


if __name__ == "__main__":
    asyncio.run(main())
