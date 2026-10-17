"""The egress proxy's process: mitmproxy built from Python, with the gate's addon.

What the proxy container runs (``python3 -m backtide.gate.main``, backtide/jail/proxy_config.py).
Design: docs/21-diseno-t06-proxy.md, section 1.

- A ``DumpMaster`` with the options of docs/21 written here, never ``mitmdump -s``: with ``-s``
  an addon that fails to load is logged and mitmproxy goes on without it, letting everything
  through. Here a failed import kills the process, and a dead proxy lets nothing out. An
  unknown option raises too (KeyError), and so the process dies (T06-1, P1).
- No ``dumper`` addon: nothing prints a flow (URLs carry secrets in their queries).
- T06-2: the addon REFUSES EVERYTHING. Nothing is recorded yet (the channel to backtide comes
  in T06-4), so nothing may go out: every request gets a 503 from the proxy itself, before
  its body is read, and no connection to any server is ever opened (``server_connect`` fails
  each one; with ``connection_strategy=lazy`` none is attempted before a request is let
  through, T06-1 P6). Each hook is wrapped: mitmproxy carries on after a hook raises (T06-1,
  P7), so on any error the flow is killed.

Imports only the standard library and mitmproxy (it runs in the proxy's image, where backtide
is not installed): never the service.
"""

import asyncio
import logging
import os

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

logger = logging.getLogger(__name__)

# backtide/jail/proxy_config.py waits for this line in the logs (a unit test keeps both equal).
READY_LOG_LINE = "backtide-proxy ready"
REFUSAL = b"backtide: nothing goes out until it can be recorded\n"

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
    "stream_large_bodies": "1m",
    "body_size_limit": "16m",
    "termlog_verbosity": "warn",
    "block_global": True,  # serve only clients with a private address
}


class RefuseEverything:
    """The gate while nothing records: no request is answered by anyone but the proxy."""

    def running(self) -> None:
        print(READY_LOG_LINE, flush=True)  # noqa: T201 - the one line ProxyJail waits for

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        _refuse(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        _refuse(flow)  # again: whatever a hook before did, the answer is still no

    def server_connect(self, data: object) -> None:
        """Every connection to a server fails before it is opened."""
        try:
            data.server.error = "backtide: no connection while nothing records"  # type: ignore[attr-defined]
        except Exception:  # mitmproxy would connect anyway: a dead proxy lets nothing out
            logger.exception("refusing a server connection failed: stopping the proxy")
            os._exit(70)


def _refuse(flow: http.HTTPFlow) -> None:
    try:
        flow.response = http.Response.make(503, REFUSAL, {"content-type": "text/plain"})
    except Exception:  # never let a request through because the refusal itself failed
        logger.exception("refusing a request failed: killing the flow")
        flow.kill()


async def main() -> None:
    opts = options.Options(confdir=OPTIONS["confdir"])
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    opts.update(**OPTIONS)  # KeyError on an unknown option: the process dies
    master.addons.add(RefuseEverything())
    await master.run()


if __name__ == "__main__":
    asyncio.run(main())
