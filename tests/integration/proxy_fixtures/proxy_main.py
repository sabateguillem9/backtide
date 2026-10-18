"""T06-1: a minimal mitmproxy built from Python (``DumpMaster``, never ``mitmdump -s``).

Runs in the pinned mitmproxy image as ``python3 /opt/t06/proxy_main.py`` in the test's proxy
container. The options are those of docs/21, section 1, set in the code; an unknown option
raises and the process dies (no proxy, no way out). There is no ``flow_detail``: it belongs
to the dumper addon, which is not loaded (``with_dumper=False``), so no flow is ever printed.
The only test-only option is ``ssl_verify_upstream_trusted_ca``: the fake internet's CA.
``T06_STRATEGY=eager`` is the control case of P6.

The test addons do something only for some hosts of the fake internet (all ``*.fake.test``):

- ``p6*``: the request hook asks the fake internet how many TLS connections it has accepted,
  waits HOOK_DELAY seconds and asks again, and passes both numbers on in ``x-t06-accepts``.
  ``p6-deny``: answers 403 itself.
- ``p7-sync``/``p7-async``: the request hook raises (sync or async); ``p7-connect``: the
  server_connect hook raises; ``p7-wrapped``: it raises inside a wrapper that answers 502.
- ``p8``: server_connect resolves the name, then points ``server.address`` at that IP and port
  8443 without touching the SNI; ``p8-sni`` sets the SNI to the name as well. The response
  carries what the hook saw (``x-t06-*``).

Prints READY_LINE from the ``running`` hook, once the proxy listens.
"""

import asyncio
import json
import os
import socket

from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

READY_LINE = "t06-proxy-ready"
CONTROL = ("control.fake.test", 9000)
HOOK_DELAY = 1.0

SETTINGS = {
    "mode": ["regular@8080"],
    "confdir": "/ca",
    "connection_strategy": os.environ.get("T06_STRATEGY", "lazy"),
    "upstream_cert": False,
    "ssl_insecure": False,
    "ssl_verify_upstream_trusted_ca": "/opt/t06/internet-ca.pem",
    "http3": False,
    "rawtcp": False,
    "tcp_hosts": [],
    "udp_hosts": [],
    "ignore_hosts": [],
    "onboarding": False,
    # No stream_large_bodies: it streams requests too, before the request hook (T06-4).
    "body_size_limit": "16m",
    "termlog_verbosity": "warn",
    "block_global": True,
}


async def fake_accepts() -> int:
    """How many TLS connections the fake internet's 443 has accepted so far (plain HTTP)."""
    reader, writer = await asyncio.open_connection(*CONTROL)
    writer.write(b"GET /stats HTTP/1.0\r\nHost: control\r\n\r\n")
    await writer.drain()
    data = await reader.read()
    writer.close()
    body = data.split(b"\r\n\r\n", 1)[1]
    return int(json.loads(body)["accepts"]["443"])


class SyncHooks:
    """Plain (not async) hooks, for P7's sync case."""

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host == "p7-sync.fake.test":
            raise RuntimeError("t06 sync request hook failure")


class Probe:
    def __init__(self) -> None:
        self.at_connect: dict[str, dict[str, str]] = {}

    def running(self) -> None:
        print(READY_LINE, flush=True)

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if host == "p6-deny.fake.test":
            flow.response = http.Response.make(403, b"refused by the test addon\n")
        elif host.startswith("p6") or host == "eager.fake.test":
            before = await fake_accepts()
            await asyncio.sleep(HOOK_DELAY)
            after = await fake_accepts()
            flow.request.headers["x-t06-accepts"] = f"{before},{after}"
        elif host == "p7-async.fake.test":
            raise RuntimeError("t06 async request hook failure")
        elif host == "p7-wrapped.fake.test":
            try:
                raise RuntimeError("t06 wrapped request hook failure")
            except Exception:  # noqa: BLE001 - the wrapper of docs/21 section 4, on trial
                flow.response = http.Response.make(502, b"refused: addon error\n")

    async def server_connect(self, data) -> None:  # noqa: ANN001 - ServerConnectionHookData
        host, port = data.server.address
        if host == "p7-connect.fake.test":
            raise RuntimeError("t06 server_connect hook failure")
        if host not in ("p8.fake.test", "p8-sni.fake.test"):
            return
        seen = {"sni-at-connect": str(data.server.sni), "address-at-connect": f"{host}:{port}"}
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
        data.server.address = (ip, 8443)
        if host == "p8-sni.fake.test":
            data.server.sni = host
        seen["address-set"] = f"{ip}:8443"
        self.at_connect[data.server.id] = seen

    def response(self, flow: http.HTTPFlow) -> None:
        seen = self.at_connect.pop(flow.server_conn.id, None)
        if flow.response is not None and seen:
            for name, value in seen.items():
                flow.response.headers[f"x-t06-{name}"] = value
            flow.response.headers["x-t06-sni-sent"] = str(flow.server_conn.sni)


async def main() -> None:
    opts = options.Options(confdir=SETTINGS["confdir"])
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    opts.update(**SETTINGS)  # KeyError on an unknown option: the process dies
    master.addons.add(SyncHooks(), Probe())
    await master.run()


if __name__ == "__main__":
    asyncio.run(main())
