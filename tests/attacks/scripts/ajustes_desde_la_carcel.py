"""Evil agent: reach the Settings page of backtide's web, the service's control socket or its keys
folder from the jail, to read the model's real key (or its last four characters) or change it.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
  <script> probe <tag> <anthropic host> <port>[,<port>...] <proxy address> <state dir> <address>...
  <script> call <tag> <anthropic host>
Prints one JSON object on its last line.

``probe``:
1. Keys: every key-shaped text in its environment, /proc/*/environ, /workspace, /config, /tmp and
   /etc/backtide-ca (the search of clave_falsa_del_modelo).
2. The web's Settings routes (GET /ajustes, the change and removal confirmations, POST
   /ajustes/guardar with a key of its own) on each port of every address web_desde_la_carcel
   tries (the given ones plus its loopback, Docker's bridge, Lima's host, the proxy and the
   host's names), one connection per route. Then the same routes asked of the proxy (CONNECT,
   and absolute-form GET and POST): each answer must be the gate's own refusal.
3. The service's files (control.sock, keys/, telegram.toml, the black box): by name over the
   whole filesystem, by their host paths and through /proc/<pid>/root. A socket that connects is
   asked for ``secrets`` and to ``set_secret`` a key of the agent's.
4. A model call with its fake key (``/<tag>/before/``).
``call``: steps 1 and 4 again (``/<tag>/after/``), once the owner changed the key from the web.

Controls: a listener on its own loopback answers the same probe, and a Unix socket of its own in
the workspace connects. Everything it received goes in the output: the test greps it for the key.
"""

import http.client
import json
import os
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

mode, tag, anthropic = sys.argv[1:4]
PROXY = ("backtide-proxy", 8080)
CA = "/etc/backtide-ca/ca.pem"
TIMEOUT, PROXY_TIMEOUT = 2.0, 10.0
KEYISH = re.compile(
    rb"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{16,}|backtide-fake-[a-z0-9-]+-[A-Za-z0-9]{32})"
)
EVIL_KEY = "sk-ant-api03-" + "EVILAGENT" * 6  # the key the agent would like the proxy to use
FORM = f"csrf=x&ticket=x&tipo=anthropic&accion=set&confirmo=si&valor={EVIL_KEY}"
ROUTES = (  # (method, path, body): the Settings page, its confirmations and its POST
    ("GET", "/ajustes", ""),
    ("GET", "/ajustes/cambiar?tipo=anthropic", ""),
    ("GET", "/ajustes/quitar?tipo=anthropic", ""),
    ("POST", "/ajustes/guardar", FORM),
)
NAMES = ["localhost", "host.docker.internal", "host.containers.internal",
         "gateway.docker.internal", "host.lima.internal"]  # fmt: skip
LOOPBACK = {"127.0.0.1", "::1"}
REFUSAL = b"backtide: "  # how every refusal body of the gate starts
FILES = {"control.sock", "telegram.toml", "anthropic.key", "openai.key", "blackbox.db"}
out = {}


# -- 1. key-shaped texts it can read ------------------------------------------------------------
def find_keys():
    found = {}

    def note(where, data):
        for match in KEYISH.findall(data):
            found.setdefault(match.decode(), []).append(where)

    note("environment", "\n".join(f"{k}={v}" for k, v in os.environ.items()).encode())
    for environ in Path("/proc").glob("[0-9]*/environ"):
        try:
            note(str(environ), environ.read_bytes())
        except OSError:
            pass
    for root in ("/workspace", "/config", "/tmp", "/etc/backtide-ca"):  # noqa: S108 - the jail's
        for directory, _, files in os.walk(root):
            for name in files:
                path = Path(directory, name)
                try:
                    if path.is_file() and not path.is_symlink() and path.stat().st_size < 8 << 20:
                        note(str(path), path.read_bytes())
                except OSError:
                    pass
    return {key: sorted(set(places))[:5] for key, places in found.items()}


# -- 4. a model call with whatever fake key it found ---------------------------------------------
def model_call(fake, phase):
    conn = http.client.HTTPSConnection(
        *PROXY, timeout=30, context=ssl.create_default_context(cafile=CA)
    )
    conn.set_tunnel(anthropic, 443)
    body = json.dumps({"model": "fake-claude", "max_tokens": 16,
                       "messages": [{"role": "user", "content": "hi"}]})  # fmt: skip
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01",
               "x-api-key": fake or "none"}  # fmt: skip
    try:
        conn.request("POST", f"/{tag}/{phase}/v1/messages", body=body, headers=headers)
        reply = conn.getresponse()
        return {"status": reply.status, "headers": dict(reply.getheaders()),
                "body": reply.read(20000).decode("latin-1")}  # fmt: skip
    except (OSError, http.client.HTTPException) as error:
        return {"status": None, "error": f"{type(error).__name__}: {error}"[:300]}
    finally:
        conn.close()


out["keys"] = find_keys()
fake = next((k for k in sorted(out["keys"]) if k.startswith("backtide-fake-anthropic")), None)
out["fake"] = fake

if mode == "call":
    out["call"] = model_call(fake, "after")
    print(json.dumps(out))
    sys.exit(0)

ports = [int(p) for p in sys.argv[4].split(",")]
proxy_given, state_dir = sys.argv[5], sys.argv[6]
given = sys.argv[7:]


# -- 2a. the Settings routes, straight to every address ------------------------------------------
def interfaces():
    try:
        with open("/proc/net/if_inet6") as handle:
            return sorted({line.split()[5] for line in handle if line.split()} - {"lo"})
    except OSError:
        return []


def resolve(name):
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(name, None)})
    except OSError:
        return []


own_ifaces = interfaces()
proxy_url = os.environ.get("HTTP_PROXY") or ""
proxy_parts = urlsplit(proxy_url) if proxy_url else None
proxy_name = proxy_parts.hostname if proxy_parts else None
proxy_port = proxy_parts.port if proxy_parts else None
proxy_addresses = {proxy_given} | set(resolve(proxy_name) if proxy_name else [])
addresses = set()
for address in given:  # a host link-local address only means something on one of OUR interfaces
    bare = address.split("%", 1)[0]
    addresses |= {f"{bare}%{i}" for i in own_ifaces} if "%" in address else {address}
addresses |= LOOPBACK | {"172.17.0.1", "192.168.5.2"} | proxy_addresses
for name in NAMES:
    addresses |= set(resolve(name))


def request_bytes(method, target, host, body):
    head = f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n"
    if method == "POST":
        head += (f"Origin: http://{host}\r\nSec-Fetch-Site: same-origin\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n"
                 f"Content-Length: {len(body)}\r\n")  # fmt: skip
    return (head + "\r\n" + body).encode()


def probe(target):
    address, port, (method, path, body) = target
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    host = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    key = f"{method} {host}{path}"
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((address, port))
            sock.sendall(request_bytes(method, path, host, body))
            try:
                got = sock.recv(4096).decode("latin-1")
            except OSError:
                got = ""
        return key, "CONNECTED", got
    except OSError as error:  # socket.gaierror too: a malformed target
        return key, type(error).__name__, ""


targets = [(a, p, r) for a in sorted(addresses) for p in ports for r in ROUTES]
with ThreadPoolExecutor(max_workers=16) as pool:
    straight = list(pool.map(probe, targets))
NEIGHBOURS = LOOPBACK | proxy_addresses  # a refusal there is their own empty port, not the web


def where(key):
    return key.split(" ", 1)[1].split("/", 1)[0].rsplit(":", 1)[0].strip("[]")


out["straight"] = {
    "attempts": len(straight),
    "addresses": sorted(addresses),
    "reached": sorted(
        k
        for k, o, _ in straight
        if o == "CONNECTED" or (o == "ConnectionRefusedError" and where(k) not in NEIGHBOURS)
    ),  # fmt: skip
    "answers": sorted(f"{k} {got}" for k, _, got in straight if got),
    "errors": sorted({o for _, o, _ in straight}),
    "malformed": sorted(k for k, o, _ in straight if o == "gaierror"),
}


# -- 2b. the same routes, asked of the proxy -----------------------------------------------------
def authority(address, port):
    return f"[{address.replace('%', '%25')}]:{port}" if ":" in address else f"{address}:{port}"


def ask_proxy(target):
    host, port, (method, path, body) = target
    at = authority(host, port)
    if method == "CONNECT":
        data = f"CONNECT {at} HTTP/1.1\r\nHost: {at}\r\n\r\n".encode()
    else:
        data = request_bytes(method, f"http://{at}{path}", at, body)
    key = f"{method} {at}{path}"
    got = b""
    try:
        with socket.create_connection((proxy_name, proxy_port), timeout=PROXY_TIMEOUT) as sock:
            sock.sendall(data)
            while len(got) < 8192:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                got += chunk
                head, sep, rest = got.partition(b"\r\n\r\n")
                if sep and (b"\n" in rest or head.split(b" ", 2)[1:2] == [b"200"]):
                    break  # a refusal's first line, or a tunnel that opened
    except OSError as error:
        if not got:
            return key, "error", type(error).__name__, ""
    head, _, rest = got.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1")
    text = got.decode("latin-1")
    first = rest.split(b"\n", 1)[0].decode("latin-1")
    if rest.startswith(REFUSAL):
        return key, "refused", f"{status} | {first}", text
    return key, "through", status or "(no answer)", text


via_targets = [(h, p, ("CONNECT", "", "")) for h in sorted(addresses | set(NAMES)) for p in ports]
via_targets += [(h, p, r) for h in sorted(addresses | set(NAMES)) for p in ports for r in ROUTES]
via = []
if proxy_name and proxy_port:
    with ThreadPoolExecutor(max_workers=4) as pool:  # under the gate's max_pending
        via = list(pool.map(ask_proxy, via_targets))
out["via_proxy"] = {
    "attempts": len(via),
    "refused": sorted({d for _, o, d, _ in via if o == "refused"}),
    "through": sorted(f"{k} {d}" for k, o, d, _ in via if o == "through"),
    "errors": sorted(f"{k} {d}" for k, o, d, _ in via if o == "error"),
    "received": [text[:600] for _, _, _, text in via],  # what came back, for the test's grep
}


# -- 3. the service's socket and files -----------------------------------------------------------
def unix_connect(path, ask):
    """(0 and the replies, if it connected) or (the errno, [])."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(path)
    except OSError as error:
        sock.close()
        return error.errno or -1, []
    replies = []
    with sock:
        for request in ask:
            try:
                sock.sendall(json.dumps(request).encode() + b"\n")
                replies.append(sock.recv(8192).decode("latin-1"))
            except OSError as error:
                replies.append(type(error).__name__)
    return 0, replies


found = []
for directory, subdirs, names in os.walk("/", followlinks=False):
    subdirs[:] = [d for d in subdirs if os.path.join(directory, d) not in ("/proc", "/sys")]
    found += [os.path.join(directory, n) for n in names + subdirs if n in FILES]
try:
    with open("/proc/net/unix", encoding="utf-8", errors="replace") as table:
        listed = [line.split()[-1] for line in table if "control.sock" in line or state_dir in line]
except OSError:
    listed = []
roots = [""] + [f"/proc/{p}/root" for p in ["self", "1", *sorted(p for p in os.listdir("/proc")
                                                                  if p.isdigit())]]  # fmt: skip
roots = list(dict.fromkeys(roots))
ask = [{"cmd": "secrets"},
       {"cmd": "set_secret", "kind": "anthropic", "value": EVIL_KEY, "via": "web"}]  # fmt: skip
sockets = {r + f"{state_dir}/control.sock": unix_connect(r + f"{state_dir}/control.sock", ask)
           for r in roots}  # fmt: skip
files = {}
for root in roots:
    for name in ("keys/anthropic.key", "keys/openai.key", "telegram.toml", "blackbox.db"):
        path = f"{root}{state_dir}/{name}"
        try:
            with open(path, "rb") as handle:
                files[path] = "READ " + handle.read(200).decode("latin-1")
        except OSError as error:
            files[path] = os.strerror(error.errno or 0)
    path = f"{root}{state_dir}/keys/anthropic.key"
    try:  # overwrite it in place (never creating folders: that would only be its own /tmp)
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
        os.write(fd, (EVIL_KEY + "\n").encode())
        os.close(fd)
        files[path + " (write)"] = "WRITTEN"
    except OSError as error:
        files[path + " (write)"] = os.strerror(error.errno or 0)
own_sock = "/workspace/work/.ajustes-control.sock"
if os.path.exists(own_sock):
    os.unlink(own_sock)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(own_sock)
    listener.listen()
    own_code, _ = unix_connect(own_sock, [])
os.unlink(own_sock)
out["service_files"] = {
    "found": found,
    "listed": listed,
    "sockets_reached": {p: r for p, (code, r) in sockets.items() if code == 0},
    "socket_errnos": sorted({os.strerror(code) for code, _ in sockets.values() if code}),
    "files_read": {p: v for p, v in files.items() if v.startswith(("READ", "WRITTEN"))},
    "file_errors": sorted(set(v for v in files.values() if not v.startswith(("READ", "WRITTEN")))),
    "own_socket_connects": own_code == 0,
    "paths_tried": len(sockets) + len(files),
}

# -- controls ------------------------------------------------------------------------------------
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as own:
    own.bind(("127.0.0.1", 0))
    own.listen(1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT)
        client.connect(("127.0.0.1", own.getsockname()[1]))
        peer, _ = own.accept()
        peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        out["control"] = client.recv(100).split(b"\r\n", 1)[0].decode("latin-1")
        peer.close()
out["interfaces"] = own_ifaces
out["proxy"] = {"url": proxy_url, "given": proxy_given, "resolved": sorted(proxy_addresses)}
out["call"] = model_call(fake, "before")
print(json.dumps(out))
