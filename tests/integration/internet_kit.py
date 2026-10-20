"""The fake internet of a VM test service (T06-5): T06-1's HTTPS servers on the service's own
egress network, the fake model providers among them, and the grants the proxy needs to use it.

A test service's egress network is ``--internal`` (proxy_kit), so with this kit the proxy reaches
exactly one container, ``proxy_fixtures/fake_internet.py`` with a test CA of its own: every name in
``HOSTS`` is an alias of it. Nothing can reach the internet, no real provider is ever contacted,
and every key is one the test made (invariant 8).

    internet = start_fake_internet(service, root)   # before service.start()
    service.main_args = internet.service_args()      # the proxy's three grants
    ...
    internet.remove()                                 # before the service's cleanup

The grants are the tests' concessions of docs/21, "En la VM" (``egress_neighbours``,
``test_public_addresses``, ``test_upstream_ca``, and since T06-7 ``test_dns``: the fake internet's
resolver as the proxy's upstream DNS); no config file can set them. service_main.py
reads them (``proxy_kit.read_grants``) from the JSON file ``--egress-grants`` names.
"""

import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from backtide.jail import docker as jail_docker
from backtide.jail import proxy_config
from tests.integration.proxy_kit import test_proxy
from tests.integration.service_kit import Service
from tests.integration.test_proxy_assumptions import (
    FIXTURES,
    INTERNET_READY,
    STATS,
    hardened,
    ip_on,
    make_ca,
    make_server_cert,
    unique,
    wait_for_line,
)

FAKE_UID = 61002
CONTAINER_PREFIX = "backtide-test-agent-"  # under the cleanup's prefixes (conftest)
ANTHROPIC_HOST = "anthropic.fake.test"
OPENAI_HOST = "openai.fake.test"
PLAIN_HOST = "plain.fake.test"  # an ordinary allowed host: it answers with what reached it
OTHER_HOST = "other.fake.test"  # a host of the fake internet that is NOT allowed
# T06-7 (login-oauth): the real login hosts, as aliases of the fake internet (with names in its
# certificate), so the proxy's OAuth rule is what stops a login and not the missing host. Inside
# the test's internal network only: nothing real is ever contacted (invariant 8).
OAUTH_LOGIN_HOSTS = (
    "auth.openai.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
    "sts.windows.net",
    "claude.ai",
    "console.anthropic.com",
    "platform.claude.com",
    "api.anthropic.com",
    "github.com",
    "openrouter.ai",
)
# T10-3 (un-get-que-envia): the Bot API's host, so the gate's Telegram translator reads what the
# agent sends there. The fake internet answers it (with what reached it): a fake Bot API inside
# the test's internal network, never Telegram (invariant 8).
TELEGRAM_HOST = "api.telegram.org"
HOSTS = (ANTHROPIC_HOST, OPENAI_HOST, PLAIN_HOST, OTHER_HOST, TELEGRAM_HOST, *OAUTH_LOGIN_HOSTS)
REPLY_TEXT = "T06 PONG FROM THE FAKE MODEL"  # proxy_fixtures/fake_internet.py
GRANTS_OPTION = "--egress-grants"


# The fake providers: names OpenClaw has no catalog of, so each brings its model (T06-1, P9).
ANTHROPIC = "t06-anthropic"
OPENAI = "t06-openai"
ANTHROPIC_MODEL = "fake-claude"
OPENAI_MODEL = "fake-gpt"


def provider_toml(*, openai: bool = True) -> str:
    """The ``[[proxy.providers]]`` of a test service: the fake Anthropic (the agent's default
    model) and, with ``openai``, the fake OpenAI-compatible one."""
    text = (
        f'[[proxy.providers]]\nname = "{ANTHROPIC}"\nkind = "anthropic"\n'
        f'host = "{ANTHROPIC_HOST}"\nmodels = ["{ANTHROPIC_MODEL}"]\n'
    )
    if openai:
        text += (
            f'[[proxy.providers]]\nname = "{OPENAI}"\nkind = "openai"\n'
            f'host = "{OPENAI_HOST}"\nmodels = ["{OPENAI_MODEL}"]\n'
        )
    return text


def made_up_key(provider: str) -> str:
    """A real-looking key that only this test run knows: what the fake provider must receive."""
    return f"sk-test-t06-{provider}-{secrets.token_urlsafe(24)}"


@dataclass
class FakeInternet:
    name: str
    ip: str
    ca_pem: str  # the test internet CA's certificate (the proxy's test_upstream_ca)
    grants_file: Path

    def service_args(self) -> tuple[str, ...]:
        return (GRANTS_OPTION, str(self.grants_file))

    def stats(self) -> dict:
        done = jail_docker.run(["exec", self.name, "python3", "-c", STATS], timeout=30)
        return json.loads(done.stdout)

    def requests(self, host: str | None = None, path_prefix: str = "") -> list[dict]:
        """What reached it (each with its headers and SNI), for ``host`` and paths under
        ``path_prefix``."""
        return [
            r
            for r in self.stats()["requests"]
            if (host is None or (r["host"] or "").split(":")[0] == host)
            and r["path"].startswith(path_prefix)
        ]

    def accepts(self) -> dict[str, int]:
        """TCP connections accepted per listener (counted before TLS)."""
        return self.stats()["accepts"]

    def dns_queries(self) -> list[dict]:
        """Every query its resolver got (``name``, ``proto``, ``from``): it is the proxy's
        upstream DNS (``test_dns``), so these are the names the proxy tried to resolve."""
        return self.stats()["dns"]

    def dns_errors(self) -> dict[str, int]:
        """How often its resolver failed to read or answer a query (by protocol)."""
        return self.stats()["dns_errors"]

    def remove(self) -> None:
        jail_docker.run(["rm", "--force", "--volumes", self.name], check=False)


def start_fake_internet(service: Service, root: Path) -> FakeInternet:
    """Make the service's egress network (as its proxy will find it) and start the fake
    internet on it. The service must not be running yet."""
    root.mkdir(mode=0o755, exist_ok=True)
    root.chmod(0o755)
    certs, files, internet = root / "certs", root / "t06", root / "internet"
    for folder in (certs, files, internet):
        folder.mkdir(exist_ok=True)
    ca_key, ca_cert = make_ca(certs, "T06-5 test internet CA", 2048, 30)
    server_pem = make_server_cert(certs, ca_key, ca_cert, (TELEGRAM_HOST, *OAUTH_LOGIN_HOSTS))
    shutil.copyfile(server_pem, internet / "server.pem")
    shutil.copyfile(FIXTURES / "fake_internet.py", files / "fake_internet.py")
    for folder in (files, internet):
        for path in folder.iterdir():
            path.chmod(0o444)
        folder.chmod(0o555)
    proxy = test_proxy(service.config)
    proxy.ensure_network()
    name = unique(CONTAINER_PREFIX)
    argv = hardened(name, FAKE_UID) + ["--network", proxy.config.network]
    for host in HOSTS:
        argv += ["--network-alias", host]
    argv += [
        "--volume", f"{files}:/opt/t06:ro,z",
        "--volume", f"{internet}:/opt/internet:ro,z",
        "--entrypoint", "python3", proxy_config.IMAGE, "/opt/t06/fake_internet.py",
    ]  # fmt: skip
    jail_docker.run(argv)
    fake = FakeInternet(name, "", ca_cert.read_text(), root / "grants.json")
    try:
        jail_docker.run(["start", name])
        wait_for_line(name, INTERNET_READY)
        fake.ip = ip_on(name, proxy.config.network)
        fake.grants_file.write_text(
            json.dumps(
                {
                    "egress_neighbours": [name],
                    "test_public_addresses": [fake.ip],
                    "test_upstream_ca": fake.ca_pem,
                    "test_dns": [fake.ip],  # its resolver is the proxy's upstream (T06-7)
                }
            )
        )
        fake.grants_file.chmod(0o600)
    except BaseException:
        fake.remove()
        raise
    return fake


def stop_with_internet(service: Service, internet: FakeInternet | None) -> None:
    """End a test service that has a fake internet: the service first (its proxy leaves the
    egress network), then the fake internet, then everything else of the service (the egress
    network can only go once nobody is on it)."""
    process = service.process
    try:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(30)
    finally:
        if internet is not None:
            internet.remove()
        service.shutdown()


def spellings(value: str) -> set[str]:
    """How a secret could show up: as is, in lower case, URL-encoded and in base64."""
    raw = value.encode()
    return {
        value,
        value.lower(),
        quote(value, safe=""),
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
    }


def _files_under(root: Path) -> Iterator[Path]:
    for directory, _, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            if path.is_file() and not path.is_symlink():
                yield path


def leaks(service: Service, values: list[str]) -> list[str]:
    """Where any spelling of any of ``values`` shows: the black box (database, WAL, checkpoint),
    the service's log, ``docker logs`` of the proxy and of the agent, the agent's whole volume
    (its workspace and every snapshot), its config folder, the sensor's and the channel's
    folders, and its environment (``docker
    inspect`` and ``/proc/1/environ``). An empty list means nowhere."""
    needles = [s.encode() for value in values for s in spellings(value)]
    found: list[str] = []

    def look(where: str, data: bytes) -> None:
        if any(needle in data for needle in needles):
            found.append(where)

    config = service.config
    for path in (config.blackbox_db, config.blackbox_checkpoint):
        for candidate in (path, path.with_name(path.name + "-wal")):
            if candidate.exists():
                look(str(candidate), candidate.read_bytes())
    look("service log", service.log_path.read_bytes() if service.log_path.exists() else b"")
    for name in (config.proxy_jail_config().name, config.jail_config().name):
        logs = jail_docker.run(["logs", name], check=False)
        look(f"docker logs {name}", (logs.stdout + logs.stderr).encode())
        inspect = jail_docker.run(["inspect", name], check=False)
        look(f"docker inspect {name}", inspect.stdout.encode())
    roots = (
        service.store.workspace,
        service.store.snapshots_dir,
        config.agent_config_dir,
        config.sensor_dir,
        config.proxy_channel_dir,
    )
    for root in roots:
        for path in _files_under(root):
            try:
                look(str(path), path.read_bytes())
            except OSError:
                found.append(f"{path} (unreadable)")
    if service.jail.is_running():
        environ = service.jail.exec(["cat", "/proc/1/environ"], timeout=30)
        look("the agent's /proc/1/environ", environ.stdout.encode())
        env = service.jail.exec(["env"], timeout=30)
        look("the agent's env", env.stdout.encode())
    return found
