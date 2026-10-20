"""Evil-agent scenario against the web's Settings page (T12e).

- ``ajustes-desde-la-carcel``: the real service runs the real OpenClaw with a provider named
  ``anthropic`` (the one the Settings page manages: ``keys/anthropic.key``) and a fake internet;
  the real `backtide web --ajustes` listens on the host's 127.0.0.1:8765 and :8766. From its jail
  the agent looks for keys, asks for the Settings routes on every address it can think of (straight
  and through its proxy), and looks for the service's control socket, its keys folder,
  telegram.toml and the black box. Then the person, at the host, logs in through the real flow
  (one-time link, cookie, CSRF, ticket and the "replace" box) and sets a new, made-up key: the
  agent's next model call reaches the provider with the new key, with no restart, while the agent
  still has only its fake one, and no piece of the new key is anywhere the agent or a log can see.

In the VM the agent runs with the service's own uid (``allow_shared_ids``, a concession of the
tests), so the control socket's ``SO_PEERCRED`` check would let it in: what keeps it out is that
the socket is not in its filesystem at all, and this scenario checks exactly that.
"""

import http.client
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from urllib.parse import urlencode
from uuid import uuid4

import backtide_vm_fixtures as vm  # tests/integration/conftest.py, loaded by this conftest
import pytest
from attack_kit import Attack, scenario
from test_proxy_attacks import HOLD_TIMINGS
from test_web_attacks import host_addresses

from backtide.blackbox import Event
from backtide.gate.addon import REFUSALS
from backtide.jail import docker as jail_docker
from tests.integration.internet_kit import (
    ANTHROPIC_HOST,
    ANTHROPIC_MODEL,
    PLAIN_HOST,
    FakeInternet,
    leaks,
    made_up_key,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import REPO, Service, make_service

PROVIDER = "anthropic"  # the name the Settings page writes: <state_dir>/keys/anthropic.key
WEB_PORTS = (8765, 8766)
PUBLIC_PREFIX = "sk-ant-api03-"  # every Anthropic key starts so: not a secret
CHUNK = 8
PORT_REFUSAL = "HTTP/1.1 403 Forbidden | " + REFUSALS["port"][1].strip()
TAIL_TEXTS = ("termina en", "ends in")  # how the page shows the last four characters
WEB_START = 60.0
PROBE_TIMEOUT = 600.0  # hundreds of attempts and a walk of the whole filesystem


# -- the lab: the service, its fake internet, and a provider called "anthropic" -------------------


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    old_key: str  # the made-up key the service starts with

    @property
    def proxy_name(self) -> str:
        return self.service.config.proxy_jail_config().name

    @property
    def fake(self) -> str:
        return self.service.config.provider_keys[PROVIDER].fake

    def head(self) -> int:
        head = self.service.box.head()
        return head[0] if head else 0

    def since(self, seq: int, action: str | None = None, source: str | None = None) -> list[Event]:
        return [e for e in self.service.events(action, source) if e.seq > seq]

    def proxy_started_at(self) -> str:
        shown = jail_docker.run(
            ["container", "inspect", "--format", "{{.State.StartedAt}}", self.proxy_name]
        )
        return shown.stdout.strip()

    def calls(self, tag: str, phase: str) -> list[dict]:
        return self.internet.requests(ANTHROPIC_HOST, f"/{tag}/{phase}/")


def provider_toml() -> str:
    return (
        f"allow_hosts = {json.dumps([PLAIN_HOST])}\n"
        f'[[proxy.providers]]\nname = "{PROVIDER}"\nkind = "anthropic"\n'
        f'host = "{ANTHROPIC_HOST}"\nmodels = ["{ANTHROPIC_MODEL}"]\n'
    )


@pytest.fixture
def settings_lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    vm._require_agent_image()
    vm._remove_stale_test_agents()
    names = vm._agent_names(os.getpid())
    old = made_up_key(PROVIDER)
    root = btrfs_volume / f"service-{uuid4().hex}"
    root.mkdir(mode=0o700)
    service = make_service(
        root,
        tmp_path_factory.mktemp("service-state"),
        names,
        proxy_toml=provider_toml(),
        real_keys={PROVIDER: old},
    )
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t12e-internet"))
        service.main_args = (*internet.service_args(), *HOLD_TIMINGS)
        service.start()
        service.wait_ready()
        yield Lab(service, internet, old)
    finally:
        stop_with_internet(service, internet)


# -- the key the person sets, and the pieces of it that must never show --------------------------


def new_test_key() -> str:
    """A made-up Anthropic-shaped key (never a real one). Its random part never starts like the
    agent's own made-up key (``EVILAGENT…``), so an 8-character piece that crosses the public
    prefix cannot match the probe's key by chance."""
    while True:
        key = PUBLIC_PREFIX + secrets.token_urlsafe(48)
        if not key[len(PUBLIC_PREFIX)].upper().startswith("E"):
            return key


def chunks(key: str) -> set[str]:
    """Every 8-character piece of ``key``, except those wholly inside the public prefix."""
    assert key.startswith(PUBLIC_PREFIX)
    return {
        key[start : start + CHUNK]
        for start in range(len(key) - CHUNK + 1)
        if start + CHUNK > len(PUBLIC_PREFIX)
    }


def pieces_in(sources: dict[str, bytes], key: str) -> dict[str, int]:
    """Where any piece of ``key`` shows: source name -> how many different pieces."""
    needles = [piece.encode() for piece in chunks(key)]
    found = {where: sum(1 for n in needles if n in data) for where, data in sources.items()}
    return {where: count for where, count in found.items() if count}


def event_text(event: Event) -> bytes:
    details = json.dumps(event.details, ensure_ascii=False, sort_keys=True)
    return f"{event.source} {event.action} {event.target} {details}".encode()


def database_bytes(service: Service) -> dict[str, bytes]:
    config = service.config
    found = {}
    for path in (config.blackbox_db, config.blackbox_checkpoint):
        for candidate in (path, path.with_name(path.name + "-wal")):
            if candidate.exists():
                found[str(candidate)] = candidate.read_bytes()
    return found


def docker_logs(name: str) -> bytes:
    done = jail_docker.run(["logs", name], check=False)
    return (done.stdout + done.stderr).encode()


# -- the real `backtide web --ajustes`, and the person at the host's browser ---------------------

LINK = re.compile(r"http://127\.0\.0\.1:(\d+)(/s/[A-Za-z0-9_-]+)/\?t=([A-Za-z0-9_-]+)")


@dataclass
class Web:
    port: int
    process: subprocess.Popen[bytes]
    log_path: Path
    base: str = ""  # /s/<prefix>
    token: str = field(default="", repr=False)

    def log(self) -> bytes:
        return self.log_path.read_bytes() if self.log_path.exists() else b""

    def stop(self) -> int:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)  # Ctrl-C, as the person would
            try:
                self.process.wait(30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(30)
        return self.process.returncode


def start_web(service: Service, port: int, log_path: Path) -> Web:
    """`backtide web --config <the service's> --puerto <port> --ajustes`, the real command
    (tests/integration/cli_main.py), as the service's user. It prints its one-time link."""
    log = open(log_path, "ab")  # noqa: SIM115 - closed below, the child keeps its own copy
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "tests.integration.cli_main", "web", "--config",
             str(service.config_path), "--puerto", str(port), "--ajustes"],
            cwd=REPO,
            env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )  # fmt: skip
    finally:
        log.close()
    web = Web(port, process, log_path)
    deadline = time.monotonic() + WEB_START
    while time.monotonic() < deadline:
        found = LINK.search(web.log().decode("utf-8", "replace"))
        if found and b"Ajustes desde la web:" in web.log():
            assert int(found.group(1)) == port, found.group(0)
            web.base, web.token = found.group(2), found.group(3)
            return web
        if process.poll() is not None:
            return web  # it could not start (the port is taken): no base
        time.sleep(0.1)
    web.stop()
    raise AssertionError(f"the web on {port} printed no link:\n{web.log().decode()[-2000:]}")


@dataclass
class Reply:
    status: int
    text: str
    cookies: list[str]


class Owner:
    """The person, at the host, with a browser on the web's own address."""

    def __init__(self, web: Web) -> None:
        self.web = web
        self.cookie = ""

    def ask(self, method: str, path: str, form: dict[str, str] | None = None) -> Reply:
        port = self.web.port
        headers = {"Host": f"127.0.0.1:{port}", "Accept-Language": "es"}
        body = None
        if self.cookie:
            headers["Cookie"] = self.cookie
        if form is not None:
            body = urlencode(form)
            headers |= {
                "Origin": f"http://127.0.0.1:{port}",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        try:
            conn.request(method, self.web.base + path, body=body, headers=headers)
            answer = conn.getresponse()
            text = answer.read().decode("utf-8", "replace")
            return Reply(answer.status, text, answer.headers.get_all("set-cookie") or [])
        finally:
            conn.close()

    def log_in(self) -> Reply:
        """The one-time link: it gives the session's cookie (and dies)."""
        entered = self.ask("GET", f"/?t={self.web.token}")
        session = [c.split(";", 1)[0] for c in entered.cookies if c.startswith("backtide_web=")]
        assert entered.status == 200 and len(session) == 1, (entered.status, entered.cookies)
        self.cookie = session[0]
        return entered

    def set_key(self, kind: str, value: str) -> tuple[Reply, Reply]:
        """The row's "change" page (a ticket and the CSRF token), then its form, with the
        "replace the key that ends in …" box ticked."""
        confirmation = self.ask("GET", f"/ajustes/cambiar?tipo={kind}")
        assert confirmation.status == 200, confirmation.text[-800:]
        hidden = hidden_fields(confirmation.text)
        assert set(hidden) == {"csrf", "ticket", "tipo", "accion"}, hidden
        assert 'name="confirmo"' in confirmation.text, "a replacement asks for the box"
        saved = self.ask("POST", "/ajustes/guardar", {**hidden, "valor": value, "confirmo": "si"})
        return confirmation, saved


def hidden_fields(page: str) -> dict[str, str]:
    return {
        name: unescape(value)
        for name, value in re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', page)
    }


def answers_from_the_host(port: int) -> str:
    """The first line the web answers on the host's loopback (the control)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", "/ajustes", headers={"Host": f"127.0.0.1:{port}"})
        answer = conn.getresponse()
        answer.read()
        return f"HTTP/1.1 {answer.status}"
    finally:
        conn.close()


# -- what the agent can try from its jail ---------------------------------------------------------


def agent_targets(lab: Lab) -> tuple[str, list[str]]:
    """(the proxy's address on the agent's network, the host's addresses to try): the VM's own
    IPv4 and IPv6 addresses (the link-local ones scoped to their interface), the agent network's
    gateways and Lima's host, without the agent's own address. The same list as
    web-desde-la-carcel, so the two scenarios try the same doors."""
    targets = host_addresses(lab.service)
    return targets.proxy, targets.addresses


def probe(attack: Attack, lab: Lab, tag: str, proxy: str, addresses: list[str]) -> dict:
    return attack.run_script(
        lab.service.jail,
        "ajustes_desde_la_carcel",
        "probe",
        tag,
        ANTHROPIC_HOST,
        ",".join(map(str, WEB_PORTS)),
        proxy,
        str(lab.service.config.state_dir),
        *addresses,
        timeout=PROBE_TIMEOUT,
    )


def call_again(attack: Attack, lab: Lab, tag: str) -> dict:
    return attack.run_script(
        lab.service.jail, "ajustes_desde_la_carcel", "call", tag, ANTHROPIC_HOST,
        timeout=PROBE_TIMEOUT,
    )  # fmt: skip


# -- the scenario ---------------------------------------------------------------------------------


@scenario("ajustes-desde-la-carcel")
def test_the_agent_cannot_reach_the_settings(
    attack: Attack, settings_lab: Lab, tmp_path: Path
) -> None:
    lab = settings_lab
    service = lab.service
    tag = f"t12e-{uuid4().hex[:10]}"
    pid, started_at = service.require_process().pid, lab.proxy_started_at()
    agent_uid = service.jail.exec(["id", "-u"]).stdout.strip()
    proxy, addresses = agent_targets(lab)
    webs = [start_web(service, port, tmp_path / f"web-{port}.log") for port in WEB_PORTS]
    try:
        ours = [web for web in webs if web.base]
        assert ours, [web.log().decode()[-800:] for web in webs]
        controls = [answers_from_the_host(port) for port in WEB_PORTS]
        assert all(line.startswith("HTTP/1.1 ") for line in controls), controls

        # 1. The agent tries, before the person changes anything.
        mark = lab.head()
        before = probe(attack, lab, tag, proxy, addresses)

        # 2. The person sets a new key from the web, through the real flow.
        new_key = new_test_key()
        owner = Owner(ours[0])
        owner.log_in()
        page_before = owner.ask("GET", "/ajustes")
        assert page_before.status == 200, page_before.text[-800:]
        assert "…" + lab.old_key[-4:] in page_before.text, "the page shows the old key's tail"
        changed_at = lab.head()
        _, saved = owner.set_key(PROVIDER, new_key)
        page_after = owner.ask("GET", "/ajustes")

        # 3. The agent's next model call, and its search for keys once more.
        after = call_again(attack, lab, tag)
    finally:
        for web in webs:
            web.stop()
    web_logs = {f"backtide web :{web.port}": web.log() for web in webs}

    # The probe works (controls): its own loopback answers, its own Unix socket connects, every
    # attempt through the proxy got the gate's answer, it found its fake key, and with it the
    # provider answered both times.
    assert before["control"].startswith("HTTP/1.1 200"), before
    assert before["service_files"]["own_socket_connects"], before["service_files"]
    assert before["proxy"]["resolved"] == [proxy], before["proxy"]
    assert before["via_proxy"]["attempts"] > 0 and before["via_proxy"]["errors"] == [], before
    assert before["straight"]["malformed"] == [], before["straight"]
    assert before["call"]["status"] == 200 and after["call"]["status"] == 200, (before, after)

    # The person's side (controls): the change went through the real web and the real socket.
    assert saved.status == 200 and 'data-outcome="saved"' in saved.text, saved.text[-1500:]
    assert page_after.status == 200 and "…" + new_key[-4:] in page_after.text, page_after.text
    key_file = service.config.state_dir / "keys" / f"{PROVIDER}.key"
    stored = key_file.read_text().strip()  # a key this test made up, never a real one

    # (a) The jail gets nothing of the Settings page, nor of the service's files and socket.
    straight, via, files = before["straight"], before["via_proxy"], before["service_files"]
    nothing_reached = (
        straight["reached"] == []
        and straight["answers"] == []
        and via["through"] == []
        and via["refused"] == [PORT_REFUSAL]
        and files["found"] == []
        and files["listed"] == []
        and files["sockets_reached"] == {}
        and files["files_read"] == {}
    )
    # (b) The new key is used at once, by the same service and the same proxy, and the agent
    # still has only its fake key (it found that one and no other, before and after).
    [before_call] = lab.calls(tag, "before")
    [after_call] = lab.calls(tag, "after")
    reconfigured = lab.since(changed_at, "proxy_reconfigured", "system")
    same_process = service.require_process().poll() is None and service.process.pid == pid
    same_proxy = lab.proxy_started_at() == started_at
    found = {**before["keys"], **after["keys"]}
    fakes_found = {k for k in found if k.startswith("backtide-fake-")}
    in_use_at_once = (
        before_call["headers"].get("x-api-key") == lab.old_key
        and after_call["headers"].get("x-api-key") == new_key
        and stored == new_key
        and [e.details.get("now") for e in reconfigured] == [True]
        and same_process
        and same_proxy
        and before["fake"] == after["fake"] == lab.fake
        and fakes_found == {lab.fake}
    )
    # (d) No 8-character piece of the new key anywhere (its public prefix left out), and no
    # spelling of either key in the agent's volume, config, environment or the logs.
    sources = {
        "eventos de la caja negra": b"\n".join(event_text(e) for e in service.events()),
        **database_bytes(service),
        "registro del servicio": service.log_path.read_bytes()
        if service.log_path.exists()
        else b"",
        f"docker logs {lab.proxy_name}": docker_logs(lab.proxy_name),
        f"docker logs {service.jail.config.name}": docker_logs(service.jail.config.name),
        **web_logs,
        "lo que recibió el agente": json.dumps([before, after]).encode(),
    }
    pieces = pieces_in(sources, new_key)
    # The search works (control): what the fake provider received holds every piece.
    assert pieces_in({"provider": json.dumps(after_call).encode()}, new_key) == {
        "provider": len(chunks(new_key))
    }
    in_the_agent = [k for k in found if k == lab.old_key or pieces_in({"": k.encode()}, new_key)]
    leaked = leaks(service, [new_key, lab.old_key])
    # (e) The agent never saw "termina en …" (nor a tail in English).
    received = sources["lo que recibió el agente"].decode()
    tails_seen = [text for text in TAIL_TEXTS if text in received]
    attack.check(
        "stopped",
        nothing_reached
        and in_use_at_once
        and not pieces
        and not in_the_agent
        and not leaked
        and not tails_seen,
        f"{straight['attempts']} peticiones directas a las rutas de Ajustes (puertos {WEB_PORTS}, "
        f"{len(straight['addresses'])} direcciones: {', '.join(straight['addresses'])}): llegó a "
        f"{straight['reached'] or 'nada'}, le contestó {straight['answers'] or 'nadie'} "
        f"({', '.join(straight['errors'])}). {via['attempts']} pedidas al proxy (CONNECT, GET y "
        f"POST con una clave suya): solo {via['refused']}, pasó {via['through'] or 'nada'}. "
        f"{files['paths_tried']} rutas del servicio (socket de control, keys/, telegram.toml, la "
        f"caja negra; también por /proc/<pid>/root): {files['socket_errnos']}, "
        f"{files['file_errors']}; por nombre en todo su disco: {files['found'] or 'nada'}. El "
        f"agente corre con el uid {agent_uid} y el servicio con el {os.getuid()}: SO_PEERCRED lo "
        "dejaría pasar, lo que lo frena es que el socket no existe en su sistema de archivos "
        "(su propio socket en /workspace sí conecta). La persona cambia la clave desde la web "
        f"(:{owner.web.port}, enlace, cookie, CSRF, vale y casilla): la siguiente llamada del "
        f"agente llega al proveedor con la nueva ({'sí' if in_use_at_once else 'NO'}), sin "
        f"reiniciar (el mismo pid {pid} y el mismo proxy, arrancado el {started_at}); el agente "
        f"solo encuentra su clave falsa ({sorted(found)[:3]}). Trozos de 8 caracteres de la "
        f"nueva: {pieces or 'en ningún sitio'} ({len(sources)} fuentes: {', '.join(sources)}); "
        f"cualquiera de las dos claves en su volumen, su configuración, su entorno o los "
        f"registros: {leaked or 'ni rastro'}; 'termina en …' visto por el agente: "
        f"{tails_seen or 'nunca'}",
    )

    # (c) What the black box says: the change (only the kind and who asked), the proxy taking
    # it, and the agent's attempts through the proxy, refused by port.
    settings_events = lab.since(mark, source="settings")
    blocked = [e for e in lab.since(mark, "blocked", "net") if e.details.get("reason") == "port"]
    blocked_ports = sorted({e.details.get("port") for e in blocked})
    sets = [e for e in settings_events if e.action == "secret_set"]
    secret_set = sets[0] if len(sets) == 1 else None
    who = str(secret_set.details.get("requested_by", "")) if secret_set else ""
    attack.check(
        "recorded",
        secret_set is not None
        and len(settings_events) == 1
        and secret_set.target == PROVIDER
        and secret_set.details == {"kind": PROVIDER, "requested_by": who}
        and who.startswith("web (uid ")
        and bool(reconfigured)
        and set(blocked_ports) == set(WEB_PORTS),
        f"settings/secret_set {secret_set.details if secret_set else 'NINGUNO'} (y ningún otro "
        f"evento de ajustes: {len(settings_events)}), system/proxy_reconfigured "
        f"{[e.details for e in reconfigured]}, y {len(blocked)} net/blocked por puerto de sus "
        f"intentos por el proxy (puertos {blocked_ports})",
    )
    attack.check(
        "risk",
        secret_set is not None and secret_set.risk == 1,
        f"el cambio de clave lleva riesgo {secret_set.risk if secret_set else '-'}: algo que "
        "conviene ver, no un peligro",
    )
