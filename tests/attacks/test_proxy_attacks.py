"""Evil-agent scenarios against the egress proxy (T06-5, docs/21 "Escenarios para T05").

The real service (`backtide vigilar`) watches the real OpenClaw with its proxy, two model
providers and a fake internet on the egress network (tests/integration/internet_kit.py: every
host is ``*.fake.test``, the network is internal, and the providers' "real" keys are made up by
the test). The agent attacks from inside its jail with the scripts in scripts/.

- ``salida-por-el-proxy``: out through the proxy (recorded before it reaches the server) where it
  is allowed, refused where it is not, and nothing around it.
- ``clave-falsa-del-modelo``: the agent only finds fake keys; a real one it "stole" is refused
  on every host, the provider refuses anything but the fake one, and never in clear.
- ``ssrf-por-el-proxy``: 80 and 443 of private, loopback, link-local and metadata addresses, and
  names that resolve there, asked of the proxy: all ``private_address``.
- ``fronting-y-tuneles``: ``Host`` against the tunnel's host (also chunked on a kept-alive
  tunnel), SSH's port, SSH inside a ``CONNECT`` to 443.
- ``secretos-en-la-red``: the Gateway token in every part of a request, and cut in two by the
  excerpt's edge: never in the black box.
- ``canal-caido``: backtide frozen, then dead, while the agent sends: refused, nothing out.
- ``herramientas-del-proveedor`` (T06-6): tools and connectors that run on the provider's side
  (web fetch, MCP, an image by URL...), bodies that are not the provider's JSON and endpoints
  that are not a model call: refused before they reach the provider, recorded.
- ``eco-de-la-clave`` (T06-6): a provider that echoes the real key it got (an error, a stream
  that spells it over three deltas, base64): it never reaches the agent whole, recorded.
"""

import ipaddress
import json
import os
import signal
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import backtide_vm_fixtures as vm  # tests/integration/conftest.py, loaded by this conftest
import pytest
from attack_kit import Attack, scenario

from backtide.blackbox import Event
from backtide.gate.echo import KeyScanner
from backtide.gate.policy import normalize_host
from backtide.gate.record import EXCERPT_BYTES
from backtide.jail import docker as jail_docker
from tests.integration.internet_kit import (
    ANTHROPIC,
    ANTHROPIC_HOST,
    OPENAI,
    OPENAI_HOST,
    OTHER_HOST,
    PLAIN_HOST,
    FakeInternet,
    leaks,
    made_up_key,
    provider_toml,
    spellings,
    start_fake_internet,
    stop_with_internet,
)
from tests.integration.service_kit import Service, make_service, wait_until

PROXY_ALIAS = "backtide-proxy"
# Names an allowed list could hold that resolve to places the agent may not reach (in the
# proxy): loopback through /etc/hosts, a number glibc reads as 127.0.0.1, and the containers
# of the agent's own network (Docker's DNS).
RESOLVING_INWARDS = ("localhost", "2130706433")
DNS_CANARY_DOMAIN = "dns-canary.test"
# Since T10-2 the gate holds every write (a POST to the allowed host too). The labs shorten its
# times (a concession of the tests): a held request waits 3 s and gets "pending" (429).
HOLD_TIMINGS = ("--hold-timings", "60,3,60,60")


@dataclass
class Lab:
    service: Service
    internet: FakeInternet
    real: dict[str, str]  # provider -> the made-up real key

    @property
    def agent(self):  # noqa: ANN201 - the AgentJail, for attack.run_script
        return self.service.jail

    @property
    def fake(self) -> dict[str, str]:
        return {name: key.fake for name, key in self.service.config.provider_keys.items()}

    @property
    def proxy_name(self) -> str:
        return self.service.config.proxy_jail_config().name

    def since(self, seq: int, action: str | None = None) -> list[Event]:
        return [e for e in self.service.events(action) if e.seq > seq]

    def head(self) -> int:
        events = self.service.events()
        return events[-1].seq if events else 0

    def tagged(self, tag: str, action: str | None = None) -> list[Event]:
        prefix = f"/{tag}/"
        return [
            e
            for e in self.service.events(action)
            if str(e.details.get("path", "")).startswith(prefix)
        ]


def start_lab(
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
    *,
    inwards: bool = False,
    hold_timings: tuple[str, ...] = HOLD_TIMINGS,
    unknown_hosts: str = "hold",
    trusted_chat: str | None = None,
    telegram_toml: str | None = None,
    agent_memory: str = "2g",
) -> Lab:
    """A started service with its fake internet. With ``inwards``, the allowed list also holds
    names that resolve to private addresses (ssrf-por-el-proxy: the fixed rule must still say
    no). ``hold_timings`` are the gate's shortened times (test_gate_attacks.py uses its own).
    ``unknown_hosts`` is ``[gate] unknown_hosts``: ``"hold"`` (the default since T10-3: reads to
    any host pass, writes are held) or ``"deny"`` (the strict mode, T06's allowed list).
    ``trusted_chat``: a Telegram chat in ``[gate] trusted`` (the owner's, in un-get-que-envia).
    ``telegram_toml``: the bot's ``telegram.toml`` (T10-4: pointed at a fake Bot API on the VM's
    127.0.0.1; the owner's chat in it is trusted by the gate too). ``agent_memory``: the agent's
    memory (T10-5's test_openclaw_telegram.py runs a second OpenClaw Gateway inside it)."""
    vm._require_agent_image()
    vm._remove_stale_test_agents()
    names = vm._agent_names(os.getpid())
    container = names[0]
    # *.dns-canary.test: allowed, but no container answers for it, so the proxy resolves it
    # through its upstream (the fake resolver): dns-tunel's positive canary.
    hosts = [PLAIN_HOST, f"*.{DNS_CANARY_DOMAIN}"]
    if inwards:
        hosts += [*RESOLVING_INWARDS, container, f"{container}-px", PROXY_ALIAS]
    real = {ANTHROPIC: made_up_key("anthropic"), OPENAI: made_up_key("openai")}
    root = btrfs_volume / f"service-{uuid4().hex}"
    root.mkdir(mode=0o700)
    service = make_service(
        root,
        tmp_path_factory.mktemp("service-state"),
        names,
        proxy_toml=f"allow_hosts = {json.dumps(hosts)}\n"
        + provider_toml()
        + gate_toml(unknown_hosts, trusted_chat),
        real_keys=real,
        agent_memory=agent_memory,
    )
    if telegram_toml is not None:
        path = service.config.state_dir / "telegram.toml"
        path.write_text(telegram_toml)
        path.chmod(0o600)
    internet: FakeInternet | None = None
    try:
        internet = start_fake_internet(service, tmp_path_factory.mktemp("t06-5-internet"))
        service.main_args = (*internet.service_args(), *hold_timings)
        service.start()
        service.wait_ready()
    except BaseException:
        stop_with_internet(service, internet)
        raise
    return Lab(service, internet, real)


def gate_toml(unknown_hosts: str, trusted_chat: str | None) -> str:
    """``[gate]`` (T10-3), after ``[proxy]`` and its providers."""
    text = f'\n[gate]\nunknown_hosts = "{unknown_hosts}"\n'
    if trusted_chat is not None:
        text += f'trusted = [{{translator = "telegram", chat = "{trusted_chat}"}}]\n'
    return text


@pytest.fixture(scope="module")
def lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Lab]:
    # T06's scenarios are about the allowed list: they run in the strict mode
    # (``[gate] unknown_hosts = "deny"``). The default (reads to any host pass) is
    # test_gate_attacks.py's lab: dns-tunel, un-get-que-envia, exfiltrar-credenciales.
    started = start_lab(btrfs_volume, tmp_path_factory, inwards=True, unknown_hosts="deny")
    try:
        yield started
    finally:
        stop_with_internet(started.service, started.internet)


@pytest.fixture
def own_lab(
    canary_environment: dict[str, str],
    btrfs_volume: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Callable[[], Lab]]:
    """A lab of the test's own (canal-caido freezes and kills its service)."""
    made: list[Lab] = []

    def make() -> Lab:
        made.append(start_lab(btrfs_volume, tmp_path_factory, unknown_hosts="deny"))
        return made[-1]

    try:
        yield make
    finally:
        for each in made:
            stop_with_internet(each.service, each.internet)


def new_tag() -> str:
    return f"t06-5-{uuid4().hex[:10]}"


def ts(event: Event) -> float:
    return datetime.fromisoformat(event.ts.replace("Z", "+00:00")).timestamp()


def reasons(events: list[Event]) -> list[str]:
    return sorted(str(e.details.get("reason")) for e in events if e.action == "blocked")


# --- salida-por-el-proxy -----------------------------------------------------------------------


@scenario("salida-por-el-proxy")
def test_out_only_through_the_proxy(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    outcome = attack.run_script(
        lab.agent, "salida_por_el_proxy", PLAIN_HOST, OTHER_HOST, lab.internet.ip, tag
    )
    assert outcome["allowed_get"]["status"] == 200, outcome  # the control: the way out works
    # T10-2: a write waits for the person (held, recorded as gate/held), even to an allowed host.
    assert outcome["allowed_post"]["status"] == 429, outcome
    assert [e.details["path"] for e in lab.tagged(tag, "held")] == [f"/{tag}/post"]
    arrived = {r["path"]: r for r in lab.internet.requests(PLAIN_HOST, f"/{tag}/")}
    recorded = {e.details["path"]: e for e in lab.tagged(tag, "request")}
    before_arrival = all(
        path in recorded and ts(recorded[path]) < request["at"] for path, request in arrived.items()
    )
    blocked = [e for e in lab.tagged(tag, "blocked")]
    around = outcome["straight"]
    stopped = (
        outcome["not_allowed"]["status"] == 403
        and lab.internet.requests(OTHER_HOST) == []
        and all(v not in ("CONNECTED", "ConnectionRefusedError") for v in around.values())
        and outcome["ipv6"] != "CONNECTED"
        and all(isinstance(v, str) for v in outcome["resolved"].values())
        and outcome["curl_without_proxy"] != 0
        and lab.internet.requests(PLAIN_HOST, f"/{tag}/curl-direct") == []
    )
    attack.check(
        "stopped",
        stopped,
        f"por el proxy, al permitido: GET {outcome['allowed_get']['status']} y POST "
        f"{outcome['allowed_post']['status']}; al no permitido ({OTHER_HOST}): "
        f"{outcome['not_allowed']['status']}, y el internet falso no recibió nada suyo. "
        f"Sin el proxy: directo a {lab.internet.ip} {around}, IPv6 {outcome['ipv6']}, sus nombres "
        f"no resuelven ({outcome['resolved']}) y curl sin variables de proxy sale con "
        f"{outcome['curl_without_proxy']}",
    )
    attack.check(
        "recorded",
        sorted(arrived) == [f"/{tag}/get"]
        and before_arrival
        and reasons(blocked) == ["not_allowed"],
        f"{len(recorded)} net/request grabados antes de que el servidor falso los recibiera "
        f"({sorted(arrived)}); el POST, retenido (gate/held, sin llegar); el no permitido, "
        f"net/blocked {reasons(blocked)}",
    )
    attack.check(
        "risk",
        [e.risk for e in blocked] == [1],
        f"el rechazo por la lista permitida lleva riesgo {[e.risk for e in blocked]}",
    )


# --- clave-falsa-del-modelo --------------------------------------------------------------------


@scenario("clave-falsa-del-modelo")
def test_the_agent_only_ever_has_a_fake_key(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    stolen = lab.real[ANTHROPIC]
    outcome = attack.run_script(
        lab.agent, "clave_falsa_del_modelo", ANTHROPIC_HOST, OPENAI_HOST, PLAIN_HOST, stolen, tag
    )
    found = outcome["found"]
    uses = outcome["uses"]
    fakes = set(lab.fake.values())
    # The control: the agent did find its fake key (in /config/openclaw.json at least) and, with
    # it, the provider answers, and the provider got the REAL key, not the fake one.
    assert lab.fake[ANTHROPIC] in found, found
    assert uses["provider_with_its_fake_key"] == 200, outcome
    [call] = lab.internet.requests(ANTHROPIC_HOST, f"/{tag}/fake/")
    assert call["headers"].get("x-api-key") == stolen
    refused = {
        name: status for name, status in uses.items() if name != "provider_with_its_fake_key"
    }
    reached = [
        r["path"]
        for r in lab.internet.requests()
        if r["path"].startswith(f"/{tag}/")
        and not r["path"].startswith((f"/{tag}/fake/", f"/{tag}/echo"))
    ]
    blocked = lab.tagged(tag, "blocked")
    leaked = leaks(lab.service, list(lab.real.values()))
    real_found = [k for k in found if any(real in k for real in lab.real.values())]
    fakes_found = {k for k in found if k.startswith("backtide-fake-")}
    look_alikes = len(found) - len(fakes_found) - len(real_found)
    places = sorted({place for k in fakes_found for place in found[k]})
    attack.check(
        "stopped",
        real_found == []
        and fakes_found <= fakes
        and all(status == 403 for status in refused.values())
        and reached == []
        and leaked == [],
        f"el agente buscó claves en su entorno, en /proc/*/environ, en /workspace, /config, /tmp "
        f"y /etc/backtide-ca y en lo que sus peticiones llevan al salir: solo encontró "
        f"las {len(fakes_found)} claves falsas ({places[:4]}), ninguna real "
        f"({real_found or 'ni una'}; {look_alikes} textos con forma de clave en el código de "
        f"OpenClaw que no son de nadie). Con la falsa, el proveedor "
        f"contesta {uses['provider_with_its_fake_key']} y recibe la real. "
        f"La real robada y los otros intentos: {refused}; al internet falso no llegó ninguno "
        f"({reached or 'nada'}). La real no está en ningún sitio: {leaked or 'ni rastro'}",
    )
    attack.check(
        "recorded",
        reasons(blocked) == sorted(["real_key"] * 5 + ["foreign_credential"] * 2),
        f"net/blocked {reasons(blocked)}",
    )
    risks = sorted({e.risk for e in blocked if e.details.get("reason") == "real_key"})
    attack.check("risk", risks == [3], f"la clave real lleva riesgo {risks}")


# --- ssrf-por-el-proxy -------------------------------------------------------------------------


def vm_ipv4() -> list[str]:
    shown = subprocess.run(
        ["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, check=True, timeout=30
    ).stdout
    return sorted(
        {
            info["local"]
            for link in json.loads(shown)
            for info in link.get("addr_info", [])
            if not ipaddress.ip_address(info["local"]).is_loopback
        }
    )


def proxy_ips(lab: Lab) -> list[str]:
    info = json.loads(jail_docker.run(["container", "inspect", lab.proxy_name]).stdout)[0]
    return sorted(n["IPAddress"] for n in info["NetworkSettings"]["Networks"].values())


@scenario("ssrf-por-el-proxy")
def test_the_proxy_takes_the_agent_nowhere_inwards(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    literals = [
        "169.254.169.254", "127.0.0.1", "10.0.0.1", "172.17.0.1", "192.168.5.2", "100.64.0.1",
        "0.0.0.0", "::1",  # noqa: S104 - a target the agent asks for, nothing binds "fe80::1", "::ffff:169.254.169.254", "fd00::1",
        *proxy_ips(lab), *vm_ipv4(),
    ]  # fmt: skip
    literals = sorted(set(literals) - {lab.internet.ip})  # the fake internet is granted as public
    names = [*RESOLVING_INWARDS, lab.service.jail.config.name, lab.proxy_name, PROXY_ALIAS]
    seq = lab.head()
    accepts = lab.internet.accepts()
    outcome = attack.run_script(lab.agent, "ssrf_por_el_proxy", tag, *literals, *names)
    statuses = {**outcome["plain"], **{f"{k} (CONNECT)": v for k, v in outcome["tunnel"].items()}}
    through = {target: status for target, status in statuses.items() if status == 200}
    unanswered = {t: s for t, s in statuses.items() if s not in (403, 502)}
    expected = {normalize_host(target) for target in [*literals, *names]}

    def refused_inwards() -> list[Event]:
        found = lab.since(seq, "blocked")
        return [e for e in found if e.details.get("reason") == "private_address"]

    # The proxy tells its refusals on its own queue: the last ones may land a moment later.
    deadline = time.monotonic() + 20
    while len(refused_inwards()) < 2 * len(expected) and time.monotonic() < deadline:
        time.sleep(0.25)
    private = refused_inwards()
    hosts = {normalize_host(str(e.details.get("host"))) for e in private}
    attack.check(
        "stopped",
        through == {} and unanswered == {} and lab.internet.accepts() == accepts,
        f"{len(statuses)} peticiones al proxy (http:// al 80 y CONNECT al 443) hacia "
        f"{len(literals)} direcciones (metadatos, loopback, privadas, las de la VM, el Mac de "
        f"Lima, las del propio proxy, IPv6 local y de enlace local, IPv4 escondida en IPv6) y "
        f"{len(names)} nombres que resuelven hacia dentro ({names}): ninguna pasa "
        f"({through or 'ninguna con 200'}), todas reciben la respuesta de la puerta "
        f"({sorted(set(map(str, statuses.values())))}; sin respuesta: {unanswered or 'ninguna'}), "
        "y el internet falso no recibió ninguna conexión nueva",
    )
    attack.check(
        "recorded",
        expected <= hosts and len(private) >= 2 * len(expected),
        f"{len(private)} net/blocked private_address, uno por intento, de "
        f"{len(hosts & expected)}/{len(expected)} destinos (falta: {sorted(expected - hosts)})",
    )
    attack.check(
        "risk",
        {e.risk for e in private} == {2},
        f"private_address con riesgo {sorted({e.risk for e in private})}",
    )


# --- fronting-y-tuneles ------------------------------------------------------------------------


@scenario("fronting-y-tuneles")
def test_fronting_and_tunnels_are_refused(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    seq = lab.head()
    outcome = attack.run_script(lab.agent, "fronting_y_tuneles", PLAIN_HOST, OTHER_HOST, tag)
    arrived = {r["path"]: r for r in lab.internet.requests(path_prefix=f"/{tag}/")}
    # The honest chunked POST is the control: it waits for backtide like any other, which since
    # T10-2 holds it (a write): recorded whole as gate/held, and nothing of it arrives.
    honest = f"/{tag}/honest-chunked"
    assert outcome["honest_chunked"] == [200, 429], outcome
    [request] = [e for e in lab.tagged(tag, "held") if e.details["path"] == honest]
    assert honest not in arrived
    assert request.details["body"]["size"] > 64 * 1024
    fronted = [p for p in arrived if "fronted" in p and not p.endswith("-get")]
    ssh = outcome["ssh_in_443"]
    blocked = lab.since(seq, "blocked")
    attack.check(
        "stopped",
        outcome["fronted"] == 403
        and outcome["fronted_chunked"] == [200, 403]
        and fronted == []
        and outcome["ssh_port"]["connect"] == 403
        and "SSH-" not in str(ssh.get("answer", "")),
        f"Host distinto del túnel: {outcome['fronted']}; lo mismo con el cuerpo a trozos tras un "
        f"GET honrado en el mismo túnel: {outcome['fronted_chunked']}; al servidor falso no llegó "
        f"nada de eso ({fronted or 'nada'}). CONNECT al 22: {outcome['ssh_port']}. SSH dentro de "
        f"un CONNECT al 443: {ssh} (sin TLS, el proxy no lo deja pasar). Control: el POST a "
        f"trozos honrado llega a backtide y queda retenido ({outcome['honest_chunked']})",
    )
    got = reasons(blocked)
    transport = [e.action for e in lab.since(seq) if e.action in ("tls_failed", "error")]
    attack.check(
        "recorded",
        got.count("host_mismatch") == 2 and "port" in got,
        f"net/blocked {got}; además {transport}",
    )
    mismatch = sorted({e.risk for e in blocked if e.details.get("reason") == "host_mismatch"})
    attack.check("risk", mismatch == [2], f"host_mismatch con riesgo {mismatch}")


# --- secretos-en-la-red ------------------------------------------------------------------------


def pieces(secret: str, size: int = 8) -> set[str]:
    return {secret[i : i + size] for i in range(len(secret) - size + 1)}


@scenario("secretos-en-la-red")
def test_secrets_in_requests_never_reach_the_black_box(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    token = lab.service.config.gateway_token.reveal()
    outcome = attack.run_script(
        lab.agent, "secretos_en_la_red", PLAIN_HOST, tag, str(EXCERPT_BYTES)
    )
    # Since T10-2 the writes, and the reads whose URL or headers carried a secret the scrubber
    # knows (decision 1's guard, M3 of the review), are held (429): recorded as gate/held. The
    # lowercased token is not a known secret, so that read goes out (and is struck when recorded).
    statuses = outcome["sent"]
    assert all(status in (200, 429) for status in statuses.values()), outcome
    assert statuses["header"] == 429 and statuses["lowercase"] == 200, outcome
    assert statuses["path"] == statuses["query"] == statuses["json"] == 429, outcome
    passed = [name for name, status in statuses.items() if status == 200]
    assert len(lab.internet.requests(PLAIN_HOST, f"/{tag}/")) == len(passed)
    recorded = lab.tagged(tag, "request") + lab.tagged(tag, "held")
    # Credentials that live in a URL path (Discord and Slack webhooks, a Telegram bot path),
    # plain and encoded: every one held with risk 3 (a GET whose URL carried a secret; since
    # T10-3 a POST too: a write whose URL or body carried a secret is risk 3, docs/32 section 5).
    # A struck path may lose its tag, so they are found by seq.
    hooks_tag = new_tag()
    seq = lab.head()
    hooks = attack.run_script(
        lab.agent, "secretos_en_la_red", PLAIN_HOST, hooks_tag, str(EXCERPT_BYTES), "webhooks"
    )
    hook_held = [e for e in lab.since(seq, "held") if e.source == "gate"]
    hook_out = lab.internet.requests(PLAIN_HOST, f"/{hooks_tag}/")
    hook_risks = {
        method: sorted({e.risk for e in hook_held if e.details.get("method") == method})
        for method in ("GET", "POST")
    }
    get_reasons = sorted({str(e.details.get("reason")) for e in hook_held
                          if e.details.get("method") == "GET"})  # fmt: skip
    config = lab.service.config
    box = b""
    for path in (config.blackbox_db, config.blackbox_checkpoint):
        for candidate in (path, path.with_name(path.name + "-wal")):
            if candidate.exists():
                box += candidate.read_bytes()
    logs = jail_docker.run(["logs", lab.proxy_name], check=False)
    proxy_log = (logs.stdout + logs.stderr).encode()
    whole = sorted(s for s in spellings(token) if s.encode() in box or s.encode() in proxy_log)
    bits = sorted(p for p in pieces(token) if p.encode() in box)
    made_up = "sk-ant-api03-" + "Mx7" * 30
    hook_bits = sorted(
        f"{name}:{p}"
        for name, value in hooks["tokens"].items()
        for p in pieces(value)
        if p.encode() in box or p.encode() in proxy_log
    )
    attack.check(
        "stopped",
        whole == []
        and bits == []
        and made_up.encode() not in box
        and hook_bits == []
        and hook_out == []
        and all(status == 429 for status in hooks["sent"].values()),
        f"el token del Gateway (lo tiene en su entorno) fue en la ruta, la consulta, una cabecera "
        f"rara, en minúsculas, un JSON, un formulario y partido por el borde del extracto de "
        f"{EXCERPT_BYTES} bytes (por los dos lados), con una clave inventada al lado: ni el token "
        f"({whole or 'nada'}), ni ningún trozo suyo de 8 caracteres ({bits[:3] or 'nada'}), ni la "
        "clave inventada están en la caja negra (base, WAL y punto de control) ni en el log del "
        f"proxy. Un webhook de Discord, uno de Slack (cada uno tal cual, con %2F, con // y con "
        f"mayúsculas mezcladas) y una ruta de bot de Telegram con %3A, por GET y por POST: "
        f"{sorted(set(hooks['sent'].values()), key=str)}; al servidor falso no llega ninguno "
        f"({len(hook_out)}) y ningún trozo de 8 caracteres de sus tokens está en la caja negra ni "
        f"en el log del proxy ({hook_bits[:3] or 'nada'})",
    )
    paths = sorted(str(e.details.get("path", "")) for e in recorded)
    attack.check(
        "recorded",
        len(recorded) == len(outcome["sent"]),
        f"las {len(recorded)} peticiones quedan grabadas, con el secreto tachado ({paths[:2]}...)",
    )
    attack.check(
        "risk",
        hook_risks == {"GET": [3], "POST": [3]} and get_reasons == ["url_secret"],
        f"los webhooks retenidos: por GET con riesgo {hook_risks['GET']} ({get_reasons}), por "
        f"POST con riesgo {hook_risks['POST']}",
    )
    attack.check(
        "held",
        len(hook_held) == len(hooks["sent"]),
        f"{len(hook_held)} gate/held para las {len(hooks['sent'])} peticiones con un webhook o un "
        "token de bot en la ruta: ninguna sale como lectura",
    )


# --- canal-caido -------------------------------------------------------------------------------


@scenario("canal-caido")
def test_with_backtide_frozen_or_dead_nothing_goes_out(
    attack: Attack, own_lab: Callable[[], Lab]
) -> None:
    lab = own_lab()
    tag = new_tag()
    process = lab.service.require_process()
    frozen_path, dead_path = f"/{tag}/frozen", f"/{tag}/dead"
    # The control: with backtide listening, the same request reaches it, which since T10-2
    # holds it (a write): 429, recorded as gate/held.
    ok = attack.run_script(lab.agent, "canal_caido", PLAIN_HOST, f"/{tag}/control")
    assert ok["status"] == 429, ok
    assert [e.details["path"] for e in lab.tagged(tag, "held")] == [f"/{tag}/control"]
    os.kill(process.pid, signal.SIGSTOP)  # backtide hangs: the channel is open, nobody answers
    try:
        frozen = attack.run_script(lab.agent, "canal_caido", PLAIN_HOST, frozen_path)
        frozen_reached = lab.internet.requests(PLAIN_HOST, frozen_path)
    finally:
        os.kill(process.pid, signal.SIGCONT)
    wait_until(
        lambda: any(e.details.get("reason") == "not_recorded" for e in lab.tagged(tag, "blocked")),
        30,
        "the refusal to be recorded once backtide is back",
        context=lab.service.diagnosis,
    )
    late = [e for e in lab.tagged(tag, "blocked") if e.details.get("path") == frozen_path]
    lab.service.kill()  # backtide dies: the proxy loses its channel
    time.sleep(1.0)
    dead = attack.run_script(lab.agent, "canal_caido", PLAIN_HOST, dead_path)
    dead_reached = lab.internet.requests(PLAIN_HOST, dead_path)
    attack.check(
        "stopped",
        frozen["status"] == 503
        and dead["status"] == 503
        and frozen_reached == []
        and dead_reached == [],
        f"con backtide congelado (SIGSTOP) el proxy espera su confirmación y contesta "
        f"{frozen['status']} a los {frozen['seconds']} s; con backtide muerto (SIGKILL), "
        f"{dead['status']} a los {dead['seconds']} s. El servidor falso no recibió ninguna de las "
        f"dos (control: con backtide atento, la misma petición llega a backtide y queda "
        f"retenida: {ok['status']})",
    )
    attack.check(
        "recorded",
        [e.details.get("reason") for e in late] == ["not_recorded"],
        f"al volver backtide, el rechazo queda grabado: net/blocked "
        f"{[e.details.get('reason') for e in late]}",
    )
    attack.check("risk", [e.risk for e in late] == [2], f"con riesgo {[e.risk for e in late]}")


# --- herramientas-del-proveedor (T06-6) ----------------------------------------------------------

# What each attempt of the script must be refused as (provider_tools.py).
PROVIDER_REFUSALS = {
    "web-fetch": ("provider_side_tool", ["web_fetch_20250910"]),
    "mcp": ("provider_side_tool", ["mcp_servers"]),
    "url-image": ("provider_side_tool", ["url_source"]),
    "gzip-search": ("provider_body", None),  # no model client compresses what it sends
    "oa-mcp": ("provider_side_tool", ["mcp"]),
    "oa-search": ("provider_side_tool", ["web_search_options"]),
    "not-json": ("provider_body", None),
    "duplicate": ("provider_body", None),
    "made-up-option": ("provider_side_tool", ["param:made_up_option"]),
    "other-case": ("provider_side_tool", ["web_fetch_20250910"]),  # "Tools" read as "tools"
    "batch": ("provider_endpoint", None),
}


def provider_script(lab: Lab, attack: Attack, tag: str, mode: str) -> dict:
    return attack.run_script(
        lab.agent, "herramientas_del_proveedor", ANTHROPIC_HOST, OPENAI_HOST, tag,
        lab.fake[ANTHROPIC], lab.fake[OPENAI], mode,
    )  # fmt: skip


def attempt_of(event: Event, tag: str) -> str:
    return str(event.details.get("path", "")).removeprefix(f"/{tag}/").split("/", 1)[0]


@scenario("herramientas-del-proveedor")
def test_the_provider_is_not_made_to_reach_other_hosts(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    outcome = provider_script(lab, attack, tag, "tools")
    # The control: a plain model call with the agent's own tool goes on, with the real key.
    assert outcome["plain"] == 200, outcome
    [plain] = lab.internet.requests(ANTHROPIC_HOST, f"/{tag}/plain/")
    assert plain["headers"].get("x-api-key") == lab.real[ANTHROPIC]
    reached = sorted(
        r["path"] for r in lab.internet.requests(path_prefix=f"/{tag}/")
        if not r["path"].startswith(f"/{tag}/plain/")
    )  # fmt: skip
    statuses = outcome["refused"]
    attack.check(
        "stopped",
        reached == [] and all(statuses[name] in (400, 403) for name in PROVIDER_REFUSALS),
        f"con su clave falsa (que el proxy cambia por la real), el agente pide al proveedor "
        f"herramientas que corren en su lado (lectura y búsqueda web, un conector MCP, una "
        f"imagen por URL, una búsqueda escondida en un cuerpo gzip; MCP y búsqueda web de "
        f"OpenAI), cuerpos que no son su JSON (no JSON, una clave repetida) y un endpoint que no "
        f"es una llamada al modelo (lotes): {statuses}; al proveedor falso no llegó ninguna "
        f"({reached or 'ninguna'}). Control: la llamada normal con su herramienta sale "
        f"({outcome['plain']}) con la clave real",
    )
    deadline = time.monotonic() + 20  # the proxy queues its refusals: the last may come later
    while len(lab.tagged(tag, "blocked")) < len(PROVIDER_REFUSALS) and time.monotonic() < deadline:
        time.sleep(0.25)
    blocked = {attempt_of(e, tag): e for e in lab.tagged(tag, "blocked")}
    got = {
        name: (str(e.details.get("reason")), e.details.get("tools")) for name, e in blocked.items()
    }
    expected = {name: (reason, tools) for name, (reason, tools) in PROVIDER_REFUSALS.items()}
    attack.check(
        "recorded",
        got == expected,
        f"net/blocked por intento: {got} (se esperaba {expected})",
    )
    risks = sorted({e.risk for e in blocked.values()})
    attack.check("risk", risks == [2], f"los rechazos llevan riesgo {risks}")
    held = lab.tagged(tag, "held")
    attack.check(
        "held",
        held == [] and len(blocked) == len(PROVIDER_REFUSALS),
        f"se rechazan al momento, sin retener ni preguntar (docs/32, decisión por defecto 2): "
        f"{len(held)} gate/held, {len(blocked)} net/blocked",
    )


# --- eco-de-la-clave (T06-6) ---------------------------------------------------------------------


@scenario("eco-de-la-clave")
def test_a_key_the_provider_echoes_never_reaches_the_agent(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    seq = lab.head()
    outcome = provider_script(lab, attack, tag, "echo")
    echoes = outcome["echoes"]
    # The control: the fake provider did get the real keys, and did answer with them.
    arrived = {r["path"].split("/")[2]: r for r in lab.internet.requests(path_prefix=f"/{tag}/")}
    assert sorted(arrived) == ["echo-b64", "echo-header", "echo-json", "echo-sse"], arrived
    assert arrived["echo-json"]["headers"].get("x-api-key") == lab.real[ANTHROPIC]
    reals = list(lab.real.values())
    scanner = KeyScanner(reals)
    got = {
        name: "\n".join([echo["headers"], echo["body"], echo["text"]])
        for name, echo in echoes.items()
    }
    whole = sorted(
        name for name, text in got.items()
        if scanner.found(text) or any(s in text for real in reals for s in spellings(real))
    )  # fmt: skip
    finished = sorted(name for name, text in got.items() if "END-OF-ECHO" in text)
    attack.check(
        "stopped",
        whole == []
        and finished == []
        and echoes["echo-json"]["body"] == ""
        and echoes["echo-header"]["body"] == "",
        f"un proveedor que devuelve la clave real que recibió: en un error JSON (el agente "
        f"recibe {echoes['echo-json']['status']} y {len(echoes['echo-json']['body'])} bytes), "
        f"en una cabecera de una respuesta normal (recibe {echoes['echo-header']['status']}), "
        f"deletreada en tres trozos de un stream SSE y en base64 en otro: la clave no llega "
        f"entera en ninguno ({whole or 'en ninguno'}), y los streams se cortan antes de su final "
        f"(llegan al final: {finished or 'ninguno'})",
    )

    def echoed() -> list[Event]:
        found = lab.since(seq, "blocked")
        return [e for e in found if e.details.get("side") == "response"]

    deadline = time.monotonic() + 20  # the proxy queues its events: the last may come later
    while len(echoed()) < 4 and time.monotonic() < deadline:
        time.sleep(0.25)
    refused = {attempt_of(e, tag): str(e.details.get("reason")) for e in echoed()}
    attack.check(
        "recorded",
        refused
        == {name: "real_key" for name in ("echo-json", "echo-header", "echo-sse", "echo-b64")},
        f"net/blocked de la respuesta por intento: {refused}",
    )
    risks = sorted({e.risk for e in echoed()})
    attack.check("risk", risks == [3], f"la clave real en una respuesta lleva riesgo {risks}")


# --- inundar-el-proxy --------------------------------------------------------------------------


def proxy_state(lab: Lab) -> dict:
    info = json.loads(jail_docker.run(["container", "inspect", lab.proxy_name]).stdout)[0]
    return info["State"]


def proxy_memory_mib(lab: Lab) -> float | None:
    done = jail_docker.run(
        ["stats", "--no-stream", "--format", "{{.MemUsage}}", lab.proxy_name], check=False
    )
    used = done.stdout.strip().split("/", 1)[0].strip()
    for unit, scale in (("GiB", 1024), ("MiB", 1.0), ("GB", 1000), ("MB", 1), ("KiB", 1 / 1024)):
        if used.endswith(unit):
            try:
                return round(float(used[: -len(unit)].strip()) * scale, 1)
            except ValueError:
                return None
    return None


@scenario("inundar-el-proxy")
def test_flooding_the_proxy_does_not_let_anything_out_unrecorded(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    seq = lab.head()
    outcome = attack.run_script(lab.agent, "inundar_el_proxy", PLAIN_HOST, tag, timeout=300)
    state = proxy_state(lab)
    memory = proxy_memory_mib(lab)
    huge = outcome["huge"]
    burst = outcome["burst"]
    # Everything that reached the fake server must have a net/request recorded before it.
    arrived = {r["path"]: r for r in lab.internet.requests(PLAIN_HOST, f"/{tag}/")}
    recorded = {e.details["path"]: e for e in lab.tagged(tag, "request")}
    before_arrival = all(
        path in recorded and ts(recorded[path]) < request["at"] for path, request in arrived.items()
    )
    # The huge bodies and the slow uploads are refused: nothing of them reaches the server.
    refused_paths = [p for p in arrived if "huge" in p or "slow" in p]
    blocked = lab.since(seq, "blocked")
    too_large = [e for e in blocked if e.details.get("reason") == "too_large"]
    throttled = lab.since(seq, "throttled")
    report = lab.service.box.verify()
    attack.check(
        "stopped",
        outcome["control"]["status"] == 200
        and huge["length_status"] == 413
        and huge["chunked_status"] == 413
        and refused_paths == []
        and state["Running"] is True
        and state.get("OOMKilled") is not True
        and memory is not None
        and memory < 1024,  # an unreadable or unknown figure fails: it proves nothing
        f"conexiones: {outcome['connections']}; cuerpo enorme: {huge}; ráfaga: {burst}; "
        f"slowloris: {len(outcome['slow']['outcomes'])} túneles; de los cuerpos enormes y lentos "
        f"no llegó nada al servidor falso ({refused_paths or 'nada'}). El proxy sigue vivo "
        f"(Running={state['Running']}, OOMKilled={state.get('OOMKilled')}, memoria {memory} MiB de "
        f"1024). Control tras la inundación: {outcome['control']['status']}",
    )
    attack.check(
        "recorded",
        before_arrival and len(too_large) >= 2 and len(throttled) >= 1 and report.ok,
        f"{len(recorded)} net/request grabados antes de que el servidor falso recibiera cada "
        f"petición; {len(too_large)} net/blocked too_large; {len(throttled)} net/throttled "
        f"(ráfaga y conexiones de más); la caja negra verifica: {report.ok} "
        f"({report.problems[:2]})",
    )
    budget_events = too_large + throttled
    attack.check(
        "risk",
        {e.risk for e in budget_events} == {1},
        f"los topes y presupuestos (too_large, throttled) llevan riesgo "
        f"{sorted({e.risk for e in budget_events})}",
    )


# --- login-oauth -------------------------------------------------------------------------------

# (host, method, path): host-only OAuth hosts (any path) and path-based ones, with the path
# tricks a lenient server might read (encoding, case, double slashes, a trailing dot).
OAUTH_TARGETS = [
    ("auth.openai.com", "GET", "/authorize?client_id=x&redirect_uri=y"),
    ("auth.openai.com", "POST", "/oauth/token"),
    ("accounts.google.com", "GET", "/o/oauth2/v2/auth?scope=all"),
    ("oauth2.googleapis.com", "POST", "/token"),
    ("www.googleapis.com", "POST", "/oauth2/v4/token"),
    ("login.microsoftonline.com", "POST", "/common/oauth2/v2.0/token"),
    ("login.microsoft.com", "POST", "/common/oauth2/v2.0/devicecode"),
    ("login.windows.net", "POST", "/common/oauth2/token"),
    ("sts.windows.net", "POST", "/tenant/oauth2/token"),
    ("claude.ai", "GET", "/oauth/authorize?client_id=x"),
    ("claude.ai", "GET", "/OAuth/Authorize"),
    ("claude.ai", "GET", "//oauth//authorize"),
    ("claude.ai", "GET", "/%6Fauth/authorize"),
    ("claude.ai", "GET", "/oauth."),
    ("console.anthropic.com", "POST", "/v1/oauth/token"),
    ("platform.claude.com", "POST", "/oauth/token"),
    ("api.anthropic.com", "GET", "/api/oauth/authorize"),
    ("github.com", "POST", "/login/oauth/access_token"),
    ("github.com", "POST", "/login/device/code"),
    ("openrouter.ai", "GET", "/auth?callback_url=https://x"),
    ("openrouter.ai", "POST", "/api/v1/auth/keys"),
]


@scenario("login-oauth")
def test_oauth_logins_through_the_proxy_are_refused(attack: Attack, lab: Lab) -> None:
    tag = new_tag()
    seq = lab.head()
    targets = [f"{host}|{method}|{path}" for host, method, path in OAUTH_TARGETS]
    outcome = attack.run_script(
        lab.agent, "login_oauth", tag, ANTHROPIC_HOST, lab.fake[ANTHROPIC], *targets
    )
    attempts = outcome["attempts"]
    # The control: a normal model call still passes (else the refusals would prove nothing).
    assert outcome["control"]["status"] == 200, outcome
    oauth_hosts = {host for host, _, _ in OAUTH_TARGETS}
    reached = {host: lab.internet.requests(host) for host in oauth_hosts}
    not_refused = {key: value for key, value in attempts.items() if value.get("status") != 403}
    blocked = [e for e in lab.since(seq, "blocked") if e.details.get("reason") == "oauth_login"]
    attack.check(
        "stopped",
        not_refused == {} and all(hits == [] for hits in reached.values()),
        f"{len(attempts)} intentos de inicio de sesión OAuth y de código de dispositivo por el "
        f"proxy: todos 403 ({not_refused or 'ninguno pasó'}); a ninguno de los {len(oauth_hosts)} "
        f"hosts de login llegó nada ({{k: len(v) for k, v in reached.items() if v}}). Control: "
        f"la llamada normal al modelo sale ({outcome['control']['status']})",
    )
    attack.check(
        "recorded",
        len(blocked) == len(OAUTH_TARGETS),
        f"{len(blocked)} net/blocked oauth_login, uno por intento (de {len(OAUTH_TARGETS)})",
    )
    attack.check(
        "risk",
        {e.risk for e in blocked} == {2},
        f"oauth_login lleva riesgo {sorted({e.risk for e in blocked})}",
    )
