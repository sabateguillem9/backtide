"""The founder's first hands-on test (T09b, docs/probar.md): the real OpenClaw in its jail,
thinking with Claude through the proxy, the gate asking on Telegram and on the web. In the VM.

    python -m scripts.demo.probar up [--modelo <id>] [--internet-falso]
    python -m scripts.demo.probar pedir <message in base64>

It lives where the demo lives (scripts/demo/demo.py: ``~/backtide-demo-run``, the same volume,
the same container names and the same sudo checks), so `make probar-parar`, `make
probar-instantaneas` and `make probar-rebobinar` are the demo's own commands. What changes is
the config: the provider ``anthropic`` in ``[proxy]`` (its real key goes in the web's Settings
page, never in a file by hand nor in a chat), the gate's defaults written out, more memory for
the agent, and a live view of the black box that also shows the gate and the model.

Concessions (all in scripts/, none in backtide/), besides the demo's own:

- The proxy runs with the VM tests' concessions (``demo.dev_proxy``) and the process sensor is
  left out (Tetragon is a privileged container of its own; `make it` tests it).
- **Starting without a key.** backtide refuses a provider of ``[proxy]`` whose
  ``keys/<name>.key`` is missing, but the Settings page that writes that file needs a running
  service. So, while the file is missing, this process (and only it) reads the provider with a
  placeholder real key, ``sk-ant-backtide-probar-sin-clave-…``: OpenClaw gets its fake key as
  always, and a model call before the real key is set reaches Anthropic with the placeholder and
  gets "invalid x-api-key" back (no cost). Saving the key in Settings hands the proxy the real
  one at once (``Egress.reload`` reads ``keys/`` again), and the placeholder is never written
  anywhere.
- ``--internet-falso`` (the verification, never the founder's run): before the service starts,
  T06's fake internet (tests/integration/internet_kit.py) goes on the proxy's egress network,
  which is made ``--internal``, with ``api.anthropic.com`` among its names, and the proxy gets
  the tests' grants. Nothing reaches Anthropic or Telegram (invariant 8).
"""

import argparse
import base64
import binascii
import json
import os
import secrets
import sys
import threading
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

import backtide.service.config as service_config
from backtide.blackbox import Event
from backtide.jail import AgentJail
from backtide.jail import docker as jail_docker
from backtide.jail.openclaw import MODEL_ID
from backtide.service.config import ConfigError, ProviderKey, Secret, ServiceConfig
from scripts.demo import demo
from scripts.demo.demo import NETWORK, Paths

PROVIDER = "anthropic"
PROVIDER_HOST = "api.anthropic.com"
DEFAULT_MODEL = "claude-sonnet-5-5"
# OpenClaw 2026.9.8's "utility model" for Anthropic (``defaultUtilityModel``): it asks it small
# things at the start of a turn. Not listed, the proxy refuses it (``model_not_listed``), and
# OpenClaw can take that 403 for a bad key and stop using the provider for a minute (seen in
# the VM). Listed, it passes; it is cheap (1 $ / 5 $ per million tokens).
UTILITY_MODEL = "claude-haiku-4-5"
# OpenClaw sends ``fallbacks: "default"`` (Anthropic's server-side fallback when a model
# refuses) with Sonnet 5.5 and Opus 5.5; the gate refuses any field it does not know
# (T06-6: ``param:fallbacks``), so without this those models never answer (seen in the VM).
ALLOWED_PARAMS = ("param:fallbacks",)
# Two OpenClaw processes at once (the Gateway, 1.4 GiB, and the CLI turn of `pedir`) went over
# 2 GiB in the VM (tests/integration/test_proxy_criterion.py): 3 GiB, like that test.
AGENT_MEMORY = "3g"
WORKSPACE_LIMIT = 192 * 1024**2  # the demo's cap: enough for a test, and a full one pauses it
# A longer session than the demo's minute: on the demo's 2 GiB image the space gate warned from
# the start and froze the agent for metadata (seen in the VM). Sparse, so it costs what it holds.
IMAGE_SIZE = 8 * demo.GIB
CYCLE_INTERVAL = 10  # seconds between "did anything change?" checks (the demo's is 5)
TURN_TIMEOUT = 660.0  # OpenClaw's own turn timeout is 600 s; a held write can wait 90 s in it
MAX_MESSAGE_BYTES = 16 * 1024
PLACEHOLDER_PREFIX = "sk-ant-backtide-probar-sin-clave-"


# -- The config ----------------------------------------------------------------------------------


def render_config(paths: Paths, uid: int, gid: int, *, model: str = DEFAULT_MODEL) -> str:
    if not MODEL_ID.fullmatch(model):
        raise demo.DemoError(f"el modelo {model!r} no tiene forma de id de modelo")
    return (
        f'state_dir = "{paths.state}"\n'
        f'volume = "{paths.volume}"\n'
        f"workspace_limit = {WORKSPACE_LIMIT}  # 192 MiB\n"
        f"cycle_interval = {CYCLE_INTERVAL}\n"
        "\n"
        "[agent]\n"
        f'name = "{demo.CONTAINER}"\n'
        f'network = "{NETWORK}"\n'
        f"uid = {uid}\n"
        f"gid = {gid}\n"
        f'memory = "{AGENT_MEMORY}"\n'
        'cpus = "2"\n'
        "\n"
        "# The egress proxy: the VM user's ids (demo.dev_proxy), and Claude as the model.\n"
        "# The real key goes in the web's Settings page (keys/anthropic.key), never here.\n"
        "[proxy]\n"
        f"uid = {uid}\n"
        f"gid = {gid}\n"
        "# Let through, besides the usual fields: Anthropic's fallback when a model refuses.\n"
        f"allow_provider_tools = {json.dumps(list(ALLOWED_PARAMS))}\n"
        "\n"
        "[[proxy.providers]]\n"
        f'name = "{PROVIDER}"\n'
        f'kind = "{PROVIDER}"\n'
        f'host = "{PROVIDER_HOST}"\n'
        "# The agent's model (make probar MODEL=...), then OpenClaw's utility model. Only these\n"
        "# reach Anthropic: a call to any other model is refused by the proxy.\n"
        f"models = {json.dumps(list(dict.fromkeys((model, UTILITY_MODEL))))}\n"
        "\n"
        "# The gate's defaults, written out: reads pass, writes to unknown hosts are held, and\n"
        "# the owner's Telegram chat (telegram.toml) is trusted.\n"
        "[gate]\n"
        'unknown_hosts = "hold"\n'
        "trust_owner_chat = true\n"
    )


def model_of(paths: Paths) -> str | None:
    """The model of the running test, from its config (for the messages)."""
    try:
        text = paths.config.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("models = ["):
            return line.split('"')[1]  # the first is the agent's
    return None


# -- Starting without a key ----------------------------------------------------------------------

_strict_keys = service_config.read_provider_keys


def keys_or_placeholder(folder: Path, names: list[str]) -> dict[str, ProviderKey]:
    """``read_provider_keys`` (every check of it, the fake key made as always), but a provider
    whose ``<name>.key`` does not exist yet gets a placeholder as its real key (see the module's
    docstring). The placeholder lives in this process only."""
    try:
        os.mkdir(folder, 0o700)  # what the Settings page would make; checked by the reader
    except FileExistsError:
        pass
    present = [name for name in names if os.path.lexists(folder / f"{name}.key")]
    keys = _strict_keys(folder, present) if present else {}
    for name in names:
        if name not in keys:
            fake = service_config._fake_key(folder / f"{name}.fake", name)
            placeholder = PLACEHOLDER_PREFIX + secrets.token_hex(16)
            keys[name] = ProviderKey(real=Secret(placeholder), fake=fake)
    return {name: keys[name] for name in names}


def has_real_key(paths: Paths) -> bool:
    return (paths.state / service_config.STATE_KEYS / f"{PROVIDER}.key").exists()


# -- The service -----------------------------------------------------------------------------------


def serve_for_test(grants: dict[str, Any] | None) -> Any:
    def serve(config: ServiceConfig, **options: Any) -> None:
        from backtide.service import runner

        jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
        proxy = demo.dev_proxy(config, **(grants or {}))
        runner.serve(config, jail=jail, proxy=proxy, sensor=False, **options)

    return serve


def start_fake_internet(paths: Paths) -> dict[str, Any]:
    """T06's fake internet on the proxy's egress network (made ``--internal``), and the grants
    that let the proxy use it. Only for the verification (`make probar FALSO=1`)."""
    from tests.integration.internet_kit import start_fake_internet_for
    from tests.integration.proxy_kit import read_grants

    config = _config(paths)
    internet = start_fake_internet_for(
        config, paths.base / demo.FAKE_INTERNET_FOLDER, name=demo.FAKE_INTERNET
    )
    return {**read_grants(internet.grants_file), "internal_egress": True}


def describe(event: Event) -> str | None:
    """The demo's line for files (any under work/) and snapshots, and also the model, the gate,
    what goes out and the Settings page. Text that comes from the agent is shown with its
    invisible characters written out."""
    when = datetime.fromisoformat(event.ts).astimezone().strftime("%H:%M:%S")
    source, action, target = event.source.value, event.action, visible(str(event.target))
    details = event.details if isinstance(event.details, dict) else {}
    method = visible(str(details.get("method") or ""))
    if source == "file":
        return f"{when}  archivo     {action:<15} {target}" if target.startswith("work/") else None
    if source == "llm":
        usage = details.get("usage")
        tokens = ""
        if isinstance(usage, dict):
            tokens = (
                f"  (entran {usage.get('input', '?')} tokens, salen {usage.get('output', '?')})"
            )
        model = visible(str(details.get("model") or ""))
        return f"{when}  modelo      {action:<15} {model}{tokens}".rstrip()
    if source == "gate":
        risk = f"riesgo {event.risk}  " if action == "held" else ""
        return f"{when}  PUERTA      {action:<15} {risk}{method} {target}".rstrip()
    if source == "net":
        if action == "request" and str(details.get("host", "")) == PROVIDER_HOST:
            return None  # the model's own calls: the llm lines say them
        why = details.get("reason")
        because = f"  ({visible(str(why))})" if why else ""
        return f"{when}  red         {action:<15} {method} {target}{because}".rstrip()
    if source == "settings":
        return f"{when}  ajustes     {action:<15} {target}"
    return demo.describe(event)


def visible(text: str, limit: int = 160) -> str:
    """``text`` on one line: control and invisible characters as ``U+XXXX``, cut at ``limit``."""
    out = "".join(c if c.isprintable() and not _invisible(c) else f"U+{ord(c):04X}" for c in text)
    return out if len(out) <= limit else out[: limit - 1] + "…"


def _invisible(char: str) -> bool:
    return char in "​‌‍⁠﻿" or "‪" <= char <= "‮" or ("⁦" <= char <= "⁩")


def command_up(paths: Paths, *, model: str, fake_internet: bool) -> int:
    demo.require_dev_vm_user_with_sudo()
    if demo.service_pid(paths) is not None:
        raise demo.DemoError("ya hay una prueba o una demo en marcha; `make probar-parar` la quita")
    render_config(paths, 0, 0, model=model)  # refuses an odd model before anything changes
    demo.require_agent_image()
    if paths.base.exists() or demo.mount_at(paths.mnt) is not None:
        print("Quedaba una prueba o una demo anterior: la quito para empezar de cero.", flush=True)
    demo.teardown(paths)
    demo.create_volume(
        paths,
        lambda p, uid, gid: render_config(p, uid, gid, model=model),
        telegram=not fake_internet,  # the fake internet's run never reaches the real Telegram
        image_size=IMAGE_SIZE,
    )
    grants = None
    if fake_internet:
        try:
            grants = start_fake_internet(paths)
        except BaseException:
            demo.teardown(paths)
            raise
        print("INTERNET FALSO: nada sale a Anthropic ni a Telegram (solo para verificar).")
    telegram = (paths.state / "telegram.toml").exists()
    print(
        "Volumen de la prueba listo (Btrfs con cuotas, tope del agente: 192 MiB).\n"
        f"Modelo del agente: {model} (de Anthropic, a través del proxy).\n"
        "Arranco `backtide vigilar`: espera a ver `agent_start` y las primeras instantáneas.\n",
        flush=True,
    )
    print(
        "FALTA LA CLAVE DE ANTHROPIC. No la pegues aquí ni en ningún archivo: en otra "
        "terminal,\n  make probar-web\nabre el enlace en el navegador del Mac, ve a «Ajustes» y "
        "pégala en «Anthropic».\nHasta entonces, si le hablas al agente, Anthropic contestará "
        "que la clave no vale (sin coste).\n",
        flush=True,
    )
    if telegram:
        print("Telegram: los avisos y las retenciones irán a tu bot.\n", flush=True)
    elif fake_internet:
        print("Telegram: apagado (internet falso).\n", flush=True)
    else:
        print(
            "Telegram: no hay ~/.config/backtide/telegram.toml en la VM, así que las "
            "retenciones solo se ven en la web.\n",
            flush=True,
        )
    print('Para hablarle: make probar-pedir MSG="...". Para parar: Ctrl-C aquí.\n', flush=True)
    paths.pid_file.write_text(f"{os.getpid()}\n")
    stop = threading.Event()
    feed = threading.Thread(
        target=demo.feed_black_box, args=(paths, stop, describe), name="probar-feed"
    )
    feed.start()
    try:
        return run_backtide("vigilar", "--config", str(paths.config), grants=grants)
    finally:
        stop.set()
        feed.join(10)
        paths.pid_file.unlink(missing_ok=True)


def run_backtide(*argv: str, grants: dict[str, Any] | None = None) -> int:
    """`backtide <argv>`, with the demo's concessions and the ones of this module."""
    return demo.run_backtide(*argv, serve=serve_for_test(grants))


# -- Talking to the agent --------------------------------------------------------------------


def decode_message(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
        message = raw.decode("utf-8")
    except (binascii.Error, ValueError) as error:
        raise demo.DemoError("el mensaje no llegó bien (base64 y UTF-8)") from error
    message = message.strip()
    if not message:
        raise demo.DemoError('di qué le pides: make probar-pedir MSG="..."')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise demo.DemoError(f"el mensaje es muy largo (como mucho {MAX_MESSAGE_BYTES} bytes)")
    return message


def agent_turn_argv(message: str) -> list[str]:
    """One turn of OpenClaw's own CLI through its Gateway, in its main session (so one message
    remembers the ones before): what `openclaw agent --message` does, as the agent's user."""
    return ["node", "openclaw.mjs", "agent", "--agent", "main", "--message", message]


def command_pedir(paths: Paths, encoded: str) -> int:
    message = decode_message(encoded)
    demo.require_demo_mount(paths)
    config = _config(paths)
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    if not jail.is_running():
        raise demo.DemoError("el agente no está en marcha: arranca `make probar` en otra terminal")
    if not has_real_key(paths):
        print("Aviso: aún no has puesto la clave de Anthropic en Ajustes (make probar-web).")
    print(f"Tú: {visible(message, 400)}\nEl agente piensa (con {model_of(paths)})...", flush=True)
    result = jail.exec(agent_turn_argv(message), timeout=TURN_TIMEOUT)
    sys.stdout.write("\nEl agente:\n" + jail_docker.sanitize(result.stdout))
    if result.stderr.strip():
        sys.stderr.write(jail_docker.sanitize(result.stderr))
    if result.returncode != 0:
        raise demo.DemoError(f"OpenClaw terminó con código {result.returncode}")
    return 0


def _config(paths: Paths) -> ServiceConfig:
    try:
        return ServiceConfig.from_file(paths.config)
    except ConfigError as error:
        raise demo.DemoError(
            f"no hay prueba en marcha o su configuración no vale: {error}"
        ) from error


# -- Entry point -----------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probar", description="La prueba de backtide (docs/probar.md)."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    up = commands.add_parser("up", help="prepara todo y arranca el servicio en primer plano")
    up.add_argument("--modelo", default=DEFAULT_MODEL, help=f"por defecto {DEFAULT_MODEL}")
    up.add_argument(
        "--internet-falso", action="store_true", help="solo para verificar: nada sale de la VM"
    )
    ask = commands.add_parser("pedir", help="un mensaje al agente, y su respuesta")
    ask.add_argument("mensaje", help="el mensaje, en base64 (lo hace el Makefile)")
    commands.add_parser("instantaneas", help="lista las instantáneas")
    rewind = commands.add_parser("rebobinar", help="vuelve a una instantánea")
    rewind.add_argument("snapshot", metavar="instantánea")
    rewind.add_argument("--si", action="store_true", help="no pedir confirmación")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = demo.PATHS
    # Every command of this process reads the keys this module's way (see the docstring).
    service_config.read_provider_keys = keys_or_placeholder  # type: ignore[assignment]
    try:
        if args.command == "up":
            return command_up(paths, model=args.modelo, fake_internet=args.internet_falso)
        if args.command == "pedir":
            return command_pedir(paths, args.mensaje)
        # The demo's own commands, with this module's reading of the keys (a test without its
        # key yet can still list and rewind).
        demo.require_demo_mount(paths)
        if args.command == "instantaneas":
            return demo.command_instantaneas(paths)
        return demo.command_rebobinar(
            paths, args.snapshot, yes=args.si, target_name="probar-rebobinar"
        )
    except demo.DemoError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
