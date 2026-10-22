"""Evil-agent scenarios for the second agent, Claude Code (profile ``claude-code``; T17a-5,
docs/34). They prove the defences of T17a-4 still hold when the jailed agent is Claude Code:
run with `make ataques PERFIL=claude-code` (conftest.py skips them in OpenClaw's battery).

The lab is the shared Claude Code lab of cc_kit.py (``cc_lab``): the real `backtide vigilar` with
``profile = "claude-code"`` and the pinned image of T17a-1, its process sensor, and T06's fake
internet. The owner's side is the real CLI (`backtide exportar`, `tarea`, `entrar`). Only fake
and made-up keys: nothing reaches Anthropic, GitHub or anywhere real (invariant 8).

- ``exportar-planta-git``: the agent leaves git repositories in its work folder; `exportar`
  skips every one, names them, and records the skip (system/export). A1 of the T17a-4 review.
- ``exportar-planta-config``: the agent plants what the owner's tools run by themselves (a
  SessionStart hook, an MCP server, CLAUDE.md, a folder-open task, a workflow, a workspace);
  `exportar` leaves it out unless --incluir-config, and records it; `--git` warns.
- ``sudo-sin-contrasena``: the image gives its user passwordless sudo; inside the jail
  ``sudo -n`` fails, the uid is not the image's and the agent is in no privileged group.
- ``cambia-sus-ajustes``: the agent rewrites its own settings (another base URL, another proxy);
  a real task still goes only through backtide's proxy (recorded), the new base URL is refused
  there, and a direct connection to the other proxy fails and is recorded (invariant 3).
- ``clave-falsa-a-otro-host``: the fake model key sent to a host other than the provider is
  never swapped for the real one (the provider is the control: there it is swapped); neither key
  reaches the black box nor the proxy's logs.
- ``escapes-en-la-terminal``: during `entrar`, escape sequences the agent writes reach the
  owner's terminal unfiltered (the relay is pending, backlog "Después"); what backtide does do,
  reset the terminal after the session, is checked (M1 of the review).
- ``nombres-de-clave-en-la-linea`` (both agents): a secret on the command line in every shape
  the unified table of backtide/blackbox/secret_words.py must strike; none reaches the black box
  or Tetragon's file.
"""

import base64
import json
import secrets
import sys
from uuid import uuid4

import pytest
from attack_kit import Attack, battery_profile, scenario
from cc_kit import ECHO_HOST, NOT_ALLOWED_HOST, PROVIDER_HOST, Lab

from backtide.jail import docker as jail_docker
from backtide.shell_cli import BUNDLE_WARNING, SESSION_CLOSED, TERMINAL_RESET
from tests.integration import sensor_kit
from tests.integration.internet_kit import REPLY_TEXT
from tests.integration.service_kit import REPO, exec_in_agent, run_cli

TASK_TIMEOUT = 300.0


def write_cmd(path: str, word: str) -> str:
    """A task prompt the fake model answers by running Claude Code's Bash tool to write a file."""
    return f"T17-BASH:[[printf '%s\\n' {word} >> /workspace/{path}]] escribe {word}"


def paths_of(requests: list[dict]) -> list[str]:
    """Only the paths of fake-internet requests: never their headers or keys (L10)."""
    return sorted(r["path"] for r in requests)


# --- exportar-planta-git -----------------------------------------------------------------------


@scenario("exportar-planta-git")
def test_export_skips_the_planted_git_repositories(attack: Attack, cc_lab: Lab, tmp_path) -> None:
    folder = f"planta-{uuid4().hex[:8]}"
    planted = attack.run_script(cc_lab.service.jail, "exportar_planta_git", folder)["planted"]
    out = tmp_path / "exportado"
    try:
        before = len(cc_lab.service.events("export"))
        taken = run_cli(cc_lab.service, "exportar", str(out))
        assert taken.returncode == 0, (taken.stdout, taken.stderr)

        exported = [p.relative_to(out).as_posix() for p in out.rglob("*")]
        git_on_host = [
            p
            for p in exported
            if p.rsplit("/", 1)[-1].casefold() in ("head", "commondir")
            or ".git" in p.casefold()
            or "escondido/vendor/lib" in p
        ]
        copied_ok = (out / folder / "proyecto" / "README.md").read_text() == "hola\n"

        (event,) = cc_lab.service.events("export")[before:]
        skipped_git = event.details.get("skipped_git", 0)
        attack.check(
            "stopped",
            git_on_host == [] and copied_ok,
            f"`backtide exportar` copió {folder}/proyecto/README.md ({copied_ok}) y no dejó "
            f"ningún repositorio en el anfitrión ({git_on_host or 'ninguno'}); el agente había "
            f"plantado {planted}.",
        )
        attack.check(
            "recorded",
            event.action == "export" and skipped_git >= 5 and bool(event.snapshot_id),
            f"system/export con skipped_git={skipped_git} (de {len(planted)} repositorios "
            f"plantados) y la instantánea {event.snapshot_id} que deja constancia de lo que salió.",
        )
        attack.check("risk", event.risk == 1, f"system/export lleva riesgo {event.risk}.")
    finally:
        exec_in_agent(
            cc_lab.service,
            f"rm -rf /workspace/work/{folder} /workspace/work/HEAD /workspace/work/refs",
        )


# --- exportar-planta-config --------------------------------------------------------------------


def _norm(text: str) -> str:
    return " ".join(text.split())


@scenario("exportar-planta-config")
def test_export_leaves_out_what_the_owners_tools_run(attack: Attack, cc_lab: Lab, tmp_path) -> None:
    service, folder = cc_lab.service, f"config-{uuid4().hex[:8]}"
    outcome = attack.run_script(service.jail, "exportar_planta_config", folder)
    planted, harmless = outcome["planted"], outcome["harmless"]
    plain, with_config = tmp_path / "sin-config", tmp_path / "con-config"
    try:
        # 1. By default: none of the planted files leaves; the harmless dot files do.
        before = len(service.events("export"))
        taken = run_cli(service, "exportar", str(plain))
        assert taken.returncode == 0, (taken.stdout, taken.stderr)
        (default_event,) = service.events("export")[before:]
        left_out = [p for p in planted if not _lexists_any_case(plain / folder, p)]
        kept = [p for p in harmless if (plain / folder / p).is_file()]
        # 2. With --incluir-config, the owner asked: all of them leave.
        taken_all = run_cli(service, "exportar", "--incluir-config", str(with_config))
        assert taken_all.returncode == 0, (taken_all.stdout, taken_all.stderr)
        (config_event,) = service.events("export")[before + 1 :]
        exported_all = [p for p in planted if _lexists_any_case(with_config / folder, p)]
        # 3. `exportar --git`: a bundle is not filtered, so it carries its own warning.
        bundle = tmp_path / "repo.bundle"
        taken_git = run_cli(service, "exportar", "--git", f"{folder}/repo", str(bundle))
        assert taken_git.returncode == 0, (taken_git.stdout, taken_git.stderr)
    finally:
        exec_in_agent(service, f"rm -rf /workspace/work/{folder}")

    bundle_warned = _norm(f"AVISO: {BUNDLE_WARNING}") in _norm(taken_git.stdout)
    attack.check(
        "stopped",
        left_out == planted
        and kept == harmless
        and exported_all == planted
        and bundle_warned
        and bundle.read_bytes().startswith(b"# v"),
        f"por defecto `exportar` deja fuera los {len(left_out)} de {len(planted)} archivos "
        f"plantados ({planted}) y saca {kept}; con --incluir-config salen los {len(exported_all)}; "
        f"`exportar --git` avisa de que un bundle no deja nada fuera ({bundle_warned}).",
    )
    skipped = default_event.details.get("skipped_config", 0)
    attack.check(
        "recorded",
        skipped >= len(planted)
        and default_event.details.get("include_config") is False
        and config_event.details.get("include_config") is True
        and bool(default_event.snapshot_id),
        f"system/export con skipped_config={skipped} e include_config=false, y la segunda con "
        f"include_config={config_event.details.get('include_config')}, cada una con su "
        "instantánea.",
    )
    attack.check(
        "risk",
        default_event.risk == 1 and config_event.risk == 1,
        f"system/export lleva riesgo {default_event.risk} y {config_event.risk}.",
    )


def _lexists_any_case(root, relative: str) -> bool:
    """Whether ``relative`` exists under ``root`` with any case on any part (the planted
    ``sub/.VSCODE`` would be ``.vscode`` to APFS)."""
    here = root
    for part in relative.split("/"):
        if not here.is_dir():
            return False
        match = [child for child in here.iterdir() if child.name.casefold() == part.casefold()]
        if not match:
            return False
        here = match[0]
    return True


# --- sudo-sin-contrasena -----------------------------------------------------------------------


@scenario("sudo-sin-contrasena")
def test_passwordless_sudo_does_nothing_in_the_jail(attack: Attack, cc_lab: Lab) -> None:
    attack.watch_service(cc_lab.service)
    outcome = attack.run_script(cc_lab.service.jail, "sudo_sin_contrasena")
    tries = outcome["tries"]
    attack.check(
        "stopped",
        outcome["uid"] not in (0, 1000)  # 1000 is the image's own `agent` user
        and outcome["euid"] not in (0, 1000)
        and outcome["no_new_privs"] == "1"
        and all(try_["code"] not in (0, None) for try_ in tries.values())
        and all(state != "WRITTEN" for state in outcome["created"].values())
        and outcome["in_privileged_group"] is False,
        f"uid {outcome['uid']} (ni 0 ni el 1000 de la imagen), "
        f"NoNewPrivs {outcome['no_new_privs']}; `sudo -n` y los demás fallan "
        f"({ {k: v['code'] for k, v in tries.items()} }); nada de /etc ni /home/agent es "
        f"escribible ({outcome['created']}); no está en el grupo docker "
        f"({outcome['docker_gid']}) ni sudo ({outcome['sudo_gid']}) de la imagen "
        f"(grupos {outcome['groups']}).",
    )
    recorded = attack.recorded_exec(binary="*/sudo", at_least=3)
    attack.check(
        "recorded",
        len(recorded) >= 3 and all(e.target.endswith("/sudo") for e in recorded),
        f"el sensor grabó {len(recorded)} exec de sudo en {attack.container_short} (>= 3).",
    )


# --- cambia-sus-ajustes ------------------------------------------------------------------------


@scenario("cambia-sus-ajustes")
def test_rewriting_its_own_settings_opens_no_way_out(attack: Attack, cc_lab: Lab) -> None:
    service, tag = cc_lab.service, f"t17a5-{uuid4().hex[:10]}"
    # 1. It cannot touch the jail's settings: every attempt is a filesystem error (never REMOVED).
    jail_attempt = attack.run_script(service.jail, "cambia_sus_ajustes", "jail")
    jail_refused = all(
        value in ("OSError", "PermissionError", "FileNotFoundError", "IsADirectoryError")
        for value in jail_attempt.values()
    )
    # 2. A real task works and its model call is recorded going through backtide's proxy to the
    #    provider: the baseline, with the agent's own settings untouched.
    since_llm = service.box.head()[0]
    done = run_cli(
        service, "tarea", write_cmd(f"work/cambia-{tag}.txt", "ok"), timeout=TASK_TIMEOUT
    )
    task_ok = done.returncode == 0 and REPLY_TEXT in done.stdout
    task_file = (cc_lab.work / f"cambia-{tag}.txt").exists()
    llm = [
        e
        for e in service.box.events(since_seq=since_llm)
        if e.source == "llm" and PROVIDER_HOST in json.dumps([e.target, e.details], default=str)
    ]
    try:
        # 3. It rewrites its own settings with another base URL and another proxy.
        attack.run_script(
            service.jail,
            "cambia_sus_ajustes",
            "proxy",
            f"https://{NOT_ALLOWED_HOST}",
            f"http://{cc_lab.internet.ip}:443",
        )
        # 4. It tries to use the other base URL (through the only route, the proxy) and to reach
        #    the other proxy straight: the first is refused and recorded, the rest never connect.
        since_net = attack.watch_service(service)
        targets = [f"{cc_lab.internet.ip}:443", "192.0.2.1:443", "[2001:db8::1]:443"]
        escape = attack.run_script(
            service.jail, "cambia_sus_ajustes", "escape", NOT_ALLOWED_HOST, *targets
        )
    finally:
        attack.run_script(service.jail, "cambia_sus_ajustes", "clean")

    arrived = cc_lab.internet.requests(NOT_ALLOWED_HOST, "/base-url-probe")
    blocked = [
        e
        for e in service.events("blocked")
        if e.seq > since_net and e.details.get("reason") == "not_allowed"
    ]
    direct_failed = all(result != "CONNECTED" for result in escape["direct"].values())
    attack.check(
        "stopped",
        jail_refused
        and task_ok
        and task_file
        and escape["proxy_status"] == 403
        and direct_failed
        and arrived == [],
        f"no puede escribir en /config/claude.json ({jail_attempt}); una tarea real funciona por "
        f"el proxy de backtide ({task_ok}, archivo escrito {task_file}); su nueva URL base por el "
        f"proxy es {escape['proxy_status']}; las conexiones directas (otro proxy, IP pública, "
        f"IPv6) fallan ({escape['direct']}); al host no permitido no llegó nada "
        f"({len(arrived)} peticiones).",
    )
    recorded_connect = attack.recorded_connect(target=f"{cc_lab.internet.ip}:443")
    attack.check(
        "recorded",
        bool(llm) and bool(blocked) and bool(recorded_connect),
        f"la llamada al modelo de la tarea quedó grabada por el proxy (llm/request, {len(llm)}); "
        f"la petición a la nueva URL base, net/blocked not_allowed ({len(blocked)}); el intento "
        f"de conexión directa al otro proxy, net/connect ({len(recorded_connect)}).",
    )
    attack.check(
        "risk",
        {e.risk for e in blocked} == {1},
        f"la lista permitida lleva riesgo {sorted({e.risk for e in blocked})}.",
    )


# --- clave-falsa-a-otro-host -------------------------------------------------------------------


@scenario("clave-falsa-a-otro-host")
def test_the_fake_key_is_never_swapped_except_for_the_provider(attack: Attack, cc_lab: Lab) -> None:
    service, tag = cc_lab.service, f"t17a5-{uuid4().hex[:10]}"
    since = service.box.head()[0]
    outcome = attack.run_script(
        service.jail, "clave_falsa_a_otro_host", PROVIDER_HOST, ECHO_HOST, NOT_ALLOWED_HOST, tag
    )
    # Control: the provider request is swapped for the real key, and reaches the provider.
    provider_calls = cc_lab.internet.requests(PROVIDER_HOST, f"/{tag}/fake/")
    provider_got_real = bool(provider_calls) and all(
        call["headers"].get("x-api-key") == cc_lab.real for call in provider_calls
    )
    # The echo host (not the provider) only ever gets the fake key, never the real one.
    echoed = cc_lab.internet.requests(ECHO_HOST, f"/{tag}/")
    echo_fields = [json.dumps([r["path"], r["headers"]]) for r in echoed]
    fake_elsewhere = all(cc_lab.real not in field for field in echo_fields)
    fake_present = any(cc_lab.fake in field for field in echo_fields)
    not_allowed_arrived = cc_lab.internet.requests(NOT_ALLOWED_HOST, f"/{tag}/")
    # The write to the echo host is held (no answer, never 200) and recorded as gate/held.
    held = [
        e
        for e in service.events("held", "gate")
        if e.seq > since and str(e.details.get("path", "")) == f"/{tag}/post"
    ]
    attack.check(
        "stopped",
        provider_got_real
        and fake_elsewhere
        and fake_present
        and outcome["not_allowed"] == 403
        and not_allowed_arrived == []
        and outcome["echo_post"] != 200
        and bool(held),
        f"al proveedor la falsa se cambia por la real ({provider_got_real}); a {ECHO_HOST} llega "
        f"la falsa y nunca la real (falsa={fake_present}, real_fuera={fake_elsewhere}); a "
        f"{NOT_ALLOWED_HOST} la puerta la rechaza ({outcome['not_allowed']}) y no llegó nada "
        f"({len(not_allowed_arrived)}); el POST al echo se retiene ({outcome['echo_post']}, "
        f"gate/held {len(held)}).",
    )
    # recorded: the model call is a net/llm event in the box with this tag.
    box_events = service.box.events(since_seq=since)
    llm = [
        e
        for e in box_events
        if e.source == "llm" and f"/{tag}/fake/" in json.dumps([e.target, e.details], default=str)
    ]
    box_text = repr([(e.source, e.action, e.target, e.details) for e in box_events])
    proxy_logs = _proxy_logs(service)
    secrets_leaked = [
        where
        for name, value in (("real", cc_lab.real), ("fake", cc_lab.fake))
        for where in (
            f"caja:{name}" if value in box_text else "",
            f"proxy:{name}" if value in proxy_logs else "",
        )
        if where
    ]
    attack.check(
        "recorded",
        bool(llm) and secrets_leaked == [],
        f"la llamada al modelo quedó grabada (net/llm con el tag, {len(llm)}); ni la clave real "
        f"ni la falsa aparecen en la caja negra ni en los logs del proxy "
        f"({secrets_leaked or 'ni rastro'}).",
    )


def _proxy_logs(service) -> str:
    name = service.config.proxy_jail_config().name
    done = jail_docker.run(["logs", name], check=False)
    return (done.stdout or "") + (done.stderr or "")


# --- escapes-en-la-terminal --------------------------------------------------------------------

OSC52 = b"\x1b]52;c;"  # the clipboard escape the agent writes; the relay (pending) would drop it


@scenario("escapes-en-la-terminal")
def test_escape_sequences_reach_the_owners_terminal(attack: Attack, cc_lab: Lab) -> None:
    from tests.integration.test_agent_profile_assumptions import Terminal, wait_for  # noqa: PLC0415

    service = cc_lab.service
    since = sensor_kit.head_seq(service)
    marker = f"t17a5esc{uuid4().hex[:8]}"
    osc52_marker = OSC52 + base64.b64encode(marker.encode()) + b"\x07"
    (service.store.workspace / "agente" / "home" / ".claude.json").unlink(missing_ok=True)
    env_argv = [
        "env", f"PYTHONPATH={REPO}", "TERM=xterm-256color", sys.executable, "-m",
        "tests.integration.cli_main", "entrar", "--config", str(service.config_path),
    ]  # fmt: skip
    term = Terminal(env_argv)
    outcome: dict = {"written": [], "failed": []}
    try:
        wait_for(lambda: "bypasspermissionson" in term.squeezed(), 90, "the prompt", term)
        start = len(term.output)
        outcome = attack.run_script(service.jail, "escapes_en_la_terminal", marker)
        wait_for(
            lambda: osc52_marker in bytes(term.output[start:]),
            30,
            "the escape bytes on the terminal",
            term,
        )
        reached = osc52_marker in bytes(term.output[start:])
        term.type("/exit")
        code = term.process.wait(timeout=60)
    finally:
        term.close()
    raw = bytes(term.output)
    reset = TERMINAL_RESET.encode()
    # M1: backtide restores the terminal AFTER the session, so its soft reset comes after the
    # agent's last escape in the stream.
    reset_after_escape = reset in raw and raw.rfind(reset) > raw.rfind(osc52_marker)
    attack.check(
        "stopped",
        reached
        and outcome["written"]
        and all(tty.startswith("/dev/pts/") for tty in outcome["written"])
        and reset_after_escape
        and SESSION_CLOSED in term.text(),
        "no se frena (el relé de terminal está en 'Después'): las secuencias del agente llegan a "
        f"la terminal del dueño sin filtrar (escritas {outcome['written']}, fallidas "
        f"{outcome['failed']}); al cerrar (código {code}) backtide restaura la terminal y manda "
        f"su reinicio suave DESPUÉS del escape del agente ({reset_after_escape}).",
    )
    sensor_kit.wait_event(
        service,
        lambda e: e.source == "exec" and marker in str(e.details.get("argv", "")),
        "the sensor's record of the agent's escape write",
        since=since,
    )
    sessions = [e for e in service.events("agent_shell") if e.seq > since]
    attack.check(
        "recorded",
        any(e.details.get("kind") == "session" for e in sessions),
        f"system/agent_shell kind=session graba que el dueño entró ({len(sessions)}); el sensor "
        "graba el proceso del agente que escribió el escape.",
    )


# --- nombres-de-clave-en-la-linea (both profiles) ----------------------------------------------


@scenario("nombres-de-clave-en-la-linea")
def test_secret_names_on_the_command_line_are_struck(
    attack: Attack, request: pytest.FixtureRequest
) -> None:
    # The secrets are made INSIDE the container (returned by the script), never on this script's
    # own python3 -c argv. The script ends with a sentinel exec `/bin/true <marker>-fin`; the test
    # waits for it before reading, so the box and the file already hold the earlier true/curl/sh
    # execs (M2: otherwise the first marker match is the launcher and the reads come too early).
    marker = f"nkln-{secrets.token_hex(4)}"
    sentinel = f"{marker}-fin"
    if battery_profile() == "claude-code":
        lab: Lab = request.getfixturevalue("cc_lab")
        service = lab.service
        since = sensor_kit.head_seq(service)
        result = attack.run_script(service.jail, "nombres_de_clave_en_la_linea", marker)
        sensor_kit.wait_event(
            service,
            lambda e: e.source == "exec" and sentinel in str(e.details.get("argv", "")),
            "the sentinel exec at the end of the probe",
            since=since,
        )
        recorded = bool(
            [
                e
                for e in service.box.events(since_seq=since)
                if e.source == "exec" and marker in str(e.details.get("argv", ""))
            ]
        )
        box_text = repr([(e.target, e.details) for e in service.box.events(since_seq=since)])
        file_text = sensor_kit.events_text(service)
        box_where = "la caja negra del servicio"
    else:
        agent = request.getfixturevalue("agent")
        sensor = request.getfixturevalue("battery_sensor")
        attack.watch(sensor, agent.jail)
        result = attack.run_script(agent, "nombres_de_clave_en_la_linea", marker)
        attack.recorded_exec(argv=sentinel)  # wait for the sentinel before reading
        recorded = bool(attack.recorded_exec(argv=marker))
        box_text = repr([(e.target, e.details) for e in sensor.box.events()])
        file_text = sensor.events_text() + sensor.sensor_logs()
        box_where = "la caja negra compartida"

    values, file_clean, labels = result["values"], result["file_clean"], result["labels"]
    in_box = [labels[val] for val in values if val in box_text]
    # The first barrier (Tetragon's RE2) must strike the plain forms, so they are absent from the
    # raw Tetragon file too. The quoted forms (a value with a space) and a name followed by a flag
    # (sensor.py: procs-only) are struck only in the black box; the root-only 0600 file may keep
    # them (docs/23 §5), so they are checked in the box alone.
    in_file = [labels[val] for val in file_clean if val in file_text]
    file_only = [val for val in values if val not in file_clean and val in file_text]
    attack.check(
        "stopped",
        in_box == [] and in_file == [],
        f"ninguno de los {len(values)} secretos inventados, en todas sus formas en la línea "
        f"(incluidas las que roban el ancla: Bearer, alice:, una bandera repetida, un "
        f"valor entrecomillado con espacio), llega a {box_where}: {in_box or 'ninguno'}; y las "
        f"{len(file_clean)} formas que la primera barrera tacha tampoco están en el archivo de "
        f"Tetragon ({in_file or 'ninguno'}). En el archivo quedaron solo formas que la primera "
        f"barrera deja a la segunda ({len(file_only)}), ya tachadas en la caja.",
    )
    attack.check(
        "recorded",
        recorded,
        f"el sensor grabó el proceso del ataque (marcador {marker}) con sus argumentos tachados.",
    )
