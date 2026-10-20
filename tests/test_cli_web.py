"""`backtide web`: arguments, messages in Spanish, exit codes, and the real server it starts. The
web needs no secret: these tests run with no gateway token and no key file at all."""

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx2 as httpx
import pytest

import backtide.web.server as server_module
from backtide.blackbox import BlackBox
from backtide.cli import main
from backtide.web.paths import WebPaths
from tests.webkit import KEY


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """A configuration and a black box, and NOTHING else: no gateway.token, no blackbox.key."""
    state = tmp_path / "state"
    state.mkdir()
    path = tmp_path / "backtide.toml"
    path.write_text(f'state_dir = "{state}"\nvolume = "{tmp_path / "vol"}"\n')
    path.chmod(0o644)
    return path


@pytest.fixture
def recorded(config_file: Path) -> BlackBox:
    """What the service would have left: a black box with a few events."""
    state = config_file.parent / "state"
    box = BlackBox(state / "blackbox.db", KEY, checkpoint_path=state / "blackbox.checkpoint")
    box.append("system", "agent_start", "")
    box.append("file", "create", "notas.md", details={"type": "file"})
    return box


def run(capsys, *args):
    code = main([str(arg) for arg in args])
    out, err = capsys.readouterr()
    return code, out, err


def test_web_is_in_the_help(capsys) -> None:
    _, out, _ = run(capsys)
    assert "web" in out


def test_a_bad_port_is_a_usage_error(capsys, config_file: Path) -> None:
    for port in ("-1", "70000"):
        code, _, err = run(capsys, "web", "--config", config_file, "--puerto", port)
        assert code == 2 and "puerto" in err


def test_a_bad_config_is_exit_2(capsys, tmp_path: Path) -> None:
    code, _, err = run(capsys, "web", "--config", tmp_path / "missing.toml")
    assert code == 2 and "configuración no válida" in err


def test_it_never_asks_for_the_key_or_the_token(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    """The service's secrets are not the web's business: it must start without them, and it
    must not even try to read them."""
    import backtide.blackbox.keys as keys
    import backtide.service.config as service_config

    monkeypatch.setattr(keys, "load_key", lambda *a, **k: pytest.fail("the web read the key"))
    monkeypatch.setattr(
        service_config.ServiceConfig,
        "from_file",
        classmethod(lambda *a, **k: pytest.fail("the web read the whole configuration")),
    )
    monkeypatch.setattr(server_module, "run_web", lambda paths, port, announce, **_: None)
    assert run(capsys, "web", "--config", config_file)[0] == 0


def test_it_prints_the_link_once_and_the_name_of_the_run_and_opens_nothing(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    seen = {}

    def fake(paths: WebPaths, port: int, announce, **options) -> None:
        seen.update(paths=paths, port=port, **options)
        announce("http://127.0.0.1:8765/s/abc/?t=SECRET", "marea-faro-nube")

    monkeypatch.setattr(server_module, "run_web", fake)
    code, out, _ = run(capsys, "web", "--config", config_file)
    assert code == 0
    assert out.count("http://127.0.0.1:8765/s/abc/?t=SECRET") == 1
    assert "solo en este ordenador" in out and "Ctrl-C" in out
    assert "Nombre de esta ejecución: marea-faro-nube" in out and "una sola vez" in out
    assert seen["port"] == 8765 and isinstance(seen["paths"], WebPaths)
    # T12b: whether this web can rewind, said once at the start. Writes are explicit: without
    # --rebobinar it only watches.
    assert seen["can_rewind"] is False
    assert "Rebobinar desde la web: no; sin `--rebobinar` esta web solo mira" in out


def test_with_the_flag_it_may_rewind_once_the_service_runs(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    seen = {}

    def fake(paths: WebPaths, port: int, announce, **options) -> None:
        seen.update(options)
        announce("http://x", "a-b-c")

    monkeypatch.setattr(server_module, "run_web", fake)
    code, out, _ = run(capsys, "web", "--config", config_file, "--rebobinar")
    assert code == 0 and seen["can_rewind"] is True
    assert "Rebobinar desde la web: cuando el servicio esté en marcha" in out


def test_a_web_of_another_user_says_it_cannot_rewind(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    from backtide.web import rewind as web_rewind

    monkeypatch.setattr(
        web_rewind.ControlRewinder,
        "availability",
        lambda self: web_rewind.Availability.OTHER_USER,
    )
    monkeypatch.setattr(
        server_module, "run_web", lambda paths, port, announce, **_: announce("http://x", "a-b-c")
    )
    out = run(capsys, "web", "--config", config_file, "--rebobinar")[1]
    assert "Rebobinar desde la web: no" in out and "backtide rebobinar" in out


@pytest.mark.parametrize("flag", ["--puerto", "--port"])
def test_the_port_can_be_chosen(capsys, config_file: Path, monkeypatch, flag: str) -> None:
    ports = []
    monkeypatch.setattr(
        server_module, "run_web", lambda paths, port, announce, **_: ports.append(port)
    )
    assert run(capsys, "web", "--config", config_file, flag, "9123")[0] == 0
    assert ports == [9123]


def test_a_port_in_use_is_exit_1_with_a_sentence(capsys, config_file: Path, recorded) -> None:
    taken = server_module.bind(0)
    try:
        port = taken.getsockname()[1]
        code, _, err = run(capsys, "web", "--config", config_file, "--puerto", str(port))
    finally:
        taken.close()
    assert code == 1 and f"no se puede abrir el puerto {port} en 127.0.0.1" in err
    assert "Traceback" not in err


def test_the_real_web_of_a_real_config(config_file: Path, recorded: BlackBox, monkeypatch) -> None:
    """`run_web` for real, with no key and no token on disk: the link it announces works once,
    the black box of the config is on the page, and the snapshots page falls back to the box
    because the volume is missing."""
    servers = []
    real_make = server_module.make_server

    def capture(app):
        servers.append(real_make(app))
        return servers[-1]

    monkeypatch.setattr(server_module, "make_server", capture)
    announced: list[tuple[str, str]] = []
    paths = WebPaths.from_file(config_file)
    thread = threading.Thread(
        target=server_module.run_web,
        args=(paths, 0, lambda url, name: announced.append((url, name))),
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not (announced and servers and servers[0].started):
        assert time.monotonic() < deadline
        time.sleep(0.02)
    try:
        link, name = announced[0]
        assert link.startswith("http://127.0.0.1:") and "/s/" in link and "/?t=" in link
        base, _, token = link.partition("/?t=")
        with httpx.Client(base_url=base) as browser:
            assert browser.get("/ahora").status_code == 401
            enter = browser.get(f"/ahora?t={token}")  # the page that sets the cookie...
            assert enter.status_code == 200 and "refresh" in enter.text
            page = browser.get("/ahora")  # ...and the next navigation, which carries it
            assert page.status_code == 200 and "notas.md" in page.text and name in page.text
            fresh = httpx.get(f"{base}/ahora?t={token}")  # the link is dead for anyone else
            assert fresh.status_code == 401
            snaps = browser.get("/instantaneas")
            assert snaps.status_code == 200
            assert (
                "No se puede leer el volumen" in snaps.text or "No hay instantáneas" in snaps.text
            )
    finally:
        servers[0].should_exit = True
        thread.join(10)
    assert not thread.is_alive()


@pytest.mark.parametrize("euid", [0, 1000])
def test_a_web_run_as_root_needs_the_flag_and_says_so(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch, euid: int
) -> None:
    """T12b: a root web has every privilege of root. Without --rebobinar it does not start (to
    watch, run it as a reader); with it, it starts and says so."""
    import backtide.cli as cli_module

    started = []
    monkeypatch.setattr(cli_module, "_effective_uid", lambda: euid)
    monkeypatch.setattr(
        server_module,
        "run_web",
        lambda paths, port, announce, **_: (started.append(1), announce("http://x", "a-b-c")),
    )
    code, out, err = run(capsys, "web", "--config", config_file)
    if euid == 0:
        assert code == 2 and started == []
        assert "como root" in err and "--rebobinar" in err and "usuario lector" in err
    else:
        assert code == 0 and started == [1]
    code, out, _ = run(capsys, "web", "--config", config_file, "--rebobinar")
    assert code == 0
    warned = "Ojo: esta web corre como root; para solo mirar, lánzala con un usuario lector" in out
    assert warned is (euid == 0)


def test_settings_are_off_unless_asked_for(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    """T12e: `--ajustes` turns the Settings page on, like `--rebobinar` the rewind."""
    seen: list[dict] = []

    def fake(paths: WebPaths, port: int, announce, **options) -> None:
        seen.append(options)
        announce("http://x", "a-b-c")

    monkeypatch.setattr(server_module, "run_web", fake)
    code, out, _ = run(capsys, "web", "--config", config_file)
    assert code == 0 and seen[-1]["can_set"] is False
    assert "Ajustes desde la web: no; sin `--ajustes`" in out
    code, out, _ = run(capsys, "web", "--config", config_file, "--ajustes")
    assert code == 0 and seen[-1]["can_set"] is True and seen[-1]["can_rewind"] is False
    assert "Ajustes desde la web: cuando el servicio esté en marcha" in out


def test_approvals_are_off_unless_asked_for(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    """T10-5 (decision 10): `--aprobar` lets the web approve and reject held requests, like
    `--rebobinar` the rewind; without it they are listed with their buttons off."""
    import backtide.cli as cli_module

    seen: list[dict] = []

    def fake(paths: WebPaths, port: int, announce, **options) -> None:
        seen.append(options)
        announce("http://x", "a-b-c")

    monkeypatch.setattr(server_module, "run_web", fake)
    code, out, _ = run(capsys, "web", "--config", config_file)
    assert code == 0 and seen[-1]["can_approve"] is False
    assert "Aprobar desde la web: no; sin `--aprobar`" in out
    code, out, _ = run(capsys, "web", "--config", config_file, "--aprobar")
    assert code == 0 and seen[-1]["can_approve"] is True
    assert seen[-1]["can_set"] is False and seen[-1]["can_rewind"] is False
    assert "Aprobar desde la web: cuando el servicio esté en marcha" in out
    monkeypatch.setattr(cli_module, "_effective_uid", lambda: 0)
    code, out, _ = run(capsys, "web", "--config", config_file, "--aprobar")
    assert code == 0 and "Ojo: esta web corre como root" in out


def test_a_root_web_with_only_ajustes_starts_and_warns(
    capsys, config_file: Path, recorded: BlackBox, monkeypatch
) -> None:
    import backtide.cli as cli_module

    monkeypatch.setattr(cli_module, "_effective_uid", lambda: 0)
    monkeypatch.setattr(
        server_module, "run_web", lambda paths, port, announce, **_: announce("http://x", "a-b-c")
    )
    code, out, _ = run(capsys, "web", "--config", config_file, "--ajustes")
    assert code == 0 and "Ojo: esta web corre como root" in out


@pytest.mark.parametrize("stop_signal", [signal.SIGINT, signal.SIGTERM], ids=["ctrl-c", "sigterm"])
def test_a_real_web_stopped_by_a_signal_says_so_and_exits_0(
    config_file: Path, recorded: BlackBox, stop_signal: signal.Signals
) -> None:
    """Ctrl-C (SIGINT) and SIGTERM end `backtide web` the way its help promises: the closing line,
    exit code 0, no traceback. uvicorn re-raises a captured signal once it has shut down, which
    used to end the process by the signal itself (code -2 and a KeyboardInterrupt)."""
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "backtide.cli",
            "web",
            "--config",
            str(config_file),
            "--puerto",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        assert process.stdout is not None
        url = ""
        for line in process.stdout:  # the link is printed before the server starts to serve
            if line.strip().startswith("http://"):
                url = line.strip()
                break
        assert url
        for _ in range(100):  # an answer proves uvicorn is serving, so its handlers are in place
            try:
                if httpx.get(url, follow_redirects=False).status_code:
                    break
            except httpx.TransportError:
                time.sleep(0.1)
        process.send_signal(stop_signal)
        out, err = process.communicate(timeout=20)
    finally:
        process.kill()
        process.wait()
    assert process.returncode == 0, err
    assert "Puesto de vigilancia parado." in out
    assert "Traceback" not in err and "KeyboardInterrupt" not in err
