"""`backtide instalar`, `imagenes`, `enlace`, `comprobar --despues-de-instalar` and the web's
link file (T13-3): arguments, messages in Spanish and exit codes. The installation itself is
tests/test_setup_install.py."""

import os
import stat
from pathlib import Path

import pytest

import backtide.cli as cli
import backtide.web.server as server_module
from backtide.cli import main
from backtide.setup import images, install

URL = "http://127.0.0.1:8765/s/AbCdEfGhIjKlMnOpQrStUv/?t=" + "T" * 43


def run(capsys, *args):
    code = main([str(arg) for arg in args])
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_effective_uid", lambda: 0)


def test_imagenes_lists_the_pinned_images(capsys) -> None:
    code, out, _ = run(capsys, "imagenes")
    assert code == 0
    assert [line.split()[0] for line in out.splitlines()] == [i.ref for i in images.pinned()]


def test_instalar_needs_root(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_effective_uid", lambda: 1000)
    code, _, err = run(capsys, "instalar", "--si")
    assert code == 2 and "necesita root" in err


@pytest.mark.parametrize(
    "args",
    [
        ("--tope-diario", "cinco"),
        ("--volumen-gib", "0"),
    ],
)
def test_instalar_refuses_bad_values(capsys, as_root: None, args: tuple[str, ...]) -> None:
    code, _, err = run(capsys, "instalar", *args)
    assert code == 2 and err


def test_a_key_comes_from_one_place_only(capsys, as_root: None, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["instalar", "--clave-archivo", str(tmp_path / "k"), "--clave-stdin"])
    assert caught.value.code == 2
    assert "--clave-stdin" in capsys.readouterr().err


def test_there_is_no_option_that_takes_a_key_itself() -> None:
    """Invariant 5 and docs/25, section 3: never a key in argv, where `ps` shows it."""
    parser = cli.build_parser()
    choices = parser._subparsers._group_actions[0].choices  # noqa: SLF001
    for action in choices["instalar"]._actions:  # noqa: SLF001
        for flag in action.option_strings:
            if "clave" in flag or "key" in flag:
                assert flag in ("--clave-archivo", "--clave-stdin", "--sin-clave"), flag


def test_instalar_passes_the_options_and_reports_a_stop(
    capsys, as_root: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = {}

    def stopped(self: install.Installer) -> list[str]:
        seen["options"] = self.options
        raise install.InstallError("Docker no responde")

    monkeypatch.setattr(install.Installer, "install", stopped)
    code, _, err = run(
        capsys, "instalar", "--si", "--clave-archivo", tmp_path / "k", "--tope-diario", "7.5",
        "--subredes", "10.77.1.0/24,10.77.2.0/24", "--volumen-gib", "10",
    )  # fmt: skip
    assert code == 1
    assert "la instalación se ha parado: Docker no responde" in err
    assert "vuelve a ejecutar el instalador" in err
    options = seen["options"]
    assert options.yes and options.key_file == tmp_path / "k"
    assert str(options.daily_usd) == "7.5" and options.volume_size == 10 * 1024**3
    assert options.subnets == "10.77.1.0/24,10.77.2.0/24"


def test_the_self_test_needs_root(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_effective_uid", lambda: 1000)
    code, _, err = run(capsys, "comprobar", "--despues-de-instalar")
    assert code == 2 and "root" in err


# The installed web's one-time link: in a file of its own, never in the journal


def test_the_web_writes_its_link_to_its_file_and_not_to_stdout(
    capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "web.toml"
    config.write_text(f'state_dir = "{tmp_path}/state"\nvolume = "{tmp_path}/vol"\n')
    link = tmp_path / "run" / "enlace"
    link.parent.mkdir(mode=0o700)
    seen = {}

    def fake(paths, port, announce, **options) -> None:
        announce(URL, "marea-faro-nube")
        seen["mode"] = stat.S_IMODE(os.stat(link).st_mode)
        seen["text"] = link.read_text()

    monkeypatch.setattr(server_module, "run_web", fake)
    code, out, err = run(capsys, "web", "--config", config, "--enlace-en", link)
    assert code == 0
    assert URL not in out and URL not in err and "?t=" not in out
    assert "sudo backtide enlace" in out and "marea-faro-nube" in out
    assert seen == {"mode": 0o600, "text": f"{URL}\nmarea-faro-nube\n"}
    assert not link.exists()  # a dead link is not left behind


def test_a_link_file_that_cannot_be_written_stops_the_web(
    capsys, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "web.toml"
    config.write_text(f'state_dir = "{tmp_path}/state"\nvolume = "{tmp_path}/vol"\n')
    monkeypatch.setattr(
        server_module, "run_web", lambda paths, port, announce, **o: announce(URL, "a-b-c")
    )
    code, out, err = run(capsys, "web", "--config", config, "--enlace-en", tmp_path / "no/enlace")
    assert code == 1 and "no se puede escribir el enlace" in err
    assert URL not in out + err


def test_enlace_prints_the_link_and_how_to_reach_it(capsys, tmp_path: Path) -> None:
    link = tmp_path / "enlace"
    cli._write_link(link, URL, "marea-faro-nube")  # noqa: SLF001
    code, out, _ = run(capsys, "enlace", "--archivo", link)
    assert code == 0
    assert URL in out and "marea-faro-nube" in out
    assert "ssh -L 8765:127.0.0.1:8765" in out and "restart backtide-web.service" in out


def test_enlace_without_a_running_web_says_how_to_start_it(capsys, tmp_path: Path) -> None:
    code, _, err = run(capsys, "enlace", "--archivo", tmp_path / "none")
    assert code == 1 and "systemctl start backtide-web.service" in err


@pytest.mark.parametrize(
    ("content", "file_mode"),
    [
        (f"{URL}\n", 0o600),  # no run name
        ("http://evil.example/?t=x\nname\n", 0o600),  # not a link of this web
        (f"{URL}\nname\n", 0o644),  # open to others: not the web's file
    ],
)
def test_enlace_prints_only_a_real_link_file(
    capsys, tmp_path: Path, content: str, file_mode: int
) -> None:
    link = tmp_path / "enlace"
    link.write_text(content)
    link.chmod(file_mode)
    code, out, err = run(capsys, "enlace", "--archivo", link)
    assert code == 1 and "no se enseña" in err and "evil" not in out


def test_enlace_never_follows_a_link(capsys, tmp_path: Path) -> None:
    target = tmp_path / "real"
    cli._write_link(target, URL, "a-b-c")  # noqa: SLF001
    (tmp_path / "enlace").symlink_to(target)
    code, out, _ = run(capsys, "enlace", "--archivo", tmp_path / "enlace")
    assert code == 1 and URL not in out
