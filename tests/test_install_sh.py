"""install.sh, the bootstrap (docs/25, section 4; T13-3). It runs for real only in a clean VM
(tests/install/instalar_lab.sh); here: that it is valid sh, short, pinned, and that it stops
before changing anything when it is not root or not on a supported Linux. And (T14, R1 of the
T13-3 review) that it builds nothing: its own functions, taken out of the script, refuse an
unpinned or unhashed requirement, and with the real uv they refuse anything that needs building."""

import base64
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.test_release import BAD, GOOD

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"
TEXT = SCRIPT.read_text()


def test_it_is_valid_posix_sh_and_short_enough_to_read() -> None:
    subprocess.run(["sh", "-n", str(SCRIPT)], check=True)
    assert TEXT.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in TEXT
    # docs/25 said "unas 100–150 líneas"; T14's check of requirements.txt and the venv without
    # building (about 40 lines) and the review's hardening (about 15) took it past that.
    # The check before the version in use changes (review of D27) took it a little past 210,
    # and the code review of 2026-10-29 (absolute file paths, I3; an honest --dry-run, I4) to 221.
    assert len(TEXT.splitlines()) <= 222


def test_uv_is_pinned_by_version_and_hash() -> None:
    assert re.search(r"^UV_VERSION=\d+\.\d+\.\d+$", TEXT, re.M)
    for arch in ("X86_64", "AARCH64"):
        assert re.search(rf"^UV_SHA256_{arch}=[0-9a-f]{{64}}$", TEXT, re.M), arch
    # the archive is checked before it is unpacked, and a mismatch stops everything
    check = TEXT.index('"$UV_SHA256" ] || die')
    assert check < TEXT.index('tar -xzf "$WORK/uv.tar.gz"')


def test_the_release_is_checked_before_anything_is_written() -> None:
    compared = TEXT.index('[ "$GOT" = "$WANT" ] || die')
    written = TEXT.index('mkdir -p "$OPT')
    assert compared < TEXT.index('tar -xf "$ARCHIVE"') < written
    # A plain git archive (no requirements.txt) and a bad requirements.txt stop it, also before.
    assert compared < TEXT.index('[ -f "$TOP/requirements.txt" ]') < written
    assert compared < TEXT.index('check_requirements "$TOP/requirements.txt" || die') < written
    assert "UV_PYTHON_PREFERENCE=only-managed" in TEXT


def test_nothing_is_built_and_every_wheel_is_checked_by_hash() -> None:
    body = TEXT.split("\nset -eu\n", 1)[1]
    assert "uv sync" not in body and " sync " not in body  # uv sync builds the project
    assert "--require-hashes --no-build" in function("install_release")
    assert "UV_BUILD_CONSTRAINT" not in TEXT  # ignored by uv sync (T13-3); not needed any more
    # The release folder, half made by a cut, is made again: the launcher is the last thing.
    installed = function("install_release")
    assert installed.rindex('mv "$1/.venv/bin/backtide.new"') > installed.index("pip install")


def test_it_never_runs_what_it_downloads_through_a_shell_or_eval() -> None:
    assert "eval" not in TEXT
    assert "| sh" not in TEXT.split("\nset -eu\n", 1)[1]
    assert "| bash" not in TEXT


def test_no_key_goes_through_it() -> None:
    body = TEXT.split("\nset -eu\n", 1)[1]
    assert "clave" not in body.lower().replace("--clave-archivo file", "")
    assert "KEY" not in body


@pytest.mark.parametrize("args", [(), ("--desde", "x.tar", "--sha256", "0" * 64)])
def test_without_root_it_stops_at_once(args: tuple[str, ...], tmp_path: Path) -> None:
    done = subprocess.run(
        ["sh", str(SCRIPT), *args], capture_output=True, text=True, cwd=tmp_path, check=False
    )
    assert done.returncode == 1
    if sys.platform == "darwin":
        # On a Mac it hands over to install-mac.sh, which never asks for root (T13b) and stops
        # at the missing or unreadable archive, before any change.
        assert "aún no hay versión publicada" in done.stderr or "no existe x.tar" in done.stderr
    else:
        assert "hace falta root" in done.stderr
    assert list(tmp_path.iterdir()) == []


def test_an_unsupported_system_stops_before_any_change(tmp_path: Path) -> None:
    """With a fake `id` that says root and no archive: on the Mac it hands over to install-mac.sh,
    which refuses root; on a supported Linux (CI) it stops at the missing release. Either way,
    before any change."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "id").write_text("#!/bin/sh\necho 0\n")
    (fake / "id").chmod(0o755)
    done = subprocess.run(
        ["sh", str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={"PATH": f"{fake}:/usr/bin:/bin"},
        check=False,
    )
    assert done.returncode == 1
    if sys.platform == "darwin":
        assert "sin sudo" in done.stderr  # install-mac.sh: root on the Mac is refused (T13b)
    else:
        assert (
            "os-release" in done.stderr
            or "no es una de las que admite" in done.stderr
            or ("aún no hay versión publicada" in done.stderr)
        )
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bin"]


def test_a_second_run_keeps_the_uv_it_has(tmp_path: Path) -> None:
    """uv prints its version with the platform after it (``uv 0.12.17 (aarch64-unknown-linux-gnu)``,
    seen in the Mac's VM, T13b): the check compares the first two words, so a second run does not
    download and reinstall uv."""
    line = next(line for line in TEXT.splitlines() if '"$UV" --version' in line)
    check = line.split("[ ", 2)[2].split(" ]", 1)[0]
    fake = tmp_path / "uv"
    fake.write_text("#!/bin/sh\necho 'uv 0.12.17 (aarch64-unknown-linux-gnu)'\n")
    fake.chmod(0o755)
    test = f"UV={fake}; UV_VERSION=0.12.17; if [ {check} ]; then echo again; else echo kept; fi"
    assert subprocess.run(["sh", "-c", test], capture_output=True, text=True).stdout == "kept\n"
    other = test.replace("UV_VERSION=0.12.17", "UV_VERSION=0.12.18")
    assert subprocess.run(["sh", "-c", other], capture_output=True, text=True).stdout == "again\n"


def function(name: str) -> str:
    """One of install.sh's functions, as text: from ``name() {`` to its closing ``}``."""
    match = re.search(rf"^{name}\(\) {{\n.*?^}}\n", TEXT, re.M | re.S)
    assert match, name
    return match.group(0)


def check(tmp_path: Path, text: str) -> subprocess.CompletedProcess[str]:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(text)
    script = function("check_requirements") + 'check_requirements "$1"\n'
    return subprocess.run(
        ["sh", "-c", script, "sh", str(requirements)], capture_output=True, text=True, check=False
    )


def test_the_check_takes_what_uv_export_writes(tmp_path: Path) -> None:
    assert check(tmp_path, GOOD).returncode == 0
    # And the real export of this repository's lock, as `make release` writes it.
    from scripts.release import build_release as release

    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv")
    files = {name: ((ROOT / name).read_bytes(), False) for name in ("pyproject.toml", "uv.lock")}
    done = check(tmp_path, release.export_requirements(files, uv))
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("case", sorted(BAD))
def test_the_check_refuses_an_unpinned_unhashed_or_odd_requirement(
    tmp_path: Path, case: str
) -> None:
    """The same cases as the release script's own check (tests/test_release.py): both agree."""
    done = check(tmp_path, BAD[case])
    assert done.returncode != 0, case
    assert "backtide: requirements.txt" in done.stderr


FAKE_UV = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_UV_LOG"
case "$1" in
  venv) for last; do :; done; mkdir -p "$last/bin" "$last/lib/python3.12/site-packages" ;;
  pip) [ -z "${FAKE_UV_FAIL:-}" ] || { echo "error: needs building" >&2; exit 2; } ;;
esac
"""


def run_install_release(
    tmp_path: Path, uv: str, env: dict[str, str] | None = None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    release_dir = tmp_path / "opt" / "releases" / "0.1.0-abcdef123456"
    release_dir.mkdir(parents=True)
    (release_dir / "requirements.txt").write_text(GOOD)
    script = function("install_release") + 'install_release "$1"\n'
    done = subprocess.run(
        ["sh", "-c", script, "sh", str(release_dir)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ["PATH"], "UV": uv, **(env or {})},
    )
    return done, release_dir


def test_install_release_runs_uv_with_hashes_and_no_build_and_writes_the_launcher(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "uv"
    fake.write_text(FAKE_UV)
    fake.chmod(0o755)
    log = tmp_path / "uv.log"
    done, release_dir = run_install_release(tmp_path, str(fake), {"FAKE_UV_LOG": str(log)})
    assert done.returncode == 0, done.stderr
    venv = release_dir / ".venv"
    assert log.read_text().splitlines() == [
        f"venv --quiet --python 3.12 {venv}",
        f"pip install --python {venv}/bin/python --require-hashes --no-build "
        f"-r {release_dir}/requirements.txt",
    ]
    pth = venv / "lib" / "python3.12" / "site-packages" / "backtide-release.pth"
    assert pth.read_text() == f"{release_dir}\n"
    launcher = venv / "bin" / "backtide"
    assert launcher.read_text() == (
        f"#!{venv}/bin/python -I\nimport sys\nfrom backtide.cli import main\nsys.exit(main())\n"
    )
    assert launcher.stat().st_mode & 0o777 == 0o755


def test_install_release_stops_without_a_launcher_when_uv_refuses(tmp_path: Path) -> None:
    fake = tmp_path / "uv"
    fake.write_text(FAKE_UV)
    fake.chmod(0o755)
    env = {"FAKE_UV_LOG": str(tmp_path / "uv.log"), "FAKE_UV_FAIL": "1"}
    done, release_dir = run_install_release(tmp_path, str(fake), env)
    assert done.returncode != 0
    assert not (release_dir / ".venv" / "bin" / "backtide").exists()
    assert not (release_dir / ".venv" / "lib" / "python3.12" / "site-packages" / "x").exists()


# --- With the real uv, offline, against wheels and an sdist made here -------------------------


def make_wheel(folder: Path, name: str) -> Path:
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n".encode()
    wheel_tag = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files = {
        f"{name}/__init__.py": b"X = 1\n",
        f"{name}-1.0.dist-info/METADATA": metadata,
        f"{name}-1.0.dist-info/WHEEL": wheel_tag,
    }
    record = []
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append(f"{name}-1.0.dist-info/RECORD,,")
    files[f"{name}-1.0.dist-info/RECORD"] = ("\n".join(record) + "\n").encode()
    wheel = folder / f"{name}-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return wheel


def make_sdist(folder: Path, name: str) -> Path:
    """Only a source archive: installing it would mean building it (here, with setuptools)."""
    sdist = folder / f"{name}-1.0.tar.gz"
    project = (
        b'[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        b'[project]\nname = "' + name.encode() + b'"\nversion = "1.0"\n'
    )
    with tarfile.open(sdist, "w:gz") as archive:
        for path, data in {
            f"{name}-1.0/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n".encode(),
            f"{name}-1.0/pyproject.toml": project,
        }.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return sdist


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def real_uv(tmp_path: Path) -> tuple[str, Path, dict[str, str]]:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv")
    index = tmp_path / "index"
    index.mkdir()
    env = {
        "UV_OFFLINE": "1",  # nothing leaves this machine: the wheels come from `index`
        "UV_NO_INDEX": "1",
        "UV_FIND_LINKS": str(index),
        "UV_CACHE_DIR": str(tmp_path / "cache"),
        "UV_NO_CONFIG": "1",
        "HOME": os.environ.get("HOME", str(tmp_path)),
    }
    found = subprocess.run(
        [uv, "python", "find", "3.12"], capture_output=True, env={**os.environ, **env}, check=False
    )
    if found.returncode != 0:
        pytest.skip("no Python 3.12 for uv offline")
    return uv, index, env


def install_with_real_uv(
    tmp_path: Path,
    real_uv: tuple[str, Path, dict[str, str]],
    requirements: str,
    extra: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    uv, _, env = real_uv
    release_dir = tmp_path / "release"
    (release_dir / "backtide").mkdir(parents=True)
    (release_dir / "backtide" / "__init__.py").write_text("")
    (release_dir / "backtide" / "cli.py").write_text(
        "import sys\ndef main():\n    print('backtide', sys.flags.isolated, sys.argv[1:])\n"
        "    return 0\n"
    )
    (release_dir / "requirements.txt").write_text(requirements)
    for name, text in (extra or {}).items():
        (release_dir / name).write_text(text)
    script = function("install_release") + 'install_release "$1"\n'
    done = subprocess.run(
        ["sh", "-c", script, "sh", str(release_dir)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ["PATH"], "UV": uv, **env},
    )
    return done, release_dir


def test_with_the_real_uv_the_wheels_install_and_the_launcher_runs_isolated(
    tmp_path: Path, real_uv: tuple[str, Path, dict[str, str]]
) -> None:
    wheel = make_wheel(real_uv[1], "alfa")
    done, release_dir = install_with_real_uv(
        tmp_path, real_uv, f"alfa==1.0 \\\n    --hash=sha256:{sha(wheel)}\n"
    )
    assert done.returncode == 0, done.stderr
    ran = subprocess.run(
        [str(release_dir / ".venv" / "bin" / "backtide"), "comprobar"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": "/nowhere-to-import-from"},
        check=True,
    )
    assert ran.stdout == "backtide 1 ['comprobar']\n"  # python -I, backtide from its folder


def test_with_the_real_uv_a_source_archive_is_never_built(
    tmp_path: Path, real_uv: tuple[str, Path, dict[str, str]]
) -> None:
    sdist = make_sdist(real_uv[1], "beta")
    done, release_dir = install_with_real_uv(
        tmp_path, real_uv, f"beta==1.0 --hash=sha256:{sha(sdist)}\n"
    )
    assert done.returncode != 0
    assert "--no-build" in done.stderr
    assert not (release_dir / ".venv" / "bin" / "backtide").exists()
    assert not list((tmp_path / "cache").glob("builds-*/*"))  # no build environment either


@pytest.mark.parametrize("case", ["wrong hash", "unhashed", "unpinned"])
def test_with_the_real_uv_a_wrong_or_missing_hash_is_refused(
    tmp_path: Path, real_uv: tuple[str, Path, dict[str, str]], case: str
) -> None:
    """uv's own check, under install.sh's: even past check_requirements, nothing goes in."""
    wheel = make_wheel(real_uv[1], "alfa")
    requirements = {
        "wrong hash": f"alfa==1.0 --hash=sha256:{'0' * 64}\n",
        "unhashed": "alfa==1.0\n",
        "unpinned": f"alfa>=1.0 --hash=sha256:{sha(wheel)}\n",
    }[case]
    done, release_dir = install_with_real_uv(tmp_path, real_uv, requirements)
    assert done.returncode != 0
    assert not (release_dir / ".venv" / "bin" / "backtide").exists()
    assert not (release_dir / ".venv" / "lib" / "python3.12" / "site-packages" / "alfa").exists()


def test_the_caller_environment_is_cleaned_before_curl_and_uv() -> None:
    """Review of T14-R1: nothing of the caller's steers uv, curl or the temporary folder."""
    body = TEXT.split("\nset -eu\n", 1)[1]
    call = body.index("\nclean_env\n")
    assert call < body.index("curl -fsSL") and call < body.index('"$UV" --version')
    assert call < body.index("WORK=$(mktemp -d /tmp/backtide.XXXXXX)")  # not $TMPDIR's
    moved = body.index("\ncd /")
    assert body.index('cp "$SOURCE" "$ARCHIVE"') < moved < body.index('tar -xf "$ARCHIVE"')
    assert moved < body.index('"$UV" --version')


def test_clean_env_leaves_uv_none_of_the_callers_variables(tmp_path: Path) -> None:
    fake = tmp_path / "uv"
    fake.write_text('#!/bin/sh\nenv > "$FAKE_UV_ENV"\n')
    fake.chmod(0o755)
    dump = tmp_path / "env.txt"
    script = function("clean_env") + 'clean_env\nexport UV_NO_CONFIG=1\n"$UV" venv\n'
    subprocess.run(
        ["sh", "-c", script],
        check=True,
        env={
            "PATH": os.environ["PATH"],
            "UV": str(fake),
            "FAKE_UV_ENV": str(dump),
            "UV_PYTHON_DOWNLOADS_JSON_URL": "x",
            "UV_INDEX_URL": "https://example.test/simple",
            "UV_INSECURE_HOST": "example.test",
            "SSL_CERT_FILE": str(tmp_path / "ca.pem"),
            "SSL_CERT_DIR": str(tmp_path / "certs"),
            "TMPDIR": str(tmp_path / "elsewhere"),
        },
    )
    seen = dict(line.split("=", 1) for line in dump.read_text().splitlines() if "=" in line)
    assert sorted(k for k in seen if k.startswith("UV_")) == ["UV_NO_CONFIG"]
    assert not {"SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR"} & seen.keys()


def test_with_the_real_uv_a_comment_continued_hides_a_line_and_the_check_refuses_it(
    tmp_path: Path, real_uv: tuple[str, Path, dict[str, str]]
) -> None:
    """Review of T14-R1: uv ends a comment at its own line, so a comment ending in a backslash,
    then `-r FILE`, makes uv read FILE: here a direct URL to a wheel no hash of ours names. The
    check refuses it."""
    alfa = make_wheel(real_uv[1], "alfa")
    other = tmp_path / "other"
    other.mkdir()
    beta = make_wheel(other, "beta")
    requirements = f"alfa==1.0 --hash=sha256:{sha(alfa)}\n# note \\\n-r other.txt\n"
    hidden = {"other.txt": f"beta @ {beta.as_uri()} --hash=sha256:{sha(beta)}\n"}
    # uv on its own installs what the hidden line names (today's behaviour, measured):
    done, release_dir = install_with_real_uv(tmp_path, real_uv, requirements, hidden)
    assert done.returncode == 0, done.stderr
    assert (release_dir / ".venv" / "lib" / "python3.12" / "site-packages" / "beta").is_dir()
    # install.sh's check, which runs before uv, refuses the file.
    refused = check(tmp_path, requirements)
    assert refused.returncode != 0
    assert "bytes que uv export no escribe" in refused.stderr


def test_only_what_was_tried_is_called_tested_and_the_rest_is_said_untested() -> None:
    """docs/44 and the testers' guide: Fedora 44 and Ubuntu 24.04 on aarch64 are tested; Fedora
    43, Ubuntu 26.04 and x86_64 are accepted, and the script says they are untested."""
    notice = TEXT[TEXT.index("backtide is a PREVIEW") :].split("\nEOF\n", 1)[0]
    assert "Tested: Fedora 44 and Ubuntu 24.04 on arm64" in notice
    assert "Fedora 43,\n    Ubuntu 26.04 and x86_64 are accepted but untested" in notice
    distro = TEXT[TEXT.index('case "$DISTRO" in') :].split("\nesac\n", 1)[0]
    assert '"ubuntu 24.04" | "fedora 44") ;;' in distro
    assert (
        '"ubuntu 26.04" | "fedora 43") say "$DISTRO se admite pero aún no se ha probado' in distro
    )
    arch = TEXT[TEXT.index('case "$(uname -m)" in') :].split("\nesac\n", 1)[0]
    assert 'say "x86_64 se admite pero aún no se ha probado (solo aarch64)"' in arch
    assert "aarch64) UV_TRIPLE" in arch and "se admite" not in arch.split("aarch64)", 1)[1]


def test_what_the_run_would_refuse_is_checked_before_the_version_in_use_changes() -> None:
    """Review of D27, finding 1: another --perfil over an install must not leave the new release
    in /opt/backtide/current (the service runs from there) when `backtide instalar` refuses."""
    check = TEXT.index('"$RELEASE/.venv/bin/backtide" instalar --solo-comprobar "$@" < /dev/null')
    assert TEXT.index('install_release "$RELEASE"') < check < TEXT.index('ln -sfn "releases/')
    assert TEXT[check:].split("\n", 1)[0].endswith('|| die "no se ha cambiado la versión en uso"')
    # At column 0, on the script's own path: never inside an if/else that could skip it.
    assert TEXT[check - 1] == "\n"


def test_files_named_on_the_command_line_are_made_absolute_before_moving_to_root(
    tmp_path: Path,
) -> None:
    """I3 of the code review of 2026-10-29: `cd /` came before `backtide instalar` read a
    relative --clave-archivo, which failed only at step 10, after pulling the images."""
    start = TEXT.index("# Take --desde and --sha256 out")
    loop = TEXT[start : TEXT.index("\ndone\n", start) + len("\ndone\n")]
    assert TEXT.index(loop) < TEXT.index("\ncd /")
    script = (
        'die() { echo "$*" >&2; exit 2; }\n' + function("absolute") + loop + 'printf "%s\\n" "$@"\n'
    )
    args = ["--clave-archivo", "k.txt", "--telegram-token-archivo=t.txt",
            "--clave-archivo=/abs", "--desde", "b.tar", "--perfil", "claude-code",
            "--telegram-token-archivo", "-"]  # fmt: skip
    ran = subprocess.run(["sh", "-c", script, "install.sh", *args], cwd=tmp_path,
                         capture_output=True, text=True, check=True)  # fmt: skip
    here = os.path.realpath(tmp_path)
    assert ran.stdout.splitlines() == [
        "--clave-archivo", f"{here}/k.txt", f"--telegram-token-archivo={here}/t.txt",
        "--clave-archivo=/abs", "--perfil", "claude-code", "--telegram-token-archivo", "-",
    ]  # fmt: skip


def test_a_dry_run_with_nothing_installed_says_nothing_was_checked() -> None:
    """I4: exiting 0 after two lines read like a passed check."""
    dry = TEXT[TEXT.index('if [ "$DRY_RUN" = 1 ]; then') :]
    dry = dry[: dry.index("\nfi\n")]
    assert "NO se ha comprobado" in dry and "versión ya instalada" in dry
