"""install.sh, the bootstrap (docs/25, section 4; T13-3). It runs for real only in a clean VM
(tests/install/instalar_lab.sh); here: that it is valid sh, short, pinned, and that it stops
before changing anything when it is not root or not on a supported Linux."""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"
TEXT = SCRIPT.read_text()


def test_it_is_valid_posix_sh_and_short_enough_to_read() -> None:
    subprocess.run(["sh", "-n", str(SCRIPT)], check=True)
    assert TEXT.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in TEXT
    assert len(TEXT.splitlines()) <= 150  # docs/25: "unas 100–150 líneas"


def test_uv_is_pinned_by_version_and_hash() -> None:
    assert re.search(r"^UV_VERSION=\d+\.\d+\.\d+$", TEXT, re.M)
    for arch in ("X86_64", "AARCH64"):
        assert re.search(rf"^UV_SHA256_{arch}=[0-9a-f]{{64}}$", TEXT, re.M), arch
    # the archive is checked before it is unpacked, and a mismatch stops everything
    check = TEXT.index('"$UV_SHA256" ] || die')
    assert check < TEXT.index('tar -xzf "$WORK/uv.tar.gz"')


def test_the_release_is_checked_before_anything_is_written() -> None:
    compared = TEXT.index('[ "$GOT" = "$WANT" ] || die')
    assert compared < TEXT.index("mkdir -p")
    assert compared < TEXT.index('tar -xf "$ARCHIVE"')
    assert "--locked --no-dev" in TEXT and "UV_PYTHON_PREFERENCE=only-managed" in TEXT


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
    assert "hace falta root" in done.stderr
    assert list(tmp_path.iterdir()) == []


def test_an_unsupported_system_stops_before_any_change(tmp_path: Path) -> None:
    """With a fake `id` that says root and no archive: on the Mac there is no os-release, so it
    stops there; on a supported Linux (CI) it stops at the missing release. Either way, before
    any change."""
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
        assert "os-release" in done.stderr or "no es una de las que admite" in done.stderr
    else:
        assert (
            "os-release" in done.stderr
            or "no es una de las que admite" in done.stderr
            or ("aún no hay versión publicada" in done.stderr)
        )
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bin"]
