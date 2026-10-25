"""The installer's pieces on a real Linux (T13-2): the preflight with the real host, and the
systemd units against the VM's own systemd.

Runs as the unprivileged Lima user in vigia-dev, so it changes nothing: the preflight only
reads, and the units are rendered to a temporary folder and checked with ``systemd-analyze``.
"""

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from backtide.setup import host, layout, preflight, units, volume
from backtide.setup.host import SystemHost
from backtide.setup.preflight import Status

pytestmark = pytest.mark.integration


def test_the_dev_vm_passes_the_preflight() -> None:
    checks = {check.key: check for check in preflight.run_checks(SystemHost(), installing=False)}
    report = preflight.report(list(checks.values()))
    print(report)
    assert not preflight.failed(list(checks.values())), report
    # vigia-dev runs kernel 6.19: its BTF is the usual size, and the sensor works there.
    assert checks["btf"].status is Status.OK, report
    for key in ("arch", "btrfs", "loop", "cgroup", "systemd", "ids", "btrfs-progs", "openssl"):
        assert checks[key].status is Status.OK, report


def test_the_btf_header_is_the_one_tetragon_reads() -> None:
    data = SystemHost().read(preflight.BTF_FILE, preflight.BTF_READ)
    assert data, "no BTF in the dev VM"
    assert preflight.btf_header_problem(data) is None


@pytest.mark.parametrize(
    "path",
    [
        layout.VOLUME_MOUNT,
        layout.PROXY_CHANNEL_DIR,
        Path("/"),
        Path("/a/.hidden"),
        Path("/.hidden"),
        Path("/x y/é-ü"),
    ],
)
def test_escape_path_matches_systemd_escape(path: Path) -> None:
    done = subprocess.run(
        ["systemd-escape", "-p", str(path)], capture_output=True, text=True, check=True
    )
    assert units.escape_path(path) == done.stdout.strip()


def test_the_units_pass_systemd_analyze_verify(tmp_path: Path) -> None:
    """``systemd-analyze verify`` reads each unit as systemd would. The program, the image and
    the folders do not exist here, so they point at ones that do; the rest is the real text."""
    stand_ins = {
        str(layout.PROGRAM): shutil.which("true") or "/usr/bin/true",
        str(layout.VOLUME_IMAGE): str(tmp_path / "volume.img"),
    }
    (tmp_path / "volume.img").write_bytes(b"")
    for name, text in units.render_units().items():
        for real, stand_in in stand_ins.items():
            text = text.replace(real, stand_in)
        (tmp_path / name).write_text(text)
    names = [str(tmp_path / name) for name in units.render_units()]
    assert not _verify_problems(names), names
    # Controls: verify prints something for each kind of mistake, so a silent verify means
    # clean units (there is no filter: any line is a problem).
    service = (tmp_path / layout.SERVICE_UNIT).read_text()
    mount = (tmp_path / units.volume_unit_name()).read_text()
    for name, text in (
        (layout.SERVICE_UNIT, service.replace("ProtectHome=yes", "ProtectHome=sometimes")),
        (
            layout.SERVICE_UNIT,
            service.replace("Requires=docker.service", "Requires=dokcer.service"),
        ),
        ("var-lib-otro.mount", mount),  # a name that does not match its Where=
    ):
        broken = tmp_path / "broken" / name
        broken.parent.mkdir(exist_ok=True)
        broken.write_text(text)
        assert _verify_problems([str(broken)]), name
        broken.unlink()


def _verify_problems(paths: list[str]) -> list[str]:
    done = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", *paths], capture_output=True, text=True
    )
    return [line for line in done.stderr.splitlines() if line.strip()]


def test_seal_refuses_a_folder_that_is_not_the_mounted_volume(tmp_path: Path) -> None:
    """With the real findmnt: a plain folder (on the VM's own disk) is not the volume, so its
    mode stays as it was."""
    folder = tmp_path / "not-mounted"
    folder.mkdir()
    folder.chmod(0o755)
    with pytest.raises(volume.VolumeError, match="no está montado"):
        volume.seal_mounted_root(folder, run=host.run)
    assert stat.S_IMODE(folder.stat().st_mode) == 0o755


def test_mkfs_never_formats_an_image_twice(tmp_path: Path) -> None:
    """The second format of the same image must fail: reinstalling never wipes the agent's
    history (mkfs.btrfs refuses an existing filesystem without -f)."""
    image = tmp_path / "volume.img"
    with image.open("wb") as file:
        file.truncate(256 * 1024 * 1024)
    assert volume.format_image(image, run=host.run) is False
    with pytest.raises(volume.VolumeError, match="mkfs.btrfs"):
        volume.format_image(image, run=host.run)
