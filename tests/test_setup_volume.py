"""The volume's creation steps (docs/25, section 1; T13-2), with a fake runner on the Mac."""

import os
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest

from backtide.setup import layout, volume
from backtide.setup.host import Ran
from backtide.setup.volume import VolumeError

MIB = 1024**2


class FakeRun:
    """Records each argv (with the image's size at that moment) and answers from a table."""

    def __init__(
        self, answers: dict[tuple[str, ...], Ran] | None = None, image: Path | None = None
    ):
        self.answers = answers or {}
        self.image = image
        self.calls: list[tuple[str, ...]] = []
        self.sizes: list[int | None] = []

    def __call__(self, argv: Sequence[str]) -> Ran | None:
        self.calls.append(tuple(argv))
        self.sizes.append(self.image.stat().st_size if self.image and self.image.exists() else None)
        return self.answers.get(tuple(argv), Ran(0, "", ""))


# Building the image


def test_create_image_makes_a_private_sparse_file(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    run = FakeRun()
    volume.create_image(image, 64 * MIB, run=run, nocow=False)
    info = image.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_size == 64 * MIB
    assert info.st_blocks * 512 < MIB  # sparse: nothing written yet
    assert run.calls == []


def test_nocow_is_set_on_the_empty_file_before_it_has_a_size(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    run = FakeRun(image=image)
    volume.create_image(image, 64 * MIB, run=run, nocow=True)
    assert run.calls == [("chattr", "+C", str(image))]
    assert run.sizes == [0]  # chattr +C only works on an empty file


def test_an_existing_image_is_never_touched(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    image.write_bytes(b"the agent's history")
    with pytest.raises(VolumeError, match="ya existe"):
        volume.create_image(image, 64 * MIB, run=FakeRun(), nocow=True)
    assert image.read_bytes() == b"the agent's history"


def test_a_symlink_in_place_of_the_image_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(b"keep")
    (tmp_path / "volume.img").symlink_to(target)
    with pytest.raises(VolumeError):
        volume.create_image(tmp_path / "volume.img", 64 * MIB, run=FakeRun(), nocow=False)
    assert target.read_bytes() == b"keep"


def test_a_failed_chattr_removes_the_new_empty_file(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    run = FakeRun({("chattr", "+C", str(image)): Ran(1, "", "chattr: Operation not supported")})
    with pytest.raises(VolumeError, match="chattr"):
        volume.create_image(image, 64 * MIB, run=run, nocow=True)
    assert not image.exists()


def test_a_missing_program_is_an_error(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    with pytest.raises(VolumeError, match="chattr"):
        volume.create_image(image, 64 * MIB, run=lambda argv: None, nocow=True)


@pytest.mark.parametrize("size", [0, -1, 1000])
def test_the_size_must_be_whole_mib(tmp_path: Path, size: int) -> None:
    with pytest.raises(ValueError):
        volume.create_image(tmp_path / "v.img", size, run=FakeRun(), nocow=False)


# Formatting


def test_format_uses_simple_quotas_and_never_forces(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    run = FakeRun()
    assert volume.format_image(image, run=run) is False
    assert run.calls == [("mkfs.btrfs", "-O", "squota", "-L", layout.VOLUME_LABEL, str(image))]
    assert all("-f" not in argv and "--force" not in argv for argv in run.calls)


def test_format_falls_back_to_quota_enable_when_mkfs_lacks_squota(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    with_squota = volume.mkfs_argv(image)
    run = FakeRun({with_squota: Ran(1, "", "ERROR: unrecognized filesystem feature 'squota'\n")})
    assert volume.format_image(image, run=run) is True  # quota enable --simple after mounting
    assert run.calls == [with_squota, ("mkfs.btrfs", "-L", layout.VOLUME_LABEL, str(image))]
    mount = Path("/var/lib/backtide-agent")
    assert volume.quota_enable_argv(mount) == ("btrfs", "quota", "enable", "--simple", str(mount))


def test_format_does_not_retry_other_failures(tmp_path: Path) -> None:
    image = tmp_path / "volume.img"
    run = FakeRun(
        {
            volume.mkfs_argv(image): Ran(
                1, "", "ERROR: volume.img appears to contain an existing filesystem (btrfs)\n"
            )
        }
    )
    with pytest.raises(VolumeError, match="existing filesystem"):
        volume.format_image(image, run=run)
    assert len(run.calls) == 1


def test_host_is_btrfs(tmp_path: Path) -> None:
    argv = ("stat", "-f", "-c", "%T", str(tmp_path))
    assert volume.host_is_btrfs(tmp_path, run=FakeRun({argv: Ran(0, "btrfs\n", "")})) is True
    assert volume.host_is_btrfs(tmp_path, run=FakeRun({argv: Ran(0, "ext2/ext3\n", "")})) is False
    with pytest.raises(VolumeError):
        volume.host_is_btrfs(tmp_path, run=FakeRun({argv: Ran(1, "", "nope")}))


# The mount point


def test_prepare_mountpoint_creates_a_private_folder(tmp_path: Path) -> None:
    point = tmp_path / "backtide-agent"
    volume.prepare_mountpoint(point)
    assert stat.S_IMODE(point.stat().st_mode) == 0o700
    volume.prepare_mountpoint(point)  # idempotent


def test_prepare_mountpoint_refuses_an_open_or_odd_folder(tmp_path: Path) -> None:
    point = tmp_path / "open"
    point.mkdir(mode=0o755)
    os.chmod(point, 0o755)  # noqa: S103 - the open folder under test
    with pytest.raises(VolumeError, match="0755"):
        volume.prepare_mountpoint(point)
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(VolumeError):
        volume.prepare_mountpoint(link)
    plain = tmp_path / "file"
    plain.write_text("")
    with pytest.raises(VolumeError):
        volume.prepare_mountpoint(plain)


def test_seal_mounted_root_closes_what_mkfs_left_open(tmp_path: Path) -> None:
    # After the first mount, the point shows the new filesystem's root, which mkfs left 0755.
    root = tmp_path / "mounted"
    root.mkdir()
    os.chmod(root, 0o755)  # noqa: S103 - what mkfs leaves, under test
    argv = volume.findmnt_argv(root)
    volume.seal_mounted_root(root, run=FakeRun({argv: Ran(0, "btrfs  backtide\n", "")}))
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_seal_refuses_a_point_that_is_not_the_mounted_volume(tmp_path: Path) -> None:
    root = tmp_path / "not-mounted"
    root.mkdir()
    os.chmod(root, 0o755)  # noqa: S103 - what mkfs leaves, under test
    argv = volume.findmnt_argv(root)
    for answer in (
        Ran(1, "", ""),  # not a mount point
        Ran(0, "ext4\n", ""),  # another filesystem
        Ran(0, "btrfs  home\n", ""),  # another Btrfs, not backtide's volume
        Ran(0, "btrfs\n", ""),  # a Btrfs without a label
    ):
        with pytest.raises(VolumeError, match="no está montado"):
            volume.seal_mounted_root(root, run=FakeRun({argv: answer}))
    assert stat.S_IMODE(root.stat().st_mode) == 0o755


def test_the_plan_reads_in_order() -> None:
    steps = volume.plan(layout.VOLUME_IMAGE, layout.VOLUME_MOUNT, layout.VOLUME_SIZE, nocow=True)
    text = [step.describe for step in steps]
    assert [step.key for step in steps] == [
        "image",
        "nocow",
        "size",
        "format",
        "mountpoint",
        "mount",
        "seal",
    ]
    assert all(line and "\n" not in line for line in text)
    no_cow = volume.plan(layout.VOLUME_IMAGE, layout.VOLUME_MOUNT, layout.VOLUME_SIZE, nocow=False)
    assert "nocow" not in [step.key for step in no_cow]


def mounted(root: Path) -> FakeRun:
    return FakeRun({volume.findmnt_argv(root): Ran(0, "btrfs  backtide\n", "")})


def test_seal_refuses_a_symlink_at_the_mount_point(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    os.chmod(target, 0o755)  # noqa: S103 - must stay as it is
    link = tmp_path / "point"
    link.symlink_to(target)
    with pytest.raises(VolumeError):
        volume.seal_mounted_root(link, run=mounted(link))
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_seal_refuses_a_root_that_is_not_the_installers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "mounted"
    root.mkdir()
    os.chmod(root, 0o755)  # noqa: S103 - what mkfs leaves, under test
    monkeypatch.setattr(os, "geteuid", lambda: root.stat().st_uid + 1)
    with pytest.raises(VolumeError, match="no es de quien instala"):
        volume.seal_mounted_root(root, run=mounted(root))
    assert stat.S_IMODE(root.stat().st_mode) == 0o755


def test_the_image_folder_must_be_private(tmp_path: Path) -> None:
    folder = tmp_path / "state"
    folder.mkdir()
    os.chmod(folder, 0o777)  # noqa: S103 - anyone could swap the image: refused
    with pytest.raises(VolumeError, match="0777"):
        volume.create_image(folder / "volume.img", 64 * MIB, run=FakeRun(), nocow=False)
    assert not (folder / "volume.img").exists()
