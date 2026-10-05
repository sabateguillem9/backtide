"""Checks that the dev VM has what Vigía needs: Linux, Docker, Btrfs and BTF."""

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_runs_on_linux() -> None:
    assert platform.system() == "Linux"


def test_kernel_exposes_btf_for_ebpf() -> None:
    # Tetragon needs the kernel's BTF type information (T07).
    assert Path("/sys/kernel/btf/vmlinux").exists()


def test_btrfs_is_available() -> None:
    assert shutil.which("btrfs"), "btrfs-progs is not installed"
    assert "btrfs" in Path("/proc/filesystems").read_text()


def test_docker_works_without_sudo() -> None:
    result = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_docker_compose_is_available() -> None:
    result = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
