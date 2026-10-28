"""The VM gates (invariant 8; review of T13b): which hostnames may run the VM-only tests."""

import pytest

from tests import vm_gates


@pytest.mark.parametrize(
    ("node", "system", "dev", "clean"),
    [
        ("lima-vigia-dev", "linux", True, False),
        ("lima-backtide-prueba-m", "linux", True, True),
        ("lima-backtide-limpia-fedora", "linux", False, True),
        ("lima-backtide", "linux", False, False),
        ("lima-backtide-prueba", "linux", False, False),
        ("lima-backtide-prueba-", "linux", False, False),
        ("lima-backtide-limpia-", "linux", False, False),
        ("lima-vigia-devx", "linux", False, False),
        ("lima-backtide-prueba-m;x", "linux", False, False),
        ("lima-backtide-prueba-m/x", "linux", False, False),
        ("lima-vigia-dev", "darwin", False, False),
        ("lima-backtide-prueba-m", "darwin", False, False),
        ("some-laptop", "linux", False, False),
    ],
)
def test_which_hosts_may_run_vm_tests(node: str, system: str, dev: bool, clean: bool) -> None:
    assert vm_gates.is_dev_vm(node, system) is dev
    assert vm_gates.is_clean_vm(node, system) is clean


def test_only_the_dev_vm_goes_without_the_lab_mark() -> None:
    assert not vm_gates.needs_lab_mark("lima-vigia-dev")
    assert vm_gates.needs_lab_mark("lima-backtide-prueba-m")
    assert vm_gates.needs_lab_mark("lima-backtide-limpia-fedora")
    assert vm_gates.lab_mark_argv(sudo=True) == [
        "sudo", "-n", "nft", "list", "table", "inet", "backtide_lab",
    ]  # fmt: skip


def _load_conftest(folder: str):
    """tests/<folder>/conftest.py as a module of its own (its folder on the path, as pytest
    puts it), to call its gate directly."""
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).parent / folder / "conftest.py"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location(f"gate_test_{folder}_conftest", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


@pytest.fixture
def a_lab_vm_without_its_mark(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Looks like a Mac test VM (Linux, named lima-backtide-prueba-x, root) whose `nft list
    table inet backtide_lab` fails: no lab network cut. Every command asked for is recorded."""
    import os
    import platform
    import subprocess
    import sys

    asked: list[list[str]] = []

    def run(argv, *args, **kwargs):
        asked.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, b"", b"Error: No such file or directory")

    monkeypatch.setattr(platform, "node", lambda: "lima-backtide-prueba-x")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    return asked


def test_the_dev_battery_refuses_a_lab_vm_without_its_mark(
    a_lab_vm_without_its_mark: list[list[str]],
) -> None:
    gate = _load_conftest("integration")._require_dev_vm_user_with_sudo
    with pytest.raises(pytest.fail.Exception, match="no lab network cut"):
        gate()
    assert a_lab_vm_without_its_mark == [vm_gates.lab_mark_argv(sudo=True)]


def test_the_installed_scenarios_refuse_a_lab_vm_without_its_mark(
    a_lab_vm_without_its_mark: list[list[str]],
) -> None:
    gate = _load_conftest("attacks")._require_installed_clean_vm
    with pytest.raises(pytest.fail.Exception, match="no lab network cut"):
        gate()
    assert a_lab_vm_without_its_mark == [vm_gates.lab_mark_argv(sudo=False)]
