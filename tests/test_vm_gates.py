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
