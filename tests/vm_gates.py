"""Where the VM-only tests may run (invariant 8): which hostnames, and the lab's mark.

Lima names a guest ``lima-<instance>``. Three kinds of VM of ours run tests:
- ``vigia-dev``, the development VM: `make it` and `make ataques`;
- ``backtide-limpia-<distro>``, the clean Linux VMs of the installer (make vm-limpia-*);
- ``backtide-prueba-<name>``, the Mac installer's test VMs (tests/install/instalar_mac_lab.sh).
The two throwaway kinds must also carry the lab's mark: the ``inet backtide_lab`` table of
tests/install/instalar_lab.sh (`bloquear`), the network cut that keeps the agent's traffic in the
VM. Without it, a VM that is only named like ours is not taken for one.
"""

DEV_VM = "lima-vigia-dev"
CLEAN_VM_PREFIXES = ("lima-backtide-limpia-", "lima-backtide-prueba-")
MAC_TEST_VM_PREFIX = "lima-backtide-prueba-"
LAB_TABLE = ("inet", "backtide_lab")


def _prefixed(node: str, prefix: str) -> bool:
    """``node`` is ``prefix`` plus a non-empty name of letters, digits and dashes."""
    rest = node.removeprefix(prefix)
    return (
        node.startswith(prefix)
        and rest != ""
        and all(c.isascii() and (c.isalnum() or c == "-") for c in rest)
    )


def is_dev_vm(node: str, system: str) -> bool:
    """May the dev battery (and `make it`) run here? vigia-dev, or a Mac test VM."""
    return system == "linux" and (node == DEV_VM or _prefixed(node, MAC_TEST_VM_PREFIX))


def is_clean_vm(node: str, system: str) -> bool:
    """Is this one of the installer's throwaway VMs (by name; the lab mark is checked apart)?"""
    return system == "linux" and any(_prefixed(node, p) for p in CLEAN_VM_PREFIXES)


def needs_lab_mark(node: str) -> bool:
    """The throwaway VMs must show the lab's network cut before anything runs there."""
    return node != DEV_VM


def lab_mark_argv(*, sudo: bool) -> list[str]:
    """The command that succeeds only when the lab's nftables table is there."""
    argv = ["nft", "list", "table", *LAB_TABLE]
    return ["sudo", "-n", *argv] if sudo else argv
