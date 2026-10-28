"""The distribution, its packages and Docker Engine (docs/25, section 4, step 2; decision 5).

Only what backtide needs and only with permission: ``btrfs-progs`` and ``openssl`` if they are
missing (and ``gnupg``, to check Docker's signing key), and Docker Engine from Docker's own
repository if there is no Docker at all. A Docker that is already there is never touched.

Docker's repository is added the way its documentation says, with one more check: its signing
key is downloaded to a temporary file and used only if its fingerprint is the one Docker
publishes (below). apt then checks every package against that key (``signed-by``) and dnf
against the imported one (``gpgcheck=1``).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from backtide.setup.host import Host

SUPPORTED = {"ubuntu": ("24.04", "26.04"), "fedora": ("43", "44")}
# What backtide has been tried on (docs/44): the rest of SUPPORTED, and x86_64, are accepted and
# said to be untested.
TESTED = {"ubuntu": ("24.04",), "fedora": ("44",)}
TESTED_ARCHITECTURES = ("aarch64",)
APT_ENV = ("env", "DEBIAN_FRONTEND=noninteractive")
# Docker's repository signing keys, as docs.docker.com publishes them (Install Docker Engine on
# Ubuntu / on Fedora). The fingerprint is what decides; the URL only says where to fetch it.
DOCKER_KEYS = {
    "ubuntu": (
        "https://download.docker.com/linux/ubuntu/gpg",
        "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
    ),
    "fedora": (
        "https://download.docker.com/linux/fedora/gpg",
        "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
    ),
}
DOCKER_PACKAGES = ("docker-ce", "docker-ce-cli", "containerd.io")
DPKG_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}


@dataclass(frozen=True)
class Distro:
    id: str
    version: str
    codename: str
    pretty: str

    @property
    def apt(self) -> bool:
        return self.id == "ubuntu"

    @property
    def supported(self) -> bool:
        return self.version in SUPPORTED.get(self.id, ())

    @property
    def tested(self) -> bool:
        return self.version in TESTED.get(self.id, ())


@dataclass(frozen=True)
class Tool:
    """A program backtide needs, how to tell it is there, and its package on each family."""

    name: str
    probe: tuple[str, ...]
    apt: str
    dnf: str


TOOLS = (
    Tool("btrfs-progs", ("mkfs.btrfs", "--version"), "btrfs-progs", "btrfs-progs"),
    Tool("openssl", ("openssl", "version"), "openssl", "openssl"),
    Tool("gnupg", ("gpg", "--version"), "gnupg", "gnupg2"),
    Tool("curl", ("curl", "--version"), "curl", "curl"),
    Tool("iproute2", ("ip", "-V"), "iproute2", "iproute"),
)


# os-release(5): /etc/os-release, else /usr/lib/os-release. On Fedora and Ubuntu the first is a
# symlink to the second, and Host.read never follows one (seen in the clean VMs of T13-3).
OS_RELEASE = ("/etc/os-release", "/usr/lib/os-release")


def read_distro(host: Host) -> Distro | None:
    """The distribution, from os-release, or None if it cannot be read."""
    data = next((found for path in OS_RELEASE if (found := host.read(path))), None)
    if not data:
        return None
    fields: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        name, sep, value = line.partition("=")
        if sep:
            fields[name.strip()] = value.strip().strip('"').strip("'")
    if "ID" not in fields:
        return None
    return Distro(
        id=fields["ID"],
        version=fields.get("VERSION_ID", ""),
        codename=fields.get("VERSION_CODENAME", ""),
        pretty=fields.get("PRETTY_NAME", fields["ID"]),
    )


def missing_tools(host: Host) -> list[Tool]:
    missing = []
    for tool in TOOLS:
        ran = host.run(tool.probe)
        if ran is None or ran.returncode != 0:
            missing.append(tool)
    return missing


def install_argvs(distro: Distro, packages: Sequence[str]) -> list[tuple[str, ...]]:
    """The commands that install ``packages`` with the distribution's own manager."""
    if distro.apt:
        return [
            (*APT_ENV, "apt-get", "update"),
            (*APT_ENV, "apt-get", "install", "-y", "--no-install-recommends", *packages),
        ]
    return [("dnf", "-y", "install", *packages)]


def package_names(distro: Distro, tools: Sequence[Tool]) -> list[str]:
    return [tool.apt if distro.apt else tool.dnf for tool in tools]


def docker_key(distro: Distro) -> tuple[str, str]:
    return DOCKER_KEYS["ubuntu" if distro.apt else "fedora"]


def primary_fingerprints(gpg_colons: str) -> list[str]:
    """One entry per ``pub`` record: the fingerprint on the ``fpr`` line right after it (or ""
    if there is none). Subkeys (``sub``) and their fingerprints are not counted."""
    found: list[str] = []
    after_pub = False
    for line in gpg_colons.splitlines():
        kind = line.split(":", 1)[0]
        if kind == "pub":
            found.append("")
            after_pub = True
        elif kind == "fpr" and after_pub:
            fields = line.split(":")
            found[-1] = fields[9].upper() if len(fields) > 9 else ""
            after_pub = False
        elif kind not in ("fpr", "fp2", "grp"):
            after_pub = False
    return found


def apt_source(distro: Distro, machine: str, keyring: str) -> str:
    arch = DPKG_ARCH.get(machine, machine)
    return (
        "# Docker Engine, added by the backtide installer (docs/25, decision 5)\n"
        f"deb [arch={arch} signed-by={keyring}] https://download.docker.com/linux/ubuntu "
        f"{distro.codename} stable\n"
    )


def dnf_repo(key: Path) -> str:
    """The repository, checked against the key the installer verified (a local file, R2): dnf
    never fetches another one."""
    return (
        "# Docker Engine, added by the backtide installer (docs/25, decision 5)\n"
        "[docker-ce-stable]\n"
        "name=Docker CE Stable - $basearch\n"
        "baseurl=https://download.docker.com/linux/fedora/$releasever/$basearch/stable\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "repo_gpgcheck=0\n"
        f"gpgkey=file://{key}\n"
    )
