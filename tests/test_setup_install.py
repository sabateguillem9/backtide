"""`backtide instalar` (docs/25, sections 3 and 4; T13-3), on the Mac with a fake machine.

The fake answers each command the way the real one does (T13-1 and the clean VMs of T13-3) and
remembers what it did: Docker installed or not, SELinux in Docker, the images, the networks, the
volume formatted and mounted, the units started. The files are real, under a temporary folder
(``Paths.under``), and owned by whoever runs the tests (``owner``): only the account and the
group of ``backtide-web`` are made up.
"""

import hashlib
import json
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

import pytest

from backtide.setup import images, layout, manifest, units
from backtide.setup.host import Ran
from backtide.setup.install import Installer, InstallError, Options, Paths
from backtide.setup.preflight import Check, Status

GIB = 1024**3
VOLUME = 64 * 1024**2  # sparse either way; small, so the tests can read it whole
# A key of the right shape that only these tests know: it must never show up in an argv.
KEY = "sk-ant-api03-" + "Tq7xW2mK9pL4vN8rB3cY6hJ1dF5gS0aZ" * 2
WEB_UID = 990
FEDORA = b'ID=fedora\nVERSION_ID=44\nPRETTY_NAME="Fedora Linux 44 (Cloud Edition)"\n'
UBUNTU = (
    b'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\n'
)
DOCKER_FPR = {"fedora": "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
              "ubuntu": "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"}  # fmt: skip


def docker_id(name: str) -> str:
    """The fake Docker's ID for an object: 64 hex characters, from its name."""
    return hashlib.sha256(name.encode()).hexdigest()


SERVICE_CONTAINERS = {"backtide-agente": "agent", "backtide-egress": "proxy",
                      "backtide-sensor": "sensor"}  # fmt: skip
BTF = b"\x9f\xeb\x01\x00" + (24).to_bytes(4, "little") + b"\0" * 80


@dataclass
class Machine:
    """The fake machine: a Host and the runner of its commands."""

    root: Path
    paths: Paths
    distro: bytes = FEDORA
    selinux: bool = True
    docker: bool = False
    docker_selinux: bool = False
    images: set[str] = field(default_factory=set)
    networks: dict[str, str] = field(default_factory=dict)
    formatted: bool = False
    mounted: bool = False
    active: set[str] = field(default_factory=set)
    users: dict[str, int] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    fail: dict[tuple[str, ...], int] = field(default_factory=dict)  # argv prefix: times to fail
    routes: list[dict] = field(default_factory=list)
    extra_keys: list[str] = field(default_factory=list)  # more keys in Docker's download
    # Docker's containers and networks, by name: their labels (the service makes the three).
    containers: dict[str, dict[str, str]] = field(default_factory=dict)
    network_labels: dict[str, dict[str, str]] = field(default_factory=dict)
    busy_networks: set[str] = field(default_factory=set)  # with someone else's container on
    channel_mounted: bool = False
    groups: set[str] = field(default_factory=set)
    usergroups: bool = True  # userdel takes the user's own group with it
    primary_gid: dict[str, int] = field(default_factory=dict)  # an account's other primary group
    groupdels: list[tuple[str, list[str]]] = field(default_factory=list)
    extra_mounts: list[Path] = field(default_factory=list)  # someone else's, the tests' witnesses
    mountinfo_readable: bool = True

    def passwd_line(self, name: str) -> str:
        uid = self.users[name]
        gid = self.primary_gid.get(name, uid)
        shell = "/usr/sbin/nologin" if name != "alguien" else "/bin/bash"
        home = "/nonexistent" if name != "alguien" else "/home/alguien"
        return f"{name}:x:{uid}:{gid}::{home}:{shell}\n"

    # Host

    def euid(self) -> int:
        return 0

    def machine(self) -> str:
        return "aarch64"

    def release(self) -> str:
        return "6.19.10-300.fc44.aarch64"

    def read(self, path: str, limit: int = 65536) -> bytes | None:
        files = {
            "/etc/os-release": self.distro,
            "/proc/filesystems": b"nodev\ttmpfs\n\tbtrfs\n",
            "/sys/kernel/btf/vmlinux": BTF,
        }
        mounts = [self.paths.volume_mount] if self.mounted else []
        mounts += [self.paths.channel_dir] if self.channel_mounted else []
        mounts += self.extra_mounts
        files["/proc/self/mountinfo" if self.mountinfo_readable else "-"] = "".join(
            f"36 25 0:32 / {str(m).replace(' ', chr(92) + '040')} rw,noatime - x y rw\n"
            for m in mounts
        ).encode()
        if self.selinux:
            files["/sys/fs/selinux/enforce"] = b"1"
        else:
            files["/sys/module/apparmor/parameters/enabled"] = b"Y\n"
        data = files.get(path)
        return None if data is None else data[:limit]

    def exists(self, path: str) -> bool:
        return path in {
            "/dev/loop-control",
            "/sys/fs/cgroup/cgroup.controllers",
            "/run/systemd/system",
            "/usr/sbin/nologin",
            *(() if self.mountinfo_readable else ("/proc/self",)),
        }

    def free_bytes(self, path: str) -> int | None:
        return 100 * GIB

    def uid_taken(self, uid: int) -> bool:
        return False

    def gid_taken(self, gid: int) -> bool:
        return False

    def clock_synced(self) -> bool | None:
        return True

    # Commands

    def run(self, argv: Sequence[str]) -> Ran | None:
        argv = tuple(argv)
        self.calls.append(argv)
        for prefix, times in list(self.fail.items()):
            if argv[: len(prefix)] == prefix and times > 0:
                self.fail[prefix] = times - 1
                return Ran(1, "", "made to fail by the test")
        return self._answer(argv)

    def _answer(self, argv: tuple[str, ...]) -> Ran | None:  # noqa: PLR0911, PLR0912
        ok = Ran(0, "", "")
        match argv:
            case ("docker", "--version"):
                return Ran(0, "Docker version 29.9.2\n", "") if self.docker else None
            case ("docker", "info", *_):
                if not self.docker:
                    return None
                options = ["name=seccomp,profile=builtin", "name=cgroupns"]
                options += ["name=selinux"] if self.docker_selinux else []
                options += [] if self.selinux else ["name=apparmor"]
                info = {"ServerVersion": "29.9.2", "OperatingSystem": "Linux",
                        "SecurityOptions": options}  # fmt: skip
                return Ran(0, json.dumps(info), "")
            case ("docker", "image", "inspect", _, _, ref):
                if ref not in self.images:
                    return Ran(1, "", "No such image")
                image = next(i for i in images.every() if i.ref == ref)
                return Ran(0, json.dumps([f"{image.repo}@{image.digest}"]), "")
            case ("docker", "pull", "--quiet", ref):
                self.images.add(ref)
                return Ran(0, ref + "\n", "")
            case ("docker", "network", "ls", *_):
                return Ran(0, "\n".join(self.networks), "")
            case ("docker", "network", "inspect", "--format", "{{.Id}} {{json .Labels}}", name):
                if name not in self.networks:
                    return Ran(1, "", f"Error response from daemon: network {name} not found")
                return Ran(
                    0, f"{docker_id(name)} {json.dumps(self.network_labels.get(name, {}))}", ""
                )
            case ("docker", "network", "inspect", "--format", _, *names):
                lines = [json.dumps([{"Subnet": self.networks[n]}]) for n in names
                         if n in self.networks]  # fmt: skip
                return Ran(0, "\n".join(lines), "") if lines else Ran(1, "", "not found")
            case ("docker", "network", "create", *rest):
                subnet = rest[rest.index("--subnet") + 1]
                self.networks[rest[-1]] = subnet
                if "--label" in rest:
                    key, _, value = rest[rest.index("--label") + 1].partition("=")
                    self.network_labels[rest[-1]] = {key: value}
                return ok
            case ("docker", "network", "rm", object_id):
                name = next((n for n in self.networks if docker_id(n) == object_id), object_id)
                if name in self.busy_networks:
                    return Ran(1, "", f"Error response from daemon: error while removing network: "
                                      f"network {name} has active endpoints")  # fmt: skip
                self.networks.pop(name, None)
                self.network_labels.pop(name, None)
                return ok
            case ("docker", "container", "inspect", "--format", _, name):
                if name not in self.containers:
                    return Ran(1, "", f"Error response from daemon: No such container: {name}")
                return Ran(0, f"{docker_id(name)} {json.dumps(self.containers[name] or None)}", "")
            case ("docker", "rm", "--force", object_id):
                name = next((n for n in self.containers if docker_id(n) == object_id), object_id)
                if self.containers.pop(name, None) is None:
                    return Ran(1, "", f"Error response from daemon: No such container: {name}")
                return ok
            case ("docker", "ps", "--all", "--quiet"):
                return Ran(0, "".join(f"{n}\n" for n in self.containers), "")
            case ("docker", "image", "rm", ref):
                if ref in self.images:
                    self.images.discard(ref)
                    return Ran(0, f"Untagged: {ref}\n", "")
                return Ran(1, "", f"Error response from daemon: No such image: {ref}")
            case ("getent", "passwd"):
                return Ran(0, "".join(self.passwd_line(n) for n in self.users), "")
            case ("getent", "passwd", name):
                if name not in self.users:
                    return Ran(2, "", "")
                return Ran(0, self.passwd_line(name), "")
            case ("getent", "group", name):
                return Ran(0, f"{name}:x:990:\n", "") if name in self.groups else Ran(2, "", "")
            case ("userdel", name):
                self.users.pop(name, None)
                if self.usergroups:  # USERGROUPS_ENAB: the user's own group goes with it
                    self.groups.discard(name)
                return ok
            case ("groupdel", name):
                # What the group held at that moment, for the tests (review of T13-4, G6).
                holders = [u for u in self.users if self.primary_gid.get(u, self.users[u]) == 990]
                self.groupdels.append((name, holders))
                self.groups.discard(name)
                return ok
            case ("ip", *_):
                return Ran(0, json.dumps(self.routes) if "route" in argv else "[]", "")
            case ("useradd", *_, name):
                self.users[name] = WEB_UID
                self.groups.add(name)
                return ok
            case ("stat", "-f", "-c", "%T", _):
                return Ran(0, "btrfs\n" if self.distro == FEDORA else "ext4\n", "")
            case ("chattr", "+C", _):
                return ok
            case ("blkid", "-p", "-o", "export", _):
                if self.formatted:
                    return Ran(0, "TYPE=btrfs\nLABEL=backtide\n", "")
                return Ran(2, "", "")
            case ("mkfs.btrfs", "--version"):
                return Ran(0, "mkfs.btrfs, part of btrfs-progs v6.19.1\n", "")
            case ("mkfs.btrfs", *_):
                self.formatted = True
                return ok
            case ("findmnt", "-n", "-o", "FSTYPE,LABEL", "--mountpoint", _):
                return Ran(0, "btrfs backtide\n", "") if self.mounted else Ran(1, "", "")
            case ("systemctl", "enable", "--now", "docker.service"):
                return ok
            case ("systemctl", "enable", "--now", *names):
                if units.volume_unit_name() in names:
                    self.mounted = True
                    self.paths.volume_mount.chmod(0o755)  # mkfs leaves the new root 0755
                self.channel_mounted |= units.channel_unit_name() in names
                self.active.update(names)
                return ok
            case ("systemctl", "disable", "--now", *names):
                self.mounted &= units.volume_unit_name() not in names
                self.channel_mounted &= units.channel_unit_name() not in names
                self.active.difference_update(names)
                return ok
            case ("systemctl", "stop", *names):
                self.active.difference_update(names)
                return ok
            case ("systemctl", "is-active", "--quiet", name):
                return ok if name in self.active else Ran(3, "", "")
            case ("systemctl", "start" | "restart", name):
                self.active.add(name)
                if name == layout.SERVICE_UNIT:  # the service makes its three containers
                    for container, role in SERVICE_CONTAINERS.items():
                        self.containers.setdefault(container, {"backtide.role": role})
                return ok
            case ("systemctl", "restart", "docker.service"):
                return ok
            case ("systemctl", "reload", "docker.service"):
                return ok
            case ("systemctl", *_):
                return ok
            case ("curl", *_, "-o", path, _url):
                Path(path).write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
                return ok
            case ("gpg", *_, "--export", fingerprint):
                return Ran(0, f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nonly {fingerprint}\n", "")
            case ("gpg", *_, "--show-keys", "--with-colons", path):
                family = "fedora" if self.distro == FEDORA else "ubuntu"
                keys = [DOCKER_FPR[family], *self.extra_keys]
                if Path(path).name == "verified.asc":
                    keys = [DOCKER_FPR[family]]  # only the exported one
                return Ran(0, "".join(f"pub:-:4096:1:X:1:::-:::scESC::::::23::0:\n"
                                      f"fpr:::::::::{key}:\n" for key in keys), "")  # fmt: skip
            case ("gpg", *_):
                return ok
            case ("rpm", "--import", _):
                return ok
            case ("rpm", "-q", "--quiet", name):  # dnf brought this weak dependency, not the rest
                return ok if self.docker and name == "docker-buildx-plugin" else Ran(1, "", "")
            case ("dnf", "-y", "install", *packages) | ("env", _, "apt-get", "install", *packages):
                if "docker-ce" in packages:
                    self.docker = True
                return ok
            case ("dnf", "-y", "remove", *packages) | (
                "env",
                _,
                "apt-get",
                "purge",
                "-y",
                *packages,
            ):
                if "docker-ce" in packages:
                    self.docker = False
                return ok
            case ("env", _, "apt-get", "update"):
                return ok
        return ok

    def docker_restarted(self) -> None:
        """What `systemctl restart docker` does with daemon.json."""
        settings = json.loads(self.paths.daemon_json.read_text())
        self.docker_selinux = settings.get("selinux-enabled") is True


class FakeAccounts:
    def __init__(self, machine: Machine) -> None:
        self.machine = machine

    def user_id(self, name: str) -> int | None:
        return self.machine.users.get(name)

    def group_id(self, name: str) -> int | None:
        # The tests' own group stands for backtide-web's: then fchown can be real.
        return os.getgid() if name in self.machine.users else None

    def fchown(self, fd: int, uid: int, gid: int) -> None:
        os.fchown(fd, uid, gid)


class Prompter:
    def __init__(
        self,
        *,
        interactive: bool = False,
        answers: bool = True,
        key: str = "",
        token: str = "",
        chat: str = "",
    ) -> None:
        self.interactive = interactive
        self.answers = answers
        self.key = key
        self.token = token  # what is typed at the Telegram token's prompt
        self.chat = chat
        self.said: list[str] = []
        self.asked: list[str] = []

    def say(self, text: str) -> None:
        self.said.append(text)

    def confirm(self, question: str) -> bool:
        self.asked.append(question)
        return self.answers

    def secret(self, prompt: str) -> str:
        self.asked.append(prompt)
        return self.token if "Telegram" in prompt else self.key

    def answer(self, question: str) -> str:
        self.asked.append(question)
        return self.chat


def new_machine(root: Path) -> Machine:
    """The folders a fresh Fedora or Ubuntu already has, and the program install.sh left."""
    paths = Paths().under(root)
    paths.program.parent.mkdir(parents=True)
    paths.program.write_text("#!/bin/sh\n")
    for folder in ("var/lib", "etc/systemd/system", "etc/yum.repos.d", "etc/apt/sources.list.d",
                   "usr/local/bin", "etc/pki/rpm-gpg"):  # fmt: skip
        (root / folder).mkdir(parents=True, exist_ok=True)
    return Machine(root, paths)


@pytest.fixture(autouse=True)
def _keys_read_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import backtide.service.config as config

    monkeypatch.setattr(config, "KEY_SETTLE_S", 0.0)


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    return new_machine(tmp_path / "machine")


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    path = tmp_path / "anthropic-key.txt"
    path.write_text(KEY + "\n")
    return path


def installer(machine: Machine, prompter: Prompter | None = None, **options) -> Installer:
    tested: list[str] = []

    def run(argv: Sequence[str]) -> Ran | None:
        ran = machine.run(argv)
        if tuple(argv) == ("systemctl", "restart", "docker.service") and ran.returncode == 0:
            machine.docker_restarted()
        return ran

    built = Installer(
        host=machine,
        run=run,
        run_long=run,
        prompter=prompter or Prompter(),
        options=Options(**{"yes": True, "volume_size": VOLUME, **options}),
        paths=machine.paths,
        accounts=FakeAccounts(machine),
        owner=(os.getuid(), os.getgid()),
        self_test=lambda config: (
            tested.append(str(config.state_dir)) or [Check("agent", Status.OK, "probado")]
        ),
        sleep=lambda seconds: None,
    )
    built.tested = tested  # type: ignore[attr-defined]
    return built


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def snapshot(root: Path) -> dict[str, tuple]:
    """Every file and folder under ``root``: kind, mode, size, modification time and content.
    A folder's time is left out: rewriting the manifest renames a file in the state folder."""
    found = {}
    for folder, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            path = Path(folder, name)
            info = os.lstat(path)
            found[str(path.relative_to(root))] = (
                stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_size,
                None if stat.S_ISDIR(info.st_mode) else info.st_mtime_ns,
                path.read_bytes() if path.is_file() and not path.is_symlink()
                else None,
            )  # fmt: skip
    return found


CHANGING = ("useradd", "mkfs.btrfs", "dnf", "env", "rpm", "curl", "chattr")


def changes(calls: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    """The commands that change the machine (not the ones that only look)."""
    found = []
    for argv in calls:
        if "--version" in argv:
            continue
        if argv[0] in CHANGING or argv[:3] in (("docker", "network", "create"),):
            found.append(argv)
        elif argv[:2] == ("docker", "pull"):
            found.append(argv)
        elif argv[0] == "systemctl" and argv[1] in ("daemon-reload", "restart", "start", "reload"):
            found.append(argv)
    return found


# A whole install


def test_a_clean_fedora_ends_installed_and_tested(machine: Machine, key_file: Path) -> None:
    run = installer(machine, key_file=key_file)
    warnings = run.install()
    paths = machine.paths
    assert run.tested == [str(paths.state_dir)]  # type: ignore[attr-defined]
    assert len(warnings) == 1 and "7.1" in warnings[0]  # the kernel of a fresh Fedora 44
    # The layout and its permissions (docs/25, section 3; D25)
    assert mode(paths.state_dir) == 0o710
    assert mode(paths.keys_dir) == 0o700
    assert mode(paths.config_file) == 0o600
    assert mode(paths.web_config_file) == 0o640
    assert mode(paths.gateway_token) == 0o600
    assert mode(paths.blackbox_db) == 0o640
    # The service refuses a black box without its key: the installer makes it first (0600)
    assert len((paths.state_dir / "blackbox.key").read_bytes()) == 32
    assert mode(paths.state_dir / "blackbox.key") == 0o600
    assert mode(paths.volume_image) == 0o600
    assert os.path.getsize(paths.volume_image) == VOLUME
    assert f"workspace_limit = {VOLUME // 20}" in paths.config_file.read_text()
    assert mode(paths.volume_mount) == 0o700  # sealed after mounting (T13-1)
    assert (paths.keys_dir / "anthropic.key").read_text() == KEY + "\n"
    assert mode(paths.keys_dir / "anthropic.key") == 0o600
    assert os.readlink(paths.bin_link) == str(paths.program)
    assert sorted(p.name for p in paths.unit_dir.iterdir()) == sorted(units.render_units())
    # Docker, from Docker's repository after checking its key, and SELinux on in it (D25)
    assert machine.docker and machine.docker_selinux
    assert json.loads(paths.daemon_json.read_text()) == {
        "live-restore": True,
        "selinux-enabled": True,
    }
    reload = machine.calls.index(("systemctl", "reload", "docker.service"))
    restart = machine.calls.index(("systemctl", "restart", "docker.service"))
    assert reload < restart  # live-restore first: the restart keeps containers alive
    assert set(machine.images) == {image.ref for image in images.pinned()}
    # Both networks with a subnet of their own, from the top of the pool
    assert machine.networks == {
        "backtide-agente-net": "172.29.255.0/24",
        "backtide-salida-net": "172.29.254.0/24",
    }
    assert machine.active >= {layout.SERVICE_UNIT, layout.WEB_UNIT, units.volume_unit_name()}


def test_the_manifest_lists_everything_it_made(machine: Machine, key_file: Path) -> None:
    installer(machine, key_file=key_file).install()
    paths = machine.paths
    record = manifest.load(paths.manifest)
    assert mode(paths.manifest) == 0o600
    # Every step once it is done (the preflight comes before there is a manifest to write)
    assert [step.key for step in installer(machine).steps()][1:] == record.steps
    files = set(record.created["files"])
    for path in (
        paths.config_file, paths.web_config_file, paths.gateway_token, paths.blackbox_db,
        paths.volume_image, paths.keys_dir / "anthropic.key", paths.bin_link, paths.dnf_repo,
        paths.daemon_json,
    ):  # fmt: skip
        assert str(path) in files, path
    assert set(record.created["dirs"]) >= {str(paths.state_dir), str(paths.volume_mount)}
    assert record.created["users"] == [layout.WEB_USER]
    assert set(record.created["units"]) == set(units.render_units())
    assert set(record.created["networks"]) == {"backtide-agente-net", "backtide-salida-net"}
    assert record.created["docker"] == ["docker-ce"]
    assert record.facts["subnets"] == machine.networks
    assert record.facts["daemon_json"] == ["live-restore", "selinux-enabled"]


def test_a_second_run_changes_nothing(machine: Machine, key_file: Path) -> None:
    installer(machine, key_file=key_file).install()
    before = snapshot(machine.root)
    before.pop("var/lib/backtide/install-manifest.json")
    machine.calls.clear()
    installer(machine, key_file=key_file).install()
    after = snapshot(machine.root)
    after.pop("var/lib/backtide/install-manifest.json")
    assert after == before
    assert changes(machine.calls) == []


def test_the_second_run_finds_the_same_manifest(machine: Machine, key_file: Path) -> None:
    installer(machine, key_file=key_file).install()
    first = machine.paths.manifest.read_text()
    installer(machine, key_file=key_file).install()
    assert machine.paths.manifest.read_text() == first


@pytest.mark.parametrize(
    "broken",
    [
        ("useradd",),
        ("dnf", "-y", "install"),
        ("systemctl", "reload", "docker.service"),  # I1: after live-restore was written
        ("docker", "pull"),
        ("mkfs.btrfs", "-O"),
        ("docker", "network", "create"),
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", "--now"),
        ("systemctl", "restart", "backtide.service"),
    ],
)
def test_an_install_cut_at_any_step_goes_on_from_there(
    tmp_path: Path, machine: Machine, key_file: Path, broken: tuple[str, ...]
) -> None:
    """Interrupted (a command fails once), then run again: the end is the same as a clean run's."""
    machine.fail[broken] = images.PULL_ATTEMPTS if broken[:2] == ("docker", "pull") else 1
    with pytest.raises(InstallError):
        installer(machine, key_file=key_file).install()
    installer(machine, key_file=key_file).install()
    clean = new_machine(tmp_path / "cleaned")  # as long a name: the same sizes
    installer(clean, key_file=key_file).install()

    def shape(root: Path) -> dict[str, tuple]:
        found = {k: v[:3] for k, v in snapshot(root).items()}
        found.pop("var/lib/backtide/install-manifest.json")  # the same sets, maybe in another order
        return found

    assert shape(machine.root) == shape(clean.root)
    for kind, items in manifest.load(clean.paths.manifest).created.items():
        assert sorted(manifest.load(machine.paths.manifest).created[kind]) == sorted(
            item.replace("cleaned", "machine") for item in items
        ), kind
    assert machine.networks == clean.networks and machine.images == clean.images
    assert manifest.load(machine.paths.manifest).steps == manifest.load(clean.paths.manifest).steps


def test_a_config_written_before_a_bad_key_is_still_backtides(
    machine: Machine, key_file: Path, tmp_path: Path
) -> None:
    """I2 of the code review: the config is recorded as soon as it is written, so a run that
    stops at a key of the wrong shape does not leave it looking like the person's."""
    bad = tmp_path / "bad.txt"
    bad.write_text("not a key\n")
    with pytest.raises(InstallError):
        installer(machine, key_file=bad).install()
    assert str(machine.paths.config_file) in manifest.load(machine.paths.manifest).created["files"]
    installer(machine, key_file=key_file).install()
    assert str(machine.paths.config_file) in manifest.load(machine.paths.manifest).created["files"]


def test_a_cut_between_mounting_and_sealing_seals_without_preparing_again(
    machine: Machine, key_file: Path
) -> None:
    """T13-2 left this: the volume is mounted (its new root 0755) and the run stops before
    the seal. The next run must not call prepare_mountpoint, which refuses a 0755 folder."""
    first = installer(machine, key_file=key_file)
    for step in first.steps():
        if step.key == "mounts":
            machine.run(("systemctl", "enable", "--now", units.volume_unit_name()))
            break
        step.action()
        if first._manifest_ready:
            first.manifest.done(step.key)
            first._save()
    assert machine.mounted and mode(machine.paths.volume_mount) == 0o755
    installer(machine, key_file=key_file).install()
    assert mode(machine.paths.volume_mount) == 0o700


# What it never does


def test_nothing_changes_without_permission(machine: Machine) -> None:
    prompter = Prompter(interactive=False)
    with pytest.raises(InstallError, match="permiso"):
        installer(machine, prompter, yes=False, no_key=True).install()
    assert not machine.docker
    assert not any(argv[0] in ("dnf", "env", "rpm") for argv in machine.calls)


def test_a_no_stops_before_installing_docker(machine: Machine) -> None:
    prompter = Prompter(interactive=True, answers=False)
    with pytest.raises(InstallError, match="no se ha dado permiso"):
        installer(machine, prompter, yes=False, no_key=True).install()
    assert "Docker no está instalado" in prompter.asked[0]
    assert not machine.docker


def test_selinux_in_an_existing_docker_is_asked_for(machine: Machine) -> None:
    machine.docker = True
    prompter = Prompter(interactive=True, answers=False)
    with pytest.raises(InstallError, match="no se ha dado permiso"):
        installer(machine, prompter, yes=False, no_key=True).install()
    assert "SELinux" in prompter.asked[-1] and "live-restore" in prompter.asked[-1]
    assert not machine.paths.daemon_json.exists()  # nothing touched before the yes


def test_an_existing_daemon_json_keeps_its_settings_and_a_copy(machine: Machine) -> None:
    machine.docker = True
    machine.paths.daemon_json.parent.mkdir(parents=True)
    machine.paths.daemon_json.write_text('{"log-driver": "journald"}\n')
    installer(machine, no_key=True).install()
    assert json.loads(machine.paths.daemon_json.read_text()) == {
        "log-driver": "journald",
        "live-restore": True,
        "selinux-enabled": True,
    }
    backup = machine.paths.state_dir / "docker-daemon.json.antes"
    assert backup.read_text() == '{"log-driver": "journald"}\n'
    record = manifest.load(machine.paths.manifest)
    assert str(machine.paths.daemon_json) not in record.created["files"]  # not ours to remove


def test_a_docker_that_uses_selinux_is_not_touched(machine: Machine) -> None:
    machine.docker = machine.docker_selinux = True
    installer(machine, no_key=True).install()
    assert not machine.paths.daemon_json.exists()
    assert ("systemctl", "restart", "docker.service") not in machine.calls
    assert manifest.load(machine.paths.manifest).created["docker"] == []


def test_ubuntu_gets_docker_from_its_signed_apt_repository(machine: Machine) -> None:
    machine.distro, machine.selinux = UBUNTU, False
    installer(machine, no_key=True).install()
    source = machine.paths.apt_source.read_text()
    assert f"signed-by={machine.paths.apt_keyring}" in source
    assert "arch=arm64" in source and " noble stable" in source
    assert machine.paths.apt_keyring.exists()
    assert not machine.paths.daemon_json.exists()  # AppArmor: nothing to change in Docker


def test_a_key_that_is_not_dockers_stops_the_install(machine: Machine) -> None:
    DOCKER_FPR["fedora"], real = "0" * 40, DOCKER_FPR["fedora"]
    try:
        with pytest.raises(InstallError, match="no es solo la de Docker"):
            installer(machine, no_key=True).install()
    finally:
        DOCKER_FPR["fedora"] = real
    assert not machine.docker
    assert not (machine.paths.state_dir / "docker-key.tmp").exists()


def test_an_existing_image_with_another_filesystem_is_never_formatted(
    machine: Machine, key_file: Path
) -> None:
    machine.paths.state_dir.mkdir(mode=0o700)
    machine.paths.volume_image.write_bytes(b"the history of the agent")

    def other(argv: Sequence[str]) -> Ran | None:
        if argv[0] == "blkid":
            return Ran(0, "TYPE=ext4\nLABEL=data\n", "")
        return Machine._answer(machine, tuple(argv))

    machine._answer = other  # type: ignore[method-assign]
    with pytest.raises(InstallError, match="otro sistema de archivos"):
        installer(machine, key_file=key_file).install()
    assert machine.paths.volume_image.read_bytes() == b"the history of the agent"
    assert not any(argv[0] == "mkfs.btrfs" and "-O" in argv for argv in machine.calls)


def test_an_existing_config_is_kept_as_it_is(machine: Machine, key_file: Path) -> None:
    installer(machine, key_file=key_file).install()
    config = machine.paths.config_file
    config.write_text("cycle_interval = 60\n" + config.read_text())
    installer(machine, key_file=key_file).install()
    assert config.read_text().startswith("cycle_interval = 60\n")


def test_an_unsupported_distribution_stops_before_any_change(machine: Machine) -> None:
    machine.distro = b"ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n"
    with pytest.raises(InstallError, match="Debian 13"):
        installer(machine, no_key=True).install()
    assert not machine.paths.state_dir.exists()
    assert changes(machine.calls) == []


def test_a_failed_preflight_stops_before_any_change(machine: Machine) -> None:
    machine.free_bytes = lambda path: 1 * GIB  # type: ignore[method-assign]
    with pytest.raises(InstallError, match="no sirve"):
        installer(machine, no_key=True).install()
    assert not machine.paths.state_dir.exists()


def test_dry_run_changes_nothing(machine: Machine, key_file: Path) -> None:
    prompter = Prompter()
    installer(machine, prompter, key_file=key_file, dry_run=True).install()
    assert not machine.paths.state_dir.exists()
    assert changes(machine.calls) == []
    text = "\n".join(prompter.said)
    assert "--dry-run" in text and "mkfs.btrfs -O squota" in text
    assert all(image.ref in text for image in images.pinned())


def test_a_failed_self_test_is_a_failed_install(machine: Machine) -> None:
    run = installer(machine, no_key=True)
    run.self_test = lambda config: [Check("egress", Status.FAIL, "sale sin el proxy")]
    with pytest.raises(InstallError, match="autoprueba"):
        run.install()


# Networks


def test_a_vpn_route_moves_the_subnets_down(machine: Machine) -> None:
    machine.routes = [{"dst": "172.29.254.0/23", "dev": "tun0"}]
    installer(machine, no_key=True).install()
    assert machine.networks == {
        "backtide-agente-net": "172.29.253.0/24",
        "backtide-salida-net": "172.29.252.0/24",
    }


def test_the_subnets_can_be_chosen(machine: Machine) -> None:
    installer(machine, no_key=True, subnets="10.77.1.0/24,10.77.2.0/24").install()
    assert machine.networks == {
        "backtide-agente-net": "10.77.1.0/24",
        "backtide-salida-net": "10.77.2.0/24",
    }


def test_existing_networks_are_left_as_they_are(machine: Machine) -> None:
    machine.networks = {"backtide-agente-net": "172.20.0.0/16"}
    installer(machine, no_key=True).install()
    assert machine.networks == {
        "backtide-agente-net": "172.20.0.0/16",
        "backtide-salida-net": "172.29.255.0/24",
    }


def test_the_network_argv_is_the_jails_own_with_a_subnet(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    created = [argv for argv in machine.calls if argv[:3] == ("docker", "network", "create")]
    assert created[0][-1] == "backtide-agente-net"
    assert "--internal" in created[0]
    assert "com.docker.network.bridge.gateway_mode_ipv4=isolated" in created[0]
    assert "--internal" not in created[1]  # the egress one: out through the host, NAT
    from backtide.jail.proxy_config import EGRESS_LABEL

    assert created[1][-1] == "backtide-salida-net" and EGRESS_LABEL in created[1]
    assert created[0][-3:-1] == ("--subnet", "172.29.255.0/24")


# Keys: never in an argument, never in a message


def test_the_key_never_reaches_an_argument_or_a_message(machine: Machine, key_file: Path) -> None:
    prompter = Prompter()
    installer(machine, prompter, key_file=key_file).install()
    assert not any(KEY in arg for argv in machine.calls for arg in argv)
    assert not any(KEY in line for line in prompter.said)
    assert KEY not in manifest.load(machine.paths.manifest).to_json()
    assert KEY not in machine.paths.config_file.read_text()


def test_the_key_from_stdin(machine: Machine) -> None:
    import io

    run = installer(machine, key_stdin=True)
    run.stdin = io.BytesIO(KEY.encode() + b"\n")
    run.install()
    assert (machine.paths.keys_dir / "anthropic.key").read_text() == KEY + "\n"


def test_the_key_asked_at_the_terminal_without_echo(machine: Machine) -> None:
    prompter = Prompter(interactive=True, key=KEY)
    installer(machine, prompter, yes=False).install()
    assert any("no se ve al escribirla" in question for question in prompter.asked)
    assert (machine.paths.keys_dir / "anthropic.key").read_text() == KEY + "\n"


def test_an_empty_answer_leaves_the_key_for_the_settings_page(machine: Machine) -> None:
    prompter = Prompter(interactive=True, key="")
    installer(machine, prompter, yes=False).install()
    assert not (machine.paths.keys_dir / "anthropic.key").exists()
    assert any("Ajustes" in line for line in prompter.said)


def test_a_key_of_the_wrong_shape_is_refused_without_saying_it(
    machine: Machine, tmp_path: Path
) -> None:
    wrong = tmp_path / "wrong.txt"
    wrong.write_text("sk-test-not-an-anthropic-key-0123456789\n")
    with pytest.raises(InstallError) as caught:
        installer(machine, key_file=wrong).install()
    assert "no parece una clave" in str(caught.value)
    assert "sk-test" not in str(caught.value)
    assert not (machine.paths.keys_dir / "anthropic.key").exists()


def test_a_new_key_replaces_the_old_one(machine: Machine, key_file: Path, tmp_path: Path) -> None:
    installer(machine, key_file=key_file).install()
    newer = tmp_path / "newer.txt"
    newer.write_text(KEY[:-4] + "ZZZZ\n")
    prompter = Prompter()
    installer(machine, prompter, key_file=newer).install()
    assert (machine.paths.keys_dir / "anthropic.key").read_text() == KEY[:-4] + "ZZZZ\n"
    assert "Clave de anthropic: cambiada." in prompter.said


def test_the_web_reads_its_own_config_and_never_the_services(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    web = machine.paths.web_config_file.read_text()
    assert f'state_dir = "{machine.paths.state_dir}"' in web
    assert "providers" not in web and "token" not in web
    config = machine.paths.config_file.read_text()
    for word in ("api_key", "sk-", "secret", "password"):
        assert word not in config
    assert 'name = "anthropic"' in config and "claude-haiku-4-5" in config


def test_the_paths_under_a_root_keep_the_real_tree(tmp_path: Path) -> None:
    moved = Paths().under(tmp_path)
    assert moved.state_dir == tmp_path / "var/lib/backtide"
    assert moved.unit_dir == tmp_path / "etc/systemd/system"
    assert Paths().state_dir == layout.STATE_DIR


def test_a_black_box_without_its_key_is_never_given_a_new_one(machine: Machine) -> None:
    """runner.open_black_box's rule, before the service even starts: a chain that exists without
    its key stays as it is, and the install stops saying why."""
    machine.paths.state_dir.mkdir(mode=0o700)
    machine.paths.blackbox_db.write_bytes(b"SQLite format 3\0 the old chain")
    with pytest.raises(InstallError, match="sin su clave"):
        installer(machine, no_key=True).install()
    assert not (machine.paths.state_dir / "blackbox.key").exists()
    assert machine.paths.blackbox_db.read_bytes() == b"SQLite format 3\0 the old chain"


def test_its_own_empty_black_box_of_a_cut_run_gets_its_key(machine: Machine) -> None:
    """A run cut after making the empty file (an older installer made it before the key): the
    file is the installer's own, empty and in the manifest, so the key can be made now."""
    run = installer(machine, no_key=True)
    for step in run.steps():
        if step.key == "config":
            break
        step.action()
    machine.paths.blackbox_db.touch(mode=0o600)
    run.manifest.add("files", machine.paths.blackbox_db)
    run._save()
    installer(machine, no_key=True).install()
    assert (machine.paths.state_dir / "blackbox.key").exists()


def test_another_release_makes_the_containers_again(machine: Machine, tmp_path: Path) -> None:
    """install.sh with another archive moves /opt/backtide/current: the proxy the service made
    mounts the old release's code and backtide refuses it (seen in Fedora 44, T13-3). The
    installer stops the service and removes the three containers; the service makes them again."""
    first = installer(machine, no_key=True)
    first.release = tmp_path / "releases/0.1.0-aaaaaaaaaaaa"
    first.install()
    machine.calls.clear()
    again = installer(machine, no_key=True)
    again.release = first.release
    again.install()
    assert not any(argv[:2] == ("docker", "rm") for argv in machine.calls)  # the same: nothing
    newer = installer(machine, no_key=True)
    newer.release = tmp_path / "releases/0.1.0-bbbbbbbbbbbb"
    newer.install()
    removed = [argv[-1] for argv in machine.calls if argv[:2] == ("docker", "rm")]
    names = ["backtide-agente", "backtide-egress", "backtide-sensor"]
    assert removed == [docker_id(name) for name in names]  # by the ID that was checked (R7)
    stop = machine.calls.index(("systemctl", "stop", layout.SERVICE_UNIT))
    first_rm = machine.calls.index(("docker", "rm", "--force", docker_id("backtide-agente")))
    assert stop < first_rm < machine.calls.index(("systemctl", "restart", layout.SERVICE_UNIT))
    assert manifest.load(machine.paths.manifest).facts["release_started"] == str(newer.release)


@pytest.mark.parametrize("distro", [FEDORA, UBUNTU])
def test_a_download_with_a_second_key_is_never_used(machine: Machine, distro: bytes) -> None:
    """Review of T13-3, R2: Docker's key AND another one in the same file. The right
    fingerprint is not enough: exactly one primary key, or nothing is installed."""
    machine.distro, machine.selinux = distro, distro == FEDORA
    machine.extra_keys = ["B" * 40]
    with pytest.raises(InstallError, match="no es solo la de Docker"):
        installer(machine, no_key=True).install()
    assert not machine.docker
    assert not machine.paths.apt_keyring.exists() and not machine.paths.rpm_key.exists()
    assert not any(argv[0] == "rpm" for argv in machine.calls)
    assert not (machine.paths.state_dir / "docker-key.tmp").exists()


def test_only_the_exported_key_is_installed(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    key = machine.paths.rpm_key
    assert key.read_text().endswith(f"only {DOCKER_FPR['fedora']}\n")  # gpg's export, not the file
    assert ("rpm", "--import", str(key)) in machine.calls
    assert f"gpgkey=file://{key}" in machine.paths.dnf_repo.read_text()
    exports = [argv for argv in machine.calls if argv[0] == "gpg" and "--export" in argv]
    assert exports and exports[0][-1] == DOCKER_FPR["fedora"]


def test_a_first_config_that_does_not_parse_is_not_left_behind(machine: Machine) -> None:
    """Review of T13-3, R8: a time zone that does not exist makes the first backtide.toml
    unusable. It is removed (and out of the manifest), so the next run writes a good one
    instead of keeping the bad one "as it is"."""
    with pytest.raises(InstallError, match="la configuración no sirve"):
        installer(machine, no_key=True, timezone="Mars/Olympus_Mons").install()
    assert not machine.paths.config_file.exists()
    record = manifest.load(machine.paths.manifest)
    assert str(machine.paths.config_file) not in record.created["files"]
    installer(machine, no_key=True, timezone="Europe/Madrid").install()
    assert 'timezone = "Europe/Madrid"' in machine.paths.config_file.read_text()


def test_a_config_the_person_wrote_is_never_removed(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    machine.paths.config_file.write_text("this is = not [ toml\n")
    with pytest.raises(InstallError, match="la configuración no sirve"):
        installer(machine, no_key=True).install()
    assert machine.paths.config_file.read_text() == "this is = not [ toml\n"


def test_a_time_zone_cannot_add_settings_to_the_config(machine: Machine) -> None:
    with pytest.raises(InstallError):
        installer(machine, no_key=True, timezone='UTC"\nworkspace_limit = 1\n#').install()
    assert not machine.paths.config_file.exists()


# The agent: OpenClaw by default, Claude Code with --perfil claude-code (D27)

TELEGRAM_TOKEN = "987654321:" + "Zq8vN3kT6pR1wX4mB7cJ0hL5sD9fG2aY"  # its shape; nobody's
CHAT = "424242424"


def config_of(machine: Machine):
    from backtide.service.config import ServiceConfig

    return ServiceConfig.from_file(machine.paths.config_file)


def test_openclaw_is_the_default_and_its_config_says_so(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    assert 'profile = "openclaw"' in machine.paths.config_file.read_text()
    assert config_of(machine).agent_profile.name == "openclaw"
    assert manifest.load(machine.paths.manifest).facts["profile"] == "openclaw"
    assert machine.paths.gateway_token.exists()


def test_claude_code_gets_its_image_its_config_and_no_gateway_token(
    machine: Machine, key_file: Path
) -> None:
    prompter = Prompter()
    installer(machine, prompter, key_file=key_file, profile="claude-code").install()
    pulled = {image.ref for image in images.pinned("claude-code")}
    assert set(machine.images) == pulled
    assert images.AGENTS["openclaw"].ref not in machine.images  # 4,7 GiB not pulled for nothing
    config = config_of(machine)
    assert config.agent_profile.name == "claude-code"
    text = machine.paths.config_file.read_text()
    assert 'profile = "claude-code"' in text
    assert '"openai"' not in text and "models =" not in text and "fallbacks" not in text
    assert [provider.name for provider in config.proxy_settings().providers] == ["anthropic"]
    assert not machine.paths.gateway_token.exists()  # OpenClaw's only
    assert (machine.paths.keys_dir / "anthropic.key").read_text() == KEY + "\n"
    record = manifest.load(machine.paths.manifest)
    assert record.facts["profile"] == "claude-code"
    assert set(record.created["images"]) == pulled
    assert any("backtide tarea" in line and "backtide entrar" in line for line in prompter.said)


def test_a_claude_code_install_run_again_without_perfil_changes_nothing(
    machine: Machine, key_file: Path
) -> None:
    installer(machine, key_file=key_file, profile="claude-code").install()
    before = snapshot(machine.root)
    before.pop("var/lib/backtide/install-manifest.json")
    machine.calls.clear()
    installer(machine, key_file=key_file).install()
    installer(machine, key_file=key_file, profile="claude-code").install()
    after = snapshot(machine.root)
    after.pop("var/lib/backtide/install-manifest.json")
    assert after == before
    assert changes(machine.calls) == []
    assert config_of(machine).agent_profile.name == "claude-code"


@pytest.mark.parametrize(("first", "then"), [("openclaw", "claude-code"),
                                             ("claude-code", "openclaw")])  # fmt: skip
def test_another_agent_over_an_install_stops_before_any_change(
    machine: Machine, first: str, then: str
) -> None:
    installer(machine, no_key=True, profile=first).install()
    before = snapshot(machine.root)
    machine.calls.clear()
    with pytest.raises(InstallError, match="desinstala antes") as caught:
        installer(machine, no_key=True, profile=then).install()
    assert f"--perfil {then}" in str(caught.value)
    assert changes(machine.calls) == [] and machine.calls == []
    assert snapshot(machine.root) == before


def uninstalled_keeping_the_config(machine: Machine) -> str:
    """What `backtide desinstalar` leaves of the config: backtide.toml in the state folder."""
    text = machine.paths.config_file.read_text()
    saved = machine.paths.state_dir / "backtide.toml.guardado"
    saved.write_text(text)
    saved.chmod(0o600)
    machine.paths.config_file.unlink()
    return text


def test_after_uninstalling_the_same_agent_comes_back_without_perfil(machine: Machine) -> None:
    installer(machine, no_key=True, profile="claude-code", daily_usd=Decimal("3")).install()
    kept = uninstalled_keeping_the_config(machine)
    installer(machine, no_key=True).install()
    assert machine.paths.config_file.read_text() == kept
    assert config_of(machine).agent_profile.name == "claude-code"


def test_after_uninstalling_another_agent_starts_on_the_same_data(machine: Machine) -> None:
    installer(machine, no_key=True, daily_usd=Decimal("3")).install()
    kept = uninstalled_keeping_the_config(machine)
    key = (machine.paths.state_dir / "blackbox.key").read_bytes()
    prompter = Prompter()
    installer(machine, prompter, no_key=True, profile="claude-code").install()
    assert config_of(machine).agent_profile.name == "claude-code"
    aside = machine.paths.state_dir / "backtide.toml.guardado.openclaw"
    assert aside.read_text() == kept and mode(aside) == 0o600  # never used, never deleted
    assert not (machine.paths.state_dir / "backtide.toml.guardado").exists()
    assert (machine.paths.state_dir / "blackbox.key").read_bytes() == key  # the same chain
    assert any("se aparta" in line and "OpenClaw" in line for line in prompter.said)


def test_claude_code_only_speaks_anthropic(machine: Machine) -> None:
    with pytest.raises(InstallError, match="Anthropic"):
        installer(machine, no_key=True, profile="claude-code", provider="openai").install()
    assert machine.calls == []


def test_a_dry_run_lists_the_image_of_its_agent(machine: Machine) -> None:
    prompter = Prompter()
    installer(machine, prompter, no_key=True, dry_run=True, profile="claude-code").install()
    text = "\n".join(prompter.said)
    assert "Agente: Claude Code" in text
    assert images.AGENTS["claude-code"].ref in text
    assert images.AGENTS["openclaw"].ref not in text
    assert changes(machine.calls) == []


# Where the key and Telegram go later: the installed web (T12c)


def test_without_a_key_it_says_how_to_open_the_web_and_where_in_settings(
    machine: Machine,
) -> None:
    prompter = Prompter()
    installer(machine, prompter, no_key=True).install()
    text = "\n".join(prompter.said)
    assert "Sin clave del modelo (--sin-clave)" in text
    assert text.count("sudo backtide enlace") >= 3  # the key's line, the summary's two
    assert "Ajustes > Modelos" in text and "Ajustes > Avisos" in text


# Telegram, optional (D27): the token like the key, never in argv nor in a message


def telegram_file(machine: Machine) -> Path:
    return machine.paths.state_dir / "telegram.toml"


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    path = tmp_path / "telegram-token.txt"
    path.write_text(TELEGRAM_TOKEN + "\n")
    return path


def test_without_telegram_nothing_is_written_and_the_web_is_named(machine: Machine) -> None:
    prompter = Prompter()
    installer(machine, prompter, no_key=True).install()
    assert not telegram_file(machine).exists()
    assert any("Sin Telegram (es opcional)" in line and "Ajustes > Avisos" in line
               for line in prompter.said)  # fmt: skip


def test_telegram_from_a_file_is_written_as_the_settings_page_writes_it(
    machine: Machine, token_file: Path
) -> None:
    from backtide.service.telegram_config import load_telegram

    prompter = Prompter()
    installer(machine, prompter, no_key=True, telegram=True, telegram_token_file=token_file,
              telegram_chat=CHAT).install()  # fmt: skip
    path = telegram_file(machine)
    assert path.read_text() == f'token = "{TELEGRAM_TOKEN}"\nchat_id = {CHAT}\n'
    assert mode(path) == 0o600
    settings = load_telegram(machine.paths.state_dir)
    assert settings is not None and settings.chat_id == int(CHAT)
    assert str(path) in manifest.load(machine.paths.manifest).created["files"]
    assert not any(TELEGRAM_TOKEN in arg for argv in machine.calls for arg in argv)
    assert not any(TELEGRAM_TOKEN in line for line in prompter.said)
    assert TELEGRAM_TOKEN not in manifest.load(machine.paths.manifest).to_json()
    assert TELEGRAM_TOKEN not in machine.paths.config_file.read_text()
    assert f"Telegram (el token y el chat {CHAT}): creada." in prompter.said
    assert not any("Ajustes > Avisos" in line for line in prompter.said)


def test_telegram_asked_at_the_terminal_without_echo(machine: Machine) -> None:
    prompter = Prompter(interactive=True, token=TELEGRAM_TOKEN, chat=CHAT)
    installer(machine, prompter, no_key=True, telegram=True).install()
    assert any("Token del bot de Telegram" in q and "no se ve" in q for q in prompter.asked)
    assert any("chat privado" in q for q in prompter.asked)
    assert TELEGRAM_TOKEN in telegram_file(machine).read_text()


def test_the_key_and_the_token_both_from_stdin_one_line_each(machine: Machine) -> None:
    import io

    run = installer(machine, key_stdin=True, telegram=True, telegram_token_stdin=True,
                    telegram_chat=CHAT)  # fmt: skip
    run.stdin = io.BytesIO(f"{KEY}\n{TELEGRAM_TOKEN}\n".encode())
    run.install()
    assert (machine.paths.keys_dir / "anthropic.key").read_text() == KEY + "\n"
    assert TELEGRAM_TOKEN in telegram_file(machine).read_text()


def test_the_token_alone_from_stdin(machine: Machine) -> None:
    import io

    run = installer(machine, no_key=True, telegram=True, telegram_token_stdin=True,
                    telegram_chat=CHAT)  # fmt: skip
    run.stdin = io.BytesIO(TELEGRAM_TOKEN.encode() + b"\n")
    run.install()
    assert TELEGRAM_TOKEN in telegram_file(machine).read_text()


def test_one_line_on_stdin_for_two_secrets_is_refused_without_saying_it(machine: Machine) -> None:
    import io

    run = installer(machine, key_stdin=True, telegram=True, telegram_token_stdin=True,
                    telegram_chat=CHAT)  # fmt: skip
    run.stdin = io.BytesIO(KEY.encode() + b"\n")
    with pytest.raises(InstallError, match="1 líneas y debían ser 2") as caught:
        run.install()
    assert KEY not in str(caught.value)


def test_a_token_of_the_wrong_shape_is_refused_without_saying_it(
    machine: Machine, tmp_path: Path
) -> None:
    wrong = tmp_path / "wrong.txt"
    wrong.write_text("not-a-bot-token-0123456789abcdefghij\n")
    with pytest.raises(InstallError, match="no parece un token") as caught:
        installer(machine, no_key=True, telegram=True, telegram_token_file=wrong,
                  telegram_chat=CHAT).install()  # fmt: skip
    assert "not-a-bot" not in str(caught.value)
    assert not telegram_file(machine).exists()


@pytest.mark.parametrize("chat", ["-100123456", "abc", "0", ""])
def test_a_chat_that_is_not_a_private_one_is_refused(
    machine: Machine, token_file: Path, chat: str
) -> None:
    with pytest.raises(InstallError, match="chat privado"):
        installer(machine, no_key=True, telegram=True, telegram_token_file=token_file,
                  telegram_chat=chat).install()  # fmt: skip
    assert not telegram_file(machine).exists()


@pytest.mark.parametrize(
    ("given", "says"),
    [({}, "--telegram-token-archivo"), ({"telegram_token_stdin": True}, "--telegram-chat")],
)
def test_telegram_without_a_terminal_needs_its_sources_before_any_change(
    machine: Machine, given: dict, says: str
) -> None:
    with pytest.raises(InstallError, match=says):
        installer(machine, no_key=True, telegram=True, **given).install()
    assert machine.calls == [] and not machine.paths.state_dir.exists()


def test_the_same_telegram_twice_changes_nothing(machine: Machine, token_file: Path) -> None:
    options = {"no_key": True, "telegram": True, "telegram_token_file": token_file,
               "telegram_chat": CHAT}  # fmt: skip
    installer(machine, **options).install()
    before = snapshot(machine.root)
    before.pop("var/lib/backtide/install-manifest.json")
    machine.calls.clear()
    prompter = Prompter()
    installer(machine, prompter, **options).install()
    after = snapshot(machine.root)
    after.pop("var/lib/backtide/install-manifest.json")
    assert after == before and changes(machine.calls) == []
    assert f"Telegram (el token y el chat {CHAT}): igual." in prompter.said
    installer(machine, no_key=True).install()  # without --telegram: kept as it is
    assert telegram_file(machine).read_bytes() == before["var/lib/backtide/telegram.toml"][4]


def test_a_new_telegram_restarts_the_running_service(
    machine: Machine, token_file: Path, tmp_path: Path
) -> None:
    installer(machine, no_key=True).install()
    machine.calls.clear()
    installer(machine, no_key=True, telegram=True, telegram_token_file=token_file,
              telegram_chat=CHAT).install()  # fmt: skip
    assert ("systemctl", "restart", layout.SERVICE_UNIT) in machine.calls
    assert ("systemctl", "restart", layout.WEB_UNIT) not in machine.calls


def test_the_tests_api_base_is_kept_as_the_settings_page_keeps_it(
    machine: Machine, token_file: Path
) -> None:
    installer(machine, no_key=True).install()
    path = telegram_file(machine)
    path.write_text(f'token = "{"1" * 9}:{"B" * 35}"\nchat_id = 7\n'
                    'api_base = "http://127.0.0.1:8081"\n')  # fmt: skip
    path.chmod(0o600)
    installer(machine, no_key=True, telegram=True, telegram_token_file=token_file,
              telegram_chat=CHAT).install()  # fmt: skip
    assert path.read_text() == (
        f'token = "{TELEGRAM_TOKEN}"\nchat_id = {CHAT}\napi_base = "http://127.0.0.1:8081"\n'
    )


# Tested distributions (docs/44): the others are accepted and said to be untested


@pytest.mark.parametrize(
    ("distro", "arch", "untested"),
    [
        (FEDORA, "aarch64", []),
        (UBUNTU, "aarch64", []),
        (b'ID=fedora\nVERSION_ID=43\nPRETTY_NAME="Fedora Linux 43"\n', "aarch64",
         ["Fedora Linux 43"]),
        (b'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04 LTS"\n', "aarch64",
         ["Ubuntu 26.04 LTS"]),
        (FEDORA, "x86_64", ["x86_64"]),
    ],
)  # fmt: skip
def test_what_is_untested_is_accepted_and_said(
    machine: Machine, distro: bytes, arch: str, untested: list[str]
) -> None:
    machine.distro = distro
    machine.machine = lambda: arch  # type: ignore[method-assign]
    machine.docker = machine.docker_selinux = True  # the fake's Docker key is 44's and 24.04's
    prompter = Prompter()
    warnings = installer(machine, prompter, no_key=True).install()
    said = [w for w in warnings if "aún no se ha probado" in w]
    assert len(said) == len(untested)
    for name, warning in zip(untested, said, strict=True):
        if name == "x86_64":
            assert name in warning and "aarch64" in warning
        else:
            assert name in warning and "Fedora 44 y Ubuntu 24.04" in warning


def test_a_config_put_aside_before_is_never_written_over(machine: Machine) -> None:
    """Review of D27, finding 2: OpenClaw, Claude Code, OpenClaw, Claude Code again, each after
    an uninstall: the first OpenClaw config put aside is still there, whole."""
    installer(machine, no_key=True, daily_usd=Decimal("3")).install()
    first = uninstalled_keeping_the_config(machine)
    installer(machine, no_key=True, profile="claude-code").install()
    uninstalled_keeping_the_config(machine)
    installer(machine, no_key=True, profile="openclaw").install()
    second = uninstalled_keeping_the_config(machine)
    prompter = Prompter()
    installer(machine, prompter, no_key=True, profile="claude-code").install()
    state = machine.paths.state_dir
    assert (state / "backtide.toml.guardado.openclaw").read_text() == first
    assert (state / "backtide.toml.guardado.openclaw.2").read_text() == second
    assert (state / "backtide.toml.guardado.claude-code").exists()
    assert any("backtide.toml.guardado.openclaw.2" in line for line in prompter.said)


def test_check_options_refuses_before_any_change(machine: Machine) -> None:
    installer(machine, no_key=True).install()
    machine.calls.clear()
    before = snapshot(machine.root)
    with pytest.raises(InstallError, match="desinstala antes"):
        installer(machine, no_key=True, profile="claude-code").check_options()
    installer(machine, no_key=True).check_options()  # the same agent: nothing to refuse
    assert machine.calls == [] and snapshot(machine.root) == before


@pytest.mark.parametrize(
    ("config", "refused"),
    [
        ("no profile line", None),  # an older backtide.toml: OpenClaw
        ("this is = not [ toml\n", "no sirve"),
        ('[agent]\nprofile = "../x"\n', "no sirve"),
    ],
)
def test_the_installed_profile_is_read_before_any_command(
    machine: Machine, config: str, refused: str | None
) -> None:
    installer(machine, no_key=True).install()
    path = machine.paths.config_file
    if config == "no profile line":
        text = path.read_text().replace('profile = "openclaw"\n', "")
        assert "profile" not in text.split("[agent]", 1)[1].split("[", 1)[0]
        path.write_text(text)
    else:
        path.write_text(config)
    machine.calls.clear()
    with pytest.raises(InstallError, match=refused or "desinstala antes"):
        installer(machine, no_key=True, profile="claude-code").install()
    assert machine.calls == []
    if refused is None:
        run = installer(machine, no_key=True)
        run.check_options()
        assert run.profile == "openclaw" and machine.calls == []


def test_a_bad_chat_stops_the_check_before_any_command(machine: Machine) -> None:
    """The chat is checked in --solo-comprobar too, terminal or not, before install.sh switches
    the release in use."""
    for interactive in (False, True):
        run = installer(machine, Prompter(interactive=interactive), no_key=True, telegram=True,
                        telegram_token_stdin=True, telegram_chat="-123")  # fmt: skip
        with pytest.raises(InstallError, match="chat privado"):
            run.check_options()
    assert machine.calls == []
