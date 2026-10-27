"""install-mac.sh, backtide on a Mac (T13b; docs/25, section 7). It runs for real only with an
isolated Lima home (tests/install/instalar_mac_lab.sh); here, with a fake Mac on the PATH
(``uname``, ``sw_vers``, ``sysctl``, ``lsof``, ``curl`` and a ``limactl`` that writes down every
call): the Lima pin, the argv of every call, the key's hop to the VM, idempotence and the
``backtide`` it leaves.

The fakes are Python scripts run by this interpreter. Nothing here starts a VM, downloads
anything or touches the real ~/.lima, ~/.local/bin or Homebrew: HOME and LIMA_HOME are tmp_path.
"""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install-mac.sh"
TEXT = SCRIPT.read_text()
TEMPLATE = ROOT / "lima" / "backtide-mac.yaml"
TEMPLATE_TEXT = TEMPLATE.read_text()
KEY = "sk-ant-api03-" + "Inventada" * 9  # made up here; the shape of a key, nobody's
SHELLS = [s for s in ("/bin/sh", shutil.which("dash")) if s and Path(s).exists()]

FAKE_LIMACTL = r"""
import json, os, sys
from pathlib import Path
state_path = Path(os.environ["FAKE_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
stdin = b"" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.buffer.read()
try:
    os.fstat(3)
    fd3 = True  # a descriptor that could hold the key, left open to Lima
except OSError:
    fd3 = False
calls = Path(os.environ["FAKE_CALLS"])
with calls.open("a") as log:
    log.write(json.dumps({"argv": args, "stdin": stdin.decode(errors="replace"), "fd3": fd3,
                          "lima_home": os.environ.get("LIMA_HOME")}) + "\n")
home = Path(os.environ["LIMA_HOME"])
vms = state.setdefault("vms", {})
ports = state.setdefault("ports", {})
listener = Path(os.environ["FAKE_LISTENER_FILE"])
def save():
    state_path.write_text(json.dumps(state))
if args == ["--version"]:
    print(f"limactl version {state.get('version', '2.2.1')}")
elif args[0] == "list":
    name = args[-1]
    if name not in vms:
        print(f"unmatched instance {name}", file=sys.stderr); sys.exit(1)
    form = args[args.index("--format") + 1] if "--format" in args else ""
    if "PortForwards" in form:
        p = ports.get(name, 8765)
        print(state.get("forwards", f"127.0.0.1 [8765 8765] 127.0.0.1 [{p} {p}] tcp false;"
              "0.0.0.0 [1 65535] 127.0.0.1 [1 65535] any true;"
              ":: [1 65535] 127.0.0.1 [1 65535] any true;"))
    elif "Mounts" in form:
        print(state.get("mounts_len", "0"))
    else:
        print(vms[name])
elif args[0] == "create":
    name = args[args.index("--name") + 1]
    vms[name] = "Stopped"
    setting = args[args.index("--set") + 1]
    ports[name] = int(setting.rsplit("=", 1)[1])
    (home / name).mkdir(parents=True, exist_ok=True)
    (home / name / "lima.yaml").write_text(Path(args[-1]).read_text())
    save()
elif args[0] == "start":
    vms[args[-1]] = "Running"; save()
    (home / args[-1] / "ha.pid").write_text("4242\n")
    listener.write_text("4242\n")  # its hostagent now holds the web's port
elif args[0] == "stop":
    vms[args[-1]] = "Stopped"; save()
    listener.unlink(missing_ok=True)
elif args[0] == "copy":
    pass
elif args[0] == "shell":
    command = args[args.index("--") + 1:] if "--" in args else []
    if state.get("shell_fails"):
        sys.exit(255)
    if command[:2] == ["printenv", "HOME"]:
        print(state.get("vm_home", "/home/me.linux"))
    elif command[:2] == ["sh", "-c"] and "findmnt" in command[2]:
        print(state.get("mounts", ""), end="")
    elif command[:3] == ["sudo", "test", "-e"]:
        sys.exit(0 if state.get("key_in_vm") else 1)
    elif command[:3] == ["sudo", "sh", "-c"]:
        sys.exit(state.get("install_exit", 0))
"""

FAKE_CURL = r"""
import os, shutil, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
with open(os.environ["FAKE_CALLS"], "a") as log:
    log.write('{"curl": "%s"}\n' % args[-1])
shutil.copy(os.environ["FAKE_LIMA_TARBALL"], out)
"""

FAKE_SHASUM = r"""
import hashlib, sys
path = sys.argv[-1]
print(hashlib.sha256(open(path, "rb").read()).hexdigest() + "  " + path)
"""


@dataclass
class Mac:
    """A fake Mac in tmp_path: its PATH, its home, the fake Lima's state and its call log."""

    root: Path
    bin: Path
    home: Path
    lima_home: Path
    script: Path
    archive: Path
    sha: str
    lima_tarball: Path

    @property
    def state_file(self) -> Path:
        return self.root / "state.json"

    @property
    def calls_file(self) -> Path:
        return self.root / "calls.jsonl"

    def state(self) -> dict:
        return json.loads(self.state_file.read_text())

    def set_state(self, **values: object) -> None:
        state = self.state()
        state.update(values)
        self.state_file.write_text(json.dumps(state))

    def calls(self) -> list[dict]:
        if not self.calls_file.exists():
            return []
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()]

    def lima_calls(self) -> list[list[str]]:
        return [call["argv"] for call in self.calls() if "argv" in call]

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.home),
            "LIMA_HOME": str(self.lima_home),
            "TMPDIR": str(self.root / "tmp"),
            "FAKE_STATE": str(self.state_file),
            "FAKE_CALLS": str(self.calls_file),
            "FAKE_LIMA_TARBALL": str(self.lima_tarball),
            "FAKE_LISTENER_FILE": str(self.root / "listener"),
        }
        env.update(extra)
        return env

    def run(
        self,
        *args: str,
        stdin: bytes | None = None,
        shell: str = "/bin/sh",
        script: Path | None = None,
        cwd: Path | None = None,
        **extra: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [shell, str(script or self.script), *args],
            input=(stdin or b"").decode(),
            capture_output=True,
            text=True,
            cwd=cwd or self.root,
            env=self.env(**extra),
            check=False,
            timeout=60,
        )

    def install(self, *extra: str, **kw: object) -> subprocess.CompletedProcess[str]:
        return self.run("--desde", str(self.archive), "--sha256", self.sha, "--si", *extra, **kw)  # type: ignore[arg-type]


def _write_fake(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o755)


def _write_sh(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def _tar(path: Path, files: dict[str, bytes], prefix: str = "") -> None:
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))


def _lima_tarball(path: Path) -> None:
    """A stand-in for Lima's release: ./bin/limactl is the fake limactl."""
    data = f"#!{sys.executable}\n{FAKE_LIMACTL}".encode()
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("./bin/limactl")
        info.size = len(data)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(data))


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A folder with a short real path for LIMA_HOME: Lima's ssh socket must fit in 104 bytes, and
    pytest's tmp_path on a Mac (/private/var/folders/...) is far longer."""
    path = Path(tempfile.mkdtemp(prefix="bm", dir="/tmp"))  # noqa: S108 - short on purpose
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def mac(tmp_path: Path, short_dir: Path) -> Mac:
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (tmp_path / "home").mkdir()
    (tmp_path / "tmp").mkdir()
    _write_sh(
        fake / "uname", 'case "$1" in -s) echo Darwin ;; -m) echo "${FAKE_ARCH:-arm64}" ;; esac'
    )
    _write_sh(fake / "sw_vers", 'echo "${FAKE_MACOS:-27.0.1}"')
    _write_sh(fake / "sysctl", 'echo "${FAKE_MEMORY:-25769803776}"')
    _write_sh(fake / "lsof", 'cat "$FAKE_LISTENER_FILE" 2>/dev/null || true')
    _write_sh(
        fake / "df",
        'echo "Filesystem 1K-blocks Used Available"; echo "x 1 1 ${FAKE_FREE_K:-209715200}"',
    )
    _write_fake(fake / "curl", FAKE_CURL)
    _write_fake(fake / "shasum", FAKE_SHASUM)
    lima_tarball = tmp_path / "lima.tar.gz"
    _lima_tarball(lima_tarball)
    # The script with the fake Lima's hash pinned instead of the real one: the mechanism is what
    # is tested here; the real pin is checked on its own below.
    fake_hash = hashlib.sha256(lima_tarball.read_bytes()).hexdigest()
    script = tmp_path / "install-mac.sh"
    script.write_text(re.sub(r"(?m)^LIMA_SHA256_ARM64=.*$", f"LIMA_SHA256_ARM64={fake_hash}", TEXT))
    archive = tmp_path / "backtide.tar"
    _tar(archive, {"install.sh": b"#!/bin/sh\n", "lima/backtide-mac.yaml": TEMPLATE.read_bytes()})
    machine = Mac(
        root=tmp_path,
        bin=fake,
        home=tmp_path / "home",
        lima_home=short_dir / "l",
        script=script,
        archive=archive,
        sha=hashlib.sha256(archive.read_bytes()).hexdigest(),
        lima_tarball=lima_tarball,
    )
    machine.state_file.write_text(json.dumps({"vms": {}}))
    return machine


def _with_limactl_on_path(mac: Mac, version: str = "2.2.1") -> Path:
    path = mac.bin / "limactl"
    _write_fake(path, FAKE_LIMACTL)
    mac.set_state(version=version)
    return path


def _wrapper(mac: Mac) -> Path:
    return mac.home / ".local" / "bin" / "backtide"


# -- the script itself -------------------------------------------------------------------------


def test_it_is_valid_posix_sh_and_short_enough_to_read() -> None:
    for shell in SHELLS:
        subprocess.run([shell, "-n", str(SCRIPT)], check=True)
    assert TEXT.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in TEXT
    assert len(TEXT.splitlines()) <= 350  # half of it is the `backtide` it leaves on the Mac


def test_lima_is_pinned_by_version_and_hash_and_checked_before_it_is_unpacked() -> None:
    assert re.search(r"^LIMA_VERSION=\d+\.\d+\.\d+$", TEXT, re.M)
    # Lima 2.2.1's own SHA256SUMS for lima-2.2.1-Darwin-arm64.tar.gz (checked on 2026-10-26).
    assert (
        "LIMA_SHA256_ARM64=9e9eacce88f37e185c346bad73aa6136f738d8cdf8c3bb23cd42b071824bc66e" in TEXT
    )
    url = "https://github.com/lima-vm/lima/releases/download/v$LIMA_VERSION/"
    assert url + "lima-$LIMA_VERSION-Darwin-arm64.tar.gz" in TEXT
    assert TEXT.index('"$LIMA_SHA256_ARM64" ] || die') < TEXT.index('tar -xzf "$WORK/lima.tar.gz"')
    assert "--proto =https" in TEXT


def test_it_never_pipes_a_download_into_a_shell_and_uses_no_homebrew() -> None:
    body = TEXT.split("\nset -eu\n", 1)[1]
    assert "eval" not in body
    assert not re.search(r"\|\s*(sudo\s+)?(ba)?sh\b", body)
    assert "brew" not in body
    # sudo exists only inside the VM: every sudo follows a `shell ... --`
    for line in body.splitlines():
        code = re.sub(
            r"'[^']*'", "''", re.sub(r'"[^"]*"', '""', line)
        )  # what runs, not what it says
        if re.search(r"\bsudo\b", code) and not code.lstrip().startswith("#"):
            assert re.search(r"\b(in_vm|probe) sudo|-- sudo backtide", code), line


def test_the_archive_is_checked_before_anything_is_written() -> None:
    checked = TEXT.index('[ "$GOT" = "$WANT" ] || die')
    for later in (
        "mkdir -p",
        "create --tty=false",
        'curl -fsSL --proto =https --tlsv1.2 -o "$WORK/lima',
    ):
        assert checked < TEXT.index(later), later


def test_the_template_mounts_nothing_and_forwards_only_the_web() -> None:
    t = TEMPLATE_TEXT
    assert t.startswith("# backtide-mac:")
    assert re.search(r"(?m)^mounts: \[\]$", t)
    assert 'location: "~' not in t and "writable" not in t
    image = re.search(
        r'location: "(https://[^"]+aarch64\.qcow2)"\n'
        r'  arch: aarch64\n  digest: "sha256:([0-9a-f]{64})"',
        t,
    )
    assert image, "the Fedora image is pinned by digest"
    assert re.search(r"(?m)^cpus: 4$", t) and 'memory: "6GiB"' in t and 'disk: "40GiB"' in t
    forwards = t.split("portForwards:\n", 1)[1]
    first, *ignored = forwards.split("\n- ")[0:3]
    assert (
        "guestPort: 8765" in first and 'hostIP: "127.0.0.1"' in first and "hostPort: 8765" in first
    )
    assert all("ignore: true" in rule and "proto: any" in rule for rule in ignored)
    assert {'guestIP: "0.0.0.0"', 'guestIP: "::"'} <= {
        line.strip().lstrip("- ") for rule in ignored for line in rule.splitlines()
    }
    for off in (
        "forwardAgent: false",
        "forwardX11: false",
        "loadDotSSHPubKeys: false",
        "propagateProxyEnv: false",
        "system: false",
        "user: false",
    ):
        assert off in t, off
    for absent in ("provision:", "plain:", "networks:", "additionalDisks:", "rosetta"):
        assert absent not in t, absent


def test_install_sh_hands_over_to_it_on_a_mac(tmp_path: Path) -> None:
    text = (ROOT / "install.sh").read_text()
    hand_over = text.index('if [ "$(uname -s)" = Darwin ]')
    assert hand_over < text.index('[ "$(id -u)" = 0 ] || die')  # before it asks for root
    assert 'exec sh "$MAC" "$@"' in text


# -- the Mac's checks: each stops before anything is made ----------------------------------------


def _nothing_made(mac: Mac) -> None:
    assert not mac.lima_home.exists()
    assert list(mac.home.iterdir()) == []
    assert mac.lima_calls() == [] or all(c[0] in ("--version", "list") for c in mac.lima_calls())


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"FAKE_ARCH": "x86_64"}, "Intel aún no"),
        ({"FAKE_MACOS": "13.4"}, "13.5 o posterior"),
        ({"FAKE_MEMORY": str(4 * 1024**3)}, "4 GiB de memoria"),
        ({"FAKE_LISTENER": "4242"}, "el puerto 8765 del Mac ya lo usa"),
    ],
)
def test_a_mac_that_does_not_fit_stops_before_any_change(mac: Mac, env: dict, message: str) -> None:
    if "FAKE_LISTENER" in env:  # another program holds the web's port on the Mac
        (mac.root / "listener").write_text(env.pop("FAKE_LISTENER") + "\n")
    done = mac.install(**env)
    assert done.returncode == 1
    assert message in done.stderr
    _nothing_made(mac)


def test_it_refuses_sudo_on_the_mac(mac: Mac) -> None:
    _write_sh(mac.bin / "id", "echo 0")
    done = mac.install()
    assert done.returncode == 1 and "sin sudo" in done.stderr
    _nothing_made(mac)


def test_a_wrong_archive_is_not_used(mac: Mac) -> None:
    done = mac.run("--desde", str(mac.archive), "--sha256", "0" * 64, "--si")
    assert done.returncode == 1 and "no se usa" in done.stderr
    _nothing_made(mac)


def test_a_lima_config_that_could_mount_folders_stops_it(mac: Mac) -> None:
    (mac.lima_home / "_config").mkdir(parents=True)
    (mac.lima_home / "_config" / "override.yaml").write_text("mounts: [{location: '~'}]\n")
    done = mac.install()
    assert done.returncode == 1 and "override.yaml" in done.stderr
    assert mac.lima_calls() == []


def test_without_a_terminal_it_needs_si(mac: Mac) -> None:
    done = mac.run("--desde", str(mac.archive), "--sha256", mac.sha)
    assert done.returncode == 1 and "--si" in done.stderr
    _nothing_made(mac)


def test_dry_run_changes_nothing(mac: Mac) -> None:
    done = mac.install("--dry-run")
    assert done.returncode == 0, done.stderr
    assert "No se ha cambiado nada" in done.stdout
    _nothing_made(mac)


# -- Lima ----------------------------------------------------------------------------------------


def test_lima_missing_the_pinned_one_goes_to_its_own_folder(mac: Mac) -> None:
    done = mac.install("--sin-clave")
    assert done.returncode == 0, done.stderr
    curls = [c["curl"] for c in mac.calls() if "curl" in c]
    assert curls == [
        "https://github.com/lima-vm/lima/releases/download/v2.2.1/lima-2.2.1-Darwin-arm64.tar.gz"
    ]
    limactl = mac.home / ".backtide" / "lima" / "2.2.1" / "bin" / "limactl"
    assert limactl.is_file()
    assert f"LIMACTL='{limactl}'" in _wrapper(mac).read_text()


def test_lima_with_the_wrong_hash_is_not_installed(mac: Mac) -> None:
    mac.lima_tarball.write_bytes(b"not lima")
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "huella de Lima" in done.stderr
    assert not (mac.home / ".backtide" / "lima" / "2.2.1").exists()
    assert mac.lima_calls() == []


def test_a_lima_2_on_the_path_is_used_and_nothing_is_downloaded(mac: Mac) -> None:
    mine = _with_limactl_on_path(mac, "2.3.0")
    done = mac.install("--sin-clave")
    assert done.returncode == 0, done.stderr
    assert not [c for c in mac.calls() if "curl" in c]
    assert f"LIMACTL='{mine}'" in _wrapper(mac).read_text()


def test_a_lima_1_on_the_path_is_left_alone_and_the_pinned_one_is_used(mac: Mac) -> None:
    _with_limactl_on_path(mac, "1.2.0")
    done = mac.install("--sin-clave")
    assert done.returncode == 0, done.stderr
    assert len([c for c in mac.calls() if "curl" in c]) == 1


# -- the VM and the calls ------------------------------------------------------------------------


def _shell_calls(mac: Mac) -> list[dict]:
    return [c for c in mac.calls() if c.get("argv", [""])[0] == "shell"]


def _install_call(mac: Mac) -> dict:
    (call,) = [
        c
        for c in _shell_calls(mac)
        if c["argv"][c["argv"].index("--") + 1 :][:3] == ["sudo", "sh", "-c"]
    ]
    return call


@pytest.mark.parametrize("shell", SHELLS)
def test_the_first_run_makes_the_vm_and_installs_inside(mac: Mac, shell: str) -> None:
    done = mac.install("--sin-clave", "--tope-diario", "3", shell=shell)
    assert done.returncode == 0, done.stderr
    argvs = mac.lima_calls()
    verbs = [a[0] for a in argvs if a[0] not in ("--version", "list")]
    assert verbs[:2] == ["create", "start"]
    create = next(a for a in argvs if a[0] == "create")
    assert create[:4] == ["create", "--tty=false", "--name", "backtide"]
    assert ".portForwards[0].hostPort = 8765" in create
    made = (mac.lima_home / "backtide" / "lima.yaml").read_text()
    assert made == TEMPLATE_TEXT  # the archive's template, nothing added
    copy = next(a for a in argvs if a[0] == "copy")
    assert copy[-1] == "backtide:/home/me.linux/backtide-mac.tar"
    call = _install_call(mac)
    argv = call["argv"]
    assert argv[:4] == ["shell", "--workdir", "/", "backtide"]
    inner = argv[argv.index("--") + 1 :]
    assert inner[4:] == [
        "sh",
        "/home/me.linux/backtide-mac.tar",
        mac.sha,
        "--si",
        "--sin-clave",
        "--tope-diario",
        "3",
    ]
    # the copy in the VM is checked again before its install.sh runs
    script = inner[3]
    assert script.index("sha256sum") < script.index('sh "$s"')
    # the mounts are looked at from inside, before installing
    order = [" ".join(c["argv"][c["argv"].index("--") + 1 :]) for c in _shell_calls(mac)]
    looked = next(i for i, c in enumerate(order) if "findmnt" in c)
    assert looked < next(i for i, c in enumerate(order) if c.startswith("sudo sh -c"))
    assert _wrapper(mac).stat().st_mode & 0o777 == 0o755


def test_a_vm_that_sees_mac_folders_gets_nothing_installed(mac: Mac) -> None:
    mac.set_state(mounts="/Users/someone\n")
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "carpetas del Mac" in done.stderr
    assert not [c for c in mac.lima_calls() if c[0] == "copy"]


def test_someone_elses_vm_with_the_name_is_not_touched(mac: Mac) -> None:
    mac.set_state(vms={"backtide": "Running"})
    (mac.lima_home / "backtide").mkdir(parents=True)
    (mac.lima_home / "backtide" / "lima.yaml").write_text("images: []\n")
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "no es la de backtide" in done.stderr
    assert [a[0] for a in mac.lima_calls() if a[0] not in ("--version", "list")] == []


def test_a_failed_install_inside_says_so_and_leaves_no_wrapper(mac: Mac) -> None:
    mac.set_state(install_exit=1)
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "se ha parado" in done.stderr
    assert not _wrapper(mac).exists()


def test_the_lab_yaml_goes_only_into_a_test_vm(mac: Mac) -> None:
    extra = mac.root / "lab.yaml"
    extra.write_text("provision: []\n")
    assert (
        mac.install(
            "--sin-clave", BACKTIDE_MAC_LAB_YAML=str(extra), BACKTIDE_MAC_LAB_PORT="18765"
        ).returncode
        == 0
    )
    assert "provision" not in (mac.lima_home / "backtide" / "lima.yaml").read_text()
    create = next(a for a in mac.lima_calls() if a[0] == "create")
    assert ".portForwards[0].hostPort = 8765" in create
    (mac.root / "listener").unlink()  # the fake has one port: the first VM's is on 8765
    done = mac.install(
        "--sin-clave",
        "--nombre-vm",
        "backtide-prueba-mac",
        BACKTIDE_MAC_LAB_YAML=str(extra),
        BACKTIDE_MAC_LAB_PORT="18765",
    )
    assert done.returncode == 0, done.stderr
    assert (
        (mac.lima_home / "backtide-prueba-mac" / "lima.yaml")
        .read_text()
        .endswith("provision: []\n")
    )
    create = [a for a in mac.lima_calls() if a[0] == "create"][-1]
    assert ".portForwards[0].hostPort = 18765" in create


@pytest.mark.parametrize("name", ["Backtide", "-x", "a b", "a;b", "a/b", ""])
def test_a_vm_name_with_odd_characters_is_refused(mac: Mac, name: str) -> None:
    done = mac.install("--nombre-vm", name)
    assert done.returncode == 1
    assert "--nombre-vm: letras minúsculas, cifras y guiones" in done.stderr
    _nothing_made(mac)


# -- the key's hop -------------------------------------------------------------------------------


def _assert_key_only_on_stdin(mac: Mac) -> None:
    for call in mac.calls():
        assert KEY not in json.dumps(call.get("argv", call)), call
    assert _install_call(mac)["stdin"] == KEY + "\n"
    assert "--clave-stdin" in _install_call(mac)["argv"]
    for path in mac.root.rglob("*"):
        if path.is_file() and path.name not in ("calls.jsonl", "key.txt"):
            assert KEY.encode() not in path.read_bytes(), path


@pytest.mark.parametrize("form", ["separate", "equals"])
def test_a_key_file_on_the_mac_reaches_the_vm_through_stdin(mac: Mac, form: str) -> None:
    key_file = mac.root / "key.txt"
    key_file.write_text(KEY + "\n")
    key_file.chmod(0o600)
    args = (
        ["--clave-archivo", str(key_file)]
        if form == "separate"
        else [f"--clave-archivo={key_file}"]
    )
    done = mac.install(*args)
    assert done.returncode == 0, done.stderr
    _assert_key_only_on_stdin(mac)
    assert str(key_file) not in json.dumps(
        _install_call(mac)["argv"]
    )  # a Mac path means nothing there
    assert KEY not in done.stdout + done.stderr


def test_a_key_on_stdin_goes_on_to_the_vm(mac: Mac) -> None:
    done = mac.install("--clave-stdin", stdin=(KEY + "\n").encode())
    assert done.returncode == 0, done.stderr
    _assert_key_only_on_stdin(mac)


def test_an_unreadable_key_file_stops_before_any_change(mac: Mac) -> None:
    done = mac.install("--clave-archivo", str(mac.root / "missing.txt"))
    assert done.returncode == 1 and "no se puede leer" in done.stderr
    _nothing_made(mac)


def test_two_ways_of_giving_the_key_are_refused(mac: Mac) -> None:
    key_file = mac.root / "key.txt"
    key_file.write_text(KEY)
    done = mac.install("--clave-archivo", str(key_file), "--clave-stdin")
    assert done.returncode == 1 and "una sola forma" in done.stderr


def test_without_a_key_option_and_no_terminal_nothing_is_sent(mac: Mac) -> None:
    done = mac.install()
    assert done.returncode == 0, done.stderr
    call = _install_call(mac)
    assert call["stdin"] == ""
    assert not {"--clave-stdin", "--sin-clave"} & set(call["argv"])


# -- idempotence ---------------------------------------------------------------------------------


def test_a_second_run_changes_nothing_on_the_mac(mac: Mac) -> None:
    assert mac.install("--sin-clave").returncode == 0
    wrapper = _wrapper(mac)
    before = (wrapper.stat().st_ino, wrapper.stat().st_mtime_ns, wrapper.read_bytes())
    lima = mac.home / ".backtide" / "lima" / "2.2.1" / "bin" / "limactl"
    lima_before = (lima.stat().st_ino, lima.stat().st_mtime_ns)
    first = len(mac.calls())
    done = mac.install("--sin-clave")
    assert done.returncode == 0, done.stderr
    second = mac.calls()[first:]
    verbs = [c["argv"][0] for c in second if "argv" in c]
    assert "create" not in verbs and "start" not in verbs
    assert not [c for c in second if "curl" in c]
    assert (wrapper.stat().st_ino, wrapper.stat().st_mtime_ns, wrapper.read_bytes()) == before
    assert (lima.stat().st_ino, lima.stat().st_mtime_ns) == lima_before
    assert "orden backtide en" not in done.stdout


def test_a_stopped_vm_is_started_not_made_again(mac: Mac) -> None:
    assert mac.install("--sin-clave").returncode == 0
    mac.set_state(vms={"backtide": "Stopped"})
    first = len(mac.calls())
    assert mac.install("--sin-clave").returncode == 0
    verbs = [c["argv"][0] for c in mac.calls()[first:] if "argv" in c]
    assert "start" in verbs and "create" not in verbs


def test_its_own_running_vm_holding_the_port_is_fine(mac: Mac) -> None:
    assert mac.install("--sin-clave").returncode == 0
    assert (mac.root / "listener").read_text() == "4242\n"  # its hostagent, as ha.pid says
    assert mac.install("--sin-clave").returncode == 0


# -- the `backtide` it leaves on the Mac -----------------------------------------------------------


@pytest.fixture
def wrapper(mac: Mac) -> Path:
    assert mac.install("--sin-clave").returncode == 0
    return _wrapper(mac)


def _wrap(
    mac: Mac, wrapper: Path, *args: str, stdin: bytes | None = None
) -> subprocess.CompletedProcess[str]:
    return mac.run(*args, script=wrapper, stdin=stdin)


def test_the_wrapper_forwards_to_sudo_backtide_in_the_vm(mac: Mac, wrapper: Path) -> None:
    first = len(mac.calls())
    done = _wrap(mac, wrapper, "comprobar", "--despues-de-instalar", "a b; c'd")
    assert done.returncode == 0, done.stderr
    (call,) = [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"]
    assert call["argv"] == [
        "shell",
        "--workdir",
        "/",
        "backtide",
        "--",
        "sudo",
        "backtide",
        "comprobar",
        "--despues-de-instalar",
        "a b; c'd",
    ]
    assert call["lima_home"] == str(mac.lima_home)


def test_the_wrapper_sends_a_key_file_through_stdin(mac: Mac, wrapper: Path) -> None:
    key_file = mac.root / "key.txt"
    key_file.write_text(KEY + "\n")
    for args in (["--clave-archivo", str(key_file)], [f"--clave-archivo={key_file}"]):
        first = len(mac.calls())
        done = _wrap(mac, wrapper, "instalar", *args)
        assert done.returncode == 0, done.stderr
        (call,) = [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"]
        assert call["argv"][-2:] == ["instalar", "--clave-stdin"]
        assert call["stdin"] == KEY + "\n"
        assert KEY not in json.dumps(call["argv"])


def test_the_wrapper_starts_a_stopped_vm_first(mac: Mac, wrapper: Path) -> None:
    mac.set_state(vms={"backtide": "Stopped"})
    first = len(mac.calls())
    done = _wrap(mac, wrapper, "enlace")
    assert done.returncode == 0, done.stderr
    verbs = [c["argv"][0] for c in mac.calls()[first:] if c["argv"][0] not in ("list",)]
    assert verbs == ["start", "shell"]
    assert "parada" in done.stderr


@pytest.mark.parametrize(
    ("verb", "argv"),
    [
        ("estado", ["list", "backtide"]),
        ("arrancar", ["start", "--tty=false", "backtide"]),
        ("parar", ["stop", "backtide"]),
    ],
)
def test_the_wrapper_handles_the_vm(mac: Mac, wrapper: Path, verb: str, argv: list[str]) -> None:
    first = len(mac.calls())
    assert _wrap(mac, wrapper, "vm", verb).returncode == 0
    assert [c["argv"] for c in mac.calls()[first:]][-1] == argv


def test_paths_with_quotes_are_quoted_in_the_wrapper(mac: Mac, short_dir: Path) -> None:
    odd = short_dir / "it's here"
    odd.mkdir()
    done = mac.install("--sin-clave", LIMA_HOME=str(odd))
    assert done.returncode == 0, done.stderr
    first = len(mac.calls())
    assert _wrap(mac, _wrapper(mac), "comprobar").returncode == 0
    call = [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"][0]
    assert call["lima_home"] == str(odd)
    assert os.access(_wrapper(mac), os.X_OK)


def test_a_lima_home_too_long_for_its_sockets_stops_before_the_vm(mac: Mac) -> None:
    deep = mac.root / ("x" * 60)
    done = mac.install("--sin-clave", LIMA_HOME=str(deep))
    assert done.returncode == 1 and "demasiado larga" in done.stderr
    assert not [a for a in mac.lima_calls() if a[0] == "create"]


# -- review of T13b ------------------------------------------------------------------------------


def test_a_lab_vm_name_needs_the_labs_network_cut(mac: Mac) -> None:
    done = mac.install("--sin-clave", "--nombre-vm", "backtide-prueba-m")
    assert done.returncode == 1 and "BACKTIDE_MAC_LAB_YAML" in done.stderr
    _nothing_made(mac)


def test_the_preview_notice_comes_first_and_once(mac: Mac) -> None:
    done = mac.install("--sin-clave")
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("backtide is a PREVIEW, with no human security audit yet.")
    assert done.stdout.count("PREVIEW") == 1
    for words in ("spending limit", "never held", "rewind does not bring back", "sleeps",
                  "Apple Silicon", "kernel 7.1+"):  # fmt: skip
        assert words in done.stdout, words
    # the Linux install.sh inside is told not to show it again
    assert "--sin-aviso" in _install_call(mac)["argv"][-1] or "--sin-aviso" in json.dumps(
        _install_call(mac)["argv"]
    )


def test_no_lima_call_ever_gets_the_keys_descriptor(mac: Mac) -> None:
    done = mac.install("--clave-stdin", stdin=(KEY + "\n").encode())
    assert done.returncode == 0, done.stderr
    assert [c["argv"][0] for c in mac.calls() if "argv" in c and c["fd3"]] == []
    assert _install_call(mac)["stdin"] == KEY + "\n"


def _on_a_terminal(mac: Mac, script: Path, *args: str, typed: bytes = b"", signal: int = 0):
    """Run ``script`` with its standard input on a pseudo-terminal (as when typed by a person);
    type ``typed`` once it asks, or send ``signal`` instead. Returns (exit code, all output)."""
    import os
    import pty
    import select
    import signal as signals
    import time

    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["/bin/sh", str(script), *args],
        stdin=slave,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=mac.root,
        env=mac.env(),
    )
    os.close(slave)
    out = b""
    deadline = time.monotonic() + 30
    asked = False
    while proc.poll() is None and time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            out += chunk
        if not asked and b"no se ve al escribirla" in out:
            asked = True
            time.sleep(0.3)
            if signal:
                proc.send_signal(signal)
            else:
                os.write(master, typed)
    out += proc.stdout.read() or b""
    proc.wait(timeout=10)
    os.close(master)
    assert signals  # imported for the callers' constants
    return proc.returncode, out.decode(errors="replace")


def test_a_typed_key_goes_through_stdin_without_echo(mac: Mac) -> None:
    code, out = _on_a_terminal(
        mac, mac.script, "--desde", str(mac.archive), "--sha256", mac.sha, "--si",
        typed=(KEY + "\n").encode(),
    )  # fmt: skip
    assert code == 0, out
    assert KEY not in out  # not echoed, never printed
    call = _install_call(mac)
    assert call["stdin"] == KEY + "\n" and "--clave-stdin" in call["argv"]
    assert KEY not in json.dumps(call["argv"])


def test_ctrl_c_at_the_key_prompt_stops_the_whole_install(mac: Mac) -> None:
    import signal

    code, out = _on_a_terminal(
        mac, mac.script, "--desde", str(mac.archive), "--sha256", mac.sha, "--si",
        signal=signal.SIGINT,
    )  # fmt: skip
    assert code == 130, out
    installs = [
        c
        for c in _shell_calls(mac)
        if c["argv"][c["argv"].index("--") + 1 :][:3] == ["sudo", "sh", "-c"]
    ]
    assert installs == [] and "no se ve al escribirla" in out
    assert not _wrapper(mac).exists()
    assert list((mac.root / "tmp").iterdir()) == []  # its work folder is gone


def test_clave_stdin_from_a_terminal_is_refused(mac: Mac) -> None:
    code, out = _on_a_terminal(
        mac, mac.script, "--desde", str(mac.archive), "--sha256", mac.sha, "--si", "--clave-stdin"
    )
    assert code == 1 and "--clave-archivo" in out
    _nothing_made(mac)


def test_the_wrapper_refuses_clave_stdin_from_a_terminal(mac: Mac, wrapper: Path) -> None:
    first = len(mac.calls())
    code, out = _on_a_terminal(mac, wrapper, "instalar", "--clave-stdin")
    assert code == 1 and "--clave-archivo" in out
    assert [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"] == []


def test_the_wrapper_passes_a_piped_key_on(mac: Mac, wrapper: Path) -> None:
    first = len(mac.calls())
    done = _wrap(mac, wrapper, "instalar", "--clave-stdin", stdin=(KEY + "\n").encode())
    assert done.returncode == 0, done.stderr
    (call,) = [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"]
    assert call["argv"][-2:] == ["instalar", "--clave-stdin"] and call["stdin"] == KEY + "\n"


@pytest.mark.parametrize("name", ["default.yaml", "override.yaml", "base.yaml"])
def test_the_wrapper_refuses_a_lima_config_that_could_change_the_vm(
    mac: Mac, wrapper: Path, name: str
) -> None:
    (mac.lima_home / "_config").mkdir(parents=True, exist_ok=True)
    (mac.lima_home / "_config" / name).write_text("mounts: [{location: '~'}]\n")
    first = len(mac.calls())
    done = _wrap(mac, wrapper, "comprobar")
    assert done.returncode == 1 and name in done.stderr
    assert mac.calls()[first:] == []


@pytest.mark.parametrize("name", ["default.yaml", "override.yaml", "base.yaml"])
def test_the_installer_refuses_a_lima_config_that_could_change_the_vm(mac: Mac, name: str) -> None:
    (mac.lima_home / "_config").mkdir(parents=True)
    (mac.lima_home / "_config" / name).write_text("mounts: [{location: '~'}]\n")
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and name in done.stderr
    assert mac.lima_calls() == []


def test_the_wrapper_will_not_give_the_link_when_another_program_has_the_port(
    mac: Mac, wrapper: Path
) -> None:
    (mac.root / "listener").write_text("999\n")  # not the hostagent (4242)
    first = len(mac.calls())
    done = _wrap(mac, wrapper, "enlace")
    assert done.returncode == 1 and "lo tiene otro programa (pid 999)" in done.stderr
    assert [c for c in mac.calls()[first:] if c.get("argv", [""])[0] == "shell"] == []
    (mac.root / "listener").write_text("4242\n")
    assert _wrap(mac, wrapper, "enlace").returncode == 0


@pytest.mark.parametrize(
    ("state", "message"),
    [
        ({"mounts_len": "1"}, "carpetas del Mac montadas"),
        (
            {"forwards": "127.0.0.1 [1 65535] 127.0.0.1 [1 65535] any false;"},
            "no son los de la plantilla",
        ),
    ],
)
def test_a_vm_whose_config_drifted_from_the_template_is_not_touched(
    mac: Mac, state: dict, message: str
) -> None:
    assert mac.install("--sin-clave").returncode == 0
    mac.set_state(**state)
    first = len(mac.calls())
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and message in done.stderr
    assert not [
        c for c in mac.calls()[first:] if c.get("argv", [""])[0] in ("shell", "copy", "start")
    ]


def test_a_failed_look_into_the_vm_is_not_taken_for_no_mounts(mac: Mac) -> None:
    mac.set_state(shell_fails=True)
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "no se pudo mirar dentro de la VM" in done.stderr
    assert not [a for a in mac.lima_calls() if a[0] == "copy"]


def test_the_wrapper_keeps_absolute_paths(mac: Mac, short_dir: Path) -> None:
    done = mac.install("--sin-clave", cwd=short_dir, LIMA_HOME="rel-lima")
    assert done.returncode == 0, done.stderr
    text = _wrapper(mac).read_text()
    assert f"LIMA_HOME='{short_dir.resolve() / 'rel-lima'}'" in text
    assert re.search(r"^LIMACTL='/", text, re.M)


def test_vm_text_shown_on_the_mac_has_no_terminal_escapes(mac: Mac) -> None:
    mac.set_state(mounts="/Users/me\x1b]0;owned\x07\n")
    done = mac.install("--sin-clave")
    assert done.returncode == 1 and "carpetas del Mac" in done.stderr
    assert "\x1b" not in done.stderr and "\x07" not in done.stderr
