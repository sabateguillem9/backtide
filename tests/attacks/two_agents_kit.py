"""Two real Claude Codes under the real unit, in vigia-dev (T26-2b; docs/47, section 11).

What the scenarios of tests/attacks/test_two_agents_attacks.py run on. The incident of 2026-11-01
(docs/incidentes.md) is why it is built this way: a defence killed the installed service ten minutes
in, and the tests never ran under the unit. So the service here is the real one:

- ``backtide vigilar`` as root, under a unit rendered from ``deploy/systemd/backtide.service.in`` by
  the same code the installer uses, only with the lab's paths. Its filters and its mount namespace
  are the ones an installation has. The clock check, every 20 s.
- Each agent's volume is a real btrfs with simple quotas in a file, and each channel a real tmpfs,
  mounted before the service starts by this kit: what the units of an installation do for the main
  agent. For another agent nothing does it yet (T26-6a creates them).
- ``--grupo-web`` with a group that has no account: the case where the narrow socket has only the
  group and its forbidden ids to go by.

It is not an installation (install.sh never runs in vigia-dev, and the clean VM is someone else's):
Python and the code come from the dev environment, bind-mounted where ``ProtectHome`` leaves them.
Nothing leaves the VM: the agents are idle, no key is real, and ``_cut`` drops whatever Docker's
bridges would forward out while the lab is up (invariant 8; the same rule as instalar_lab.sh).

Everything is the lab's and goes at the end: unit, mounts, containers, networks, groups, folders.
"""

import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backtide.jail import identity
from backtide.jail.config import AGENT_UID
from backtide.jail.proxy_config import (
    CHANNEL_SIZE,
    CHANNEL_TMPFS_SOURCE,
    PROXY_GID,
    PROXY_UID,
    channel_tmpfs_options,
)
from backtide.setup import layout, units

REPO = Path(__file__).resolve().parents[2]
LAB = Path("/var/lib/backtide-lab-dos")
STATE = LAB / "state"
ETC = LAB / "etc"
CONFIG = ETC / "backtide.toml"
MAIN_VOLUME = LAB / "volume"
AGENT_VOLUMES = LAB / "agents"
# Where an installation has its program: /opt is readable by a container under SELinux, and the
# proxy mounts the package. The copy is root's, so the proxy's check of who may change it holds.
OPT = Path("/opt/backtide-lab-dos")
BIN = OPT / "bin"
UNIT = "backtide-lab-dos.service"
UNIT_FILE = Path("/run/systemd/system") / UNIT
WEB_GROUP = "backtide-lab-dos-web"
NFT_TABLE = "backtide_lab_dos"
GIB = 1024**3
MIB = 1024**2
# P1 is 341 MiB on 1 GiB, and a new volume has about 494: the caps are what a test can reach,
# and each its own, so one that took the other's would show.
VOLUME_SIZE = GIB
MAIN_CAP = 48 * MIB
OTHER_CAP = 64 * MIB
SLUG = "revisor"
NUMBER = 1
START_TIMEOUT = 240.0
MAX_RESTARTS = 3


def sh(*argv: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=check)  # noqa: S603


def sudo(*argv: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return sh("sudo", "-n", *argv, check=check, timeout=timeout)


def wait(condition: Any, timeout: float, what: str, context: Any = lambda: "") -> None:
    deadline = time.monotonic() + timeout
    while True:
        if condition():
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout:.0f} s waiting for {what}\n{context()}")
        time.sleep(0.5)


@dataclass(frozen=True)
class Agent:
    """One agent of the lab, as the scenarios see it."""

    slug: str
    container: str
    proxy: str
    network: str
    volume: Path
    box: Path  # the folder with its black box
    uid: int
    proxy_uid: int


MAIN = Agent(
    "principal", "backtide-agente", "backtide-egress", "backtide-agente-net", MAIN_VOLUME, STATE,
    AGENT_UID, PROXY_UID,
)  # fmt: skip
OTHER = Agent(
    SLUG, identity.agent_container(SLUG), identity.proxy_container(SLUG),
    identity.agent_network(SLUG), AGENT_VOLUMES / SLUG, STATE / "agents" / SLUG,
    identity.agent_id(NUMBER), identity.proxy_id(NUMBER),
)  # fmt: skip


class Lab:
    """The lab up: the unit started and both agents running. ``close`` takes everything away."""

    def __init__(self) -> None:
        self.main = MAIN
        self.other = OTHER
        self.web_gid = 0

    # Reading what happened (as root: the state is root's)

    def helper(self, *args: str, timeout: float = 120) -> Any:
        ran = sudo(
            str(BIN / "python"), str(REPO / "tests" / "attacks" / "two_agents_helper.py"), *args,
            timeout=timeout,
        )  # fmt: skip
        return json.loads(ran.stdout.strip().splitlines()[-1])

    def events(self, agent: Agent, action: str | None = None) -> list[dict[str, Any]]:
        return self.helper("events", str(agent.box), *([action] if action else []))

    def installation_events(self, action: str | None = None) -> list[dict[str, Any]]:
        return self.helper("events", str(STATE / "installation"), *([action] if action else []))

    def snapshots(self, agent: Agent) -> list[str]:
        return self.helper("snapshots", str(agent.volume))

    def usage(self, agent: Agent) -> dict[str, Any]:
        return self.helper("usage", str(agent.volume / "workspace"))

    def verify(self, agent: Agent) -> dict[str, Any]:
        return self.helper("verify", str(agent.box))

    # The service

    def show(self, name: str) -> str:
        return sh("systemctl", "show", "-p", name, "--value", UNIT).stdout.strip()

    def journal(self, since: str = "") -> str:
        since_args = ["--since", since] if since else ["-b"]
        return sudo(
            "journalctl", "-u", UNIT, "--no-pager", "-o", "cat", *since_args, check=False
        ).stdout

    def running(self, agent: Agent) -> bool:
        ran = sh(
            "docker", "inspect", "--format", "{{.State.Running}}", agent.container, check=False
        )
        return ran.stdout.strip() == "true"

    def in_agent(
        self, agent: Agent, script: str, *, timeout: float = 60
    ) -> subprocess.CompletedProcess[str]:
        return sh(
            "docker", "exec", agent.container, "sh", "-c", script, check=False, timeout=timeout
        )

    def diagnosis(self) -> str:
        return (
            f"unit: {self.show('ActiveState')}/{self.show('SubState')} "
            f"restarts {self.show('NRestarts')} pid {self.show('MainPID')}\n"
            f"{sh('docker', 'ps', '-a', '--format', '{{.Names}} {{.Status}}').stdout}\n"
            f"{self.journal()[-3000:]}\n{self._risky()}"
        )

    def _risky(self) -> str:
        lines = []
        for agent in (MAIN, OTHER):
            try:
                found = self.events(agent)
            except Exception as error:  # a diagnosis never hides what it diagnoses
                lines.append(f"{agent.slug}: {error}")
                continue
            lines += [f"{agent.slug}: {json.dumps(e)[:600]}" for e in found if e["risk"] >= 2]
        return "\n".join(lines[-20:])

    def wait_up(self, timeout: float = START_TIMEOUT) -> None:
        """The unit active and both agents running."""

        def up() -> bool:
            if int(self.show("NRestarts") or 0) > MAX_RESTARTS:
                raise AssertionError(f"the service keeps restarting\n{self.diagnosis()}")
            return (
                self.show("ActiveState") == "active" and self.running(MAIN) and self.running(OTHER)
            )

        wait(
            up,
            timeout,
            "both agents to run under the unit",
            self.diagnosis,
        )

    def restart(self) -> None:
        sudo("systemctl", "restart", UNIT, timeout=180)
        self.wait_up()

    def stop(self) -> None:
        sudo("systemctl", "stop", UNIT, timeout=180)

    def start(self) -> None:
        sudo("systemctl", "start", UNIT, timeout=60)
        self.wait_up()

    # Going away

    def close(self) -> None:
        sudo("systemctl", "stop", UNIT, check=False, timeout=180)
        sudo("rm", "-f", str(UNIT_FILE), check=False)
        sudo("systemctl", "daemon-reload", check=False)
        sudo("systemctl", "reset-failed", UNIT, check=False)
        names = [MAIN.container, MAIN.proxy, OTHER.container, OTHER.proxy, "backtide-sensor"]
        sh("docker", "rm", "--force", *names, check=False)
        nets = [
            MAIN.network, "backtide-salida-net", OTHER.network, identity.egress_network(SLUG)
        ]  # fmt: skip
        sh("docker", "network", "rm", *nets, check=False)
        sudo("sh", "-c", _UNMOUNT_ALL, check=False)
        sudo("rm", "-rf", "--one-file-system", str(LAB), str(OPT), check=False)
        sudo("groupdel", WEB_GROUP, check=False)
        sudo("nft", "delete", "table", "inet", NFT_TABLE, check=False)


_UNMOUNT_ALL = (
    f"findmnt -rn -o TARGET | grep -E '^({LAB}|{OPT})' | sort -r | while read -r point; do "
    'umount "$point"; done'
)


def _cut() -> None:
    """Nothing the proxies would forward leaves the VM while the lab is up (invariant 8)."""
    rules = (
        f"add table inet {NFT_TABLE}\n"
        f"add chain inet {NFT_TABLE} forward {{ type filter hook forward priority -50; "
        "policy accept; }\n"
        f'add rule inet {NFT_TABLE} forward iifname {{ "br-*", "docker0" }} '
        f'oifname != {{ "br-*", "docker0" }} counter drop\n'
    )
    subprocess.run(  # noqa: S603
        ["sudo", "-n", "nft", "-f", "-"], input=rules, text=True, check=True, timeout=30
    )


def _write_as_root(path: Path, text: str, mode: str = "0644") -> None:
    subprocess.run(  # noqa: S603
        ["sudo", "-n", "install", "-m", mode, "/dev/stdin", str(path)],
        input=text,
        text=True,
        check=True,
        timeout=30,
    )


def _make_volume(image: Path, mount: Path) -> None:
    """As the installer does (backtide/setup/volume.py): sparse, squota, loop, 0700."""
    sudo("truncate", "-s", str(VOLUME_SIZE), str(image))
    sudo("chmod", "0600", str(image))
    sudo("mkfs.btrfs", "-q", "-O", "squota", str(image))
    sudo("mkdir", "-p", str(mount))
    sudo("mount", "-o", "loop,noatime,nosuid,nodev", str(image), str(mount))
    sudo("chmod", "0700", str(mount))


def _dev_python() -> tuple[Path, Path]:
    """Where the dev environment's Python and its packages really are."""
    real = Path(os.path.realpath(sys.executable))
    site = next(Path(sys.prefix, "lib").glob("python3.*/site-packages"))
    return real.parents[1], site


def _programs() -> None:
    """The unit runs with ``ProtectHome``, and the dev environment lives in /home: the same files,
    bind-mounted into the lab."""
    python_home, site = _dev_python()
    sudo("mkdir", "-p", str(BIN), str(OPT / "python"), str(OPT / "site"), str(OPT / "code"))
    sudo("mount", "--bind", "-o", "ro", str(python_home), str(OPT / "python"))
    sudo("mount", "--bind", "-o", "ro", str(site), str(OPT / "site"))
    sudo("cp", "-r", str(REPO / "backtide"), str(REPO / "deploy"), str(OPT / "code"))
    sudo("chown", "-R", "root:root", str(OPT / "code"))
    sudo("chmod", "-R", "go-w", str(OPT / "code"))
    interpreter = next((OPT / "python" / "bin").glob("python3.*"))
    python = (
        "#!/bin/sh\nPYTHONDONTWRITEBYTECODE=1 "
        f'PYTHONPATH={OPT}/code:{REPO}/tests/attacks:{OPT}/site exec {interpreter} "$@"\n'
    )
    _write_as_root(BIN / "python", python, "0755")
    program = (
        f"#!/bin/sh\nexec {BIN}/python -c "
        "'import sys; from backtide.cli import main; sys.exit(main(sys.argv[1:]))' \"$@\"\n"
    )
    _write_as_root(BIN / "backtide", program, "0755")


def _unit() -> str:
    template = (units.TEMPLATE_DIR / "backtide.service.in").read_text(encoding="utf-8")
    return units.render(
        template,
        {
            **units.unit_values(),
            "PROGRAM": str(BIN / "backtide"),
            "CONFIG_FILE": str(CONFIG),
            "STATE_DIR": str(STATE),
            "VOLUME_MOUNT": str(MAIN_VOLUME),
            "PROXY_CHANNEL_DIR": str(STATE / "proxy-channel"),
            "AGENT_VOLUMES": str(AGENT_VOLUMES),
            "EXPORT_DIR": str(LAB / "export"),
            "WEB_USER": WEB_GROUP,
        },
    )


MAIN_CONFIG = f"""\
state_dir = "{STATE}"
volume = "{MAIN_VOLUME}"
workspace_limit = {MAIN_CAP}
cycle_interval = 3.0
prune_interval = 20
[agent]
profile = "claude-code"
[[proxy.providers]]
name = "anthropic"
kind = "anthropic"
[budget]
auto_prices = false
[gate]
wait_s = 3
hold_s = 30
"""

OTHER_FILE = f"""\
number = {NUMBER}
name = "Revisor"
volume = "{OTHER.volume}"
workspace_limit = {OTHER_CAP}
[agent]
profile = "claude-code"
"""


def open_lab() -> Lab:
    """Build it all and wait for both agents. Whatever is left from a run that died goes first."""
    lab = Lab()
    lab.close()
    try:
        _cut()
        sudo("groupadd", "--system", WEB_GROUP)
        lab.web_gid = int(sh("getent", "group", WEB_GROUP).stdout.split(":")[2])
        sudo("mkdir", "-p", str(LAB), str(ETC), str(AGENT_VOLUMES))
        sudo("chmod", "0755", str(LAB), str(ETC), str(AGENT_VOLUMES))
        sudo("install", "-d", "-m", "0710", "-g", WEB_GROUP, str(STATE))
        sudo("install", "-d", "-m", "0700", str(STATE / "keys"))
        sudo("install", "-d", "-m", "0700", str(STATE / "agents"))
        sudo("install", "-d", "-m", "0700", str(OTHER.box))
        _programs()
        _write_as_root(
            STATE / "keys" / "anthropic.key",
            f"sk-ant-api03-{secrets.token_urlsafe(60)}\n",
            "0600",
        )
        _make_volume(STATE / "volume.img", MAIN_VOLUME)
        _make_volume(OTHER.box / "volume.img", OTHER.volume)
        sudo("mkdir", "-p", str(STATE / "proxy-channel"))
        for channel, uid, gid in (
            (STATE / "proxy-channel", PROXY_UID, PROXY_GID),
            (OTHER.box / "proxy-channel", OTHER.proxy_uid, OTHER.proxy_uid),
        ):
            sudo("mkdir", "-p", str(channel))
            options = channel_tmpfs_options(CHANNEL_SIZE, uid, gid)
            sudo("mount", "-t", "tmpfs", "-o", options, CHANNEL_TMPFS_SOURCE, str(channel))
        _write_as_root(CONFIG, MAIN_CONFIG)
        sudo("install", "-d", "-m", "0755", str(ETC / "agents"))
        _write_as_root(ETC / "agents" / f"{SLUG}.toml", OTHER_FILE)
        _write_as_root(UNIT_FILE, _unit())
        sudo("systemctl", "daemon-reload")
        lab.start()
    except BaseException:
        print(lab.diagnosis())
        lab.close()
        raise
    return lab


__all__ = ["LAB", "MAIN", "OTHER", "Lab", "layout", "open_lab"]
