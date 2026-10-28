"""backtide's own Docker containers and networks, told apart by their labels (T13-4).

The service names its three containers and the installer its two networks, but a name alone
proves nothing: anyone can make a container called ``backtide-agente``. So everything backtide
makes carries a ``backtide.role`` label (backtide.jail.config.ROLE_LABEL), and the uninstaller, and
the installer when it remakes the containers for another version, only ever removes an object
whose label says it is the one expected. One without it is left alone, and the person is told.
"""

import json
import re
from collections.abc import Collection
from enum import Enum

from backtide.jail.config import AGENT_LABEL, AGENT_NETWORK_LABEL, ROLE_LABEL
from backtide.jail.docker import sanitize
from backtide.jail.proxy_config import EGRESS_LABEL, PROXY_LABEL
from backtide.jail.sensor import LABEL as SENSOR_LABEL
from backtide.service.config import ServiceConfig
from backtide.setup.host import Runner

_ID = re.compile(r"[0-9a-f]{12,64}")


class DockerObjectError(Exception):
    """Docker could not say what an object is, or could not remove it (in Spanish)."""


class Found(Enum):
    ABSENT = "absent"
    OURS = "ours"
    NOT_OURS = "not ours"


def role(label: str) -> str:
    """``backtide.role=agent`` -> ``agent``."""
    key, _, value = label.partition("=")
    if key != ROLE_LABEL or not value:
        raise ValueError(f"{label!r} is not a {ROLE_LABEL} label")
    return value


def expected_containers(config: ServiceConfig) -> dict[str, str]:
    """Each container the service makes and the role its label must say."""
    return {
        config.jail_config().name: role(AGENT_LABEL),
        config.proxy_jail_config().name: role(PROXY_LABEL),
        config.sensor_jail_config().name: role(SENSOR_LABEL),
    }


def expected_networks(config: ServiceConfig) -> dict[str, str]:
    """Each network the installer makes and the role its label must say."""
    return {
        config.jail_config().network: role(AGENT_NETWORK_LABEL),
        config.proxy_jail_config().network: role(EGRESS_LABEL),
    }


def find(kind: str, name: str, wanted: str | Collection[str], *, run: Runner) -> Found:
    """Is there a ``kind`` (container or network) called ``name``, and is it backtide's
    ``wanted`` one (a role, or any of several)? Raises DockerObjectError if Docker does not
    answer."""
    return inspect(kind, name, wanted, run=run)[0]


def inspect(
    kind: str, name: str, wanted: str | Collection[str], *, run: Runner
) -> tuple[Found, str]:
    """``find``, and the object's ID from the same ``docker inspect`` (review of T13-4, R7): what
    is removed is the object that was checked, never another one given the name meanwhile."""
    accepted = {wanted} if isinstance(wanted, str) else set(wanted)
    if kind not in ("container", "network"):
        raise ValueError(f"unknown kind {kind!r}")
    labels_of = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
    ran = run(("docker", kind, "inspect", "--format", "{{.Id}} " + labels_of, name))
    if ran is None:
        raise DockerObjectError("Docker no está instalado")
    if ran.returncode != 0:
        if "no such" in ran.stderr.lower() or "not found" in ran.stderr.lower():
            return Found.ABSENT, ""
        detail = sanitize(ran.stderr.strip(), 200)
        raise DockerObjectError(f"Docker no pudo mirar {kind} {name}: {detail}")
    object_id, _, text = ran.stdout.strip().partition(" ")
    if not _ID.fullmatch(object_id):
        raise DockerObjectError(f"Docker dio algo raro al mirar {kind} {name}")
    try:
        labels = json.loads(text or "null") or {}
    except ValueError:
        raise DockerObjectError(f"Docker dio algo raro al mirar {kind} {name}") from None
    if not isinstance(labels, dict) or labels.get(ROLE_LABEL) not in accepted:
        return Found.NOT_OURS, object_id
    return Found.OURS, object_id


def remove(kind: str, name: str, wanted: str | Collection[str], *, run: Runner) -> Found:
    """Remove ``name`` if it is backtide's ``wanted`` one, by the ID that was checked; what was
    there. A container goes with ``rm --force`` (it holds no state: the agent's lives in its
    volume and state folder)."""
    found, object_id = inspect(kind, name, wanted, run=run)
    if found is not Found.OURS:
        return found
    if kind == "container":
        argv: tuple[str, ...] = ("docker", "rm", "--force", object_id)
    else:
        argv = ("docker", "network", "rm", object_id)
    ran = run(argv)
    if ran is None or ran.returncode != 0:
        if ran is not None and "no such" in ran.stderr.lower():
            return Found.ABSENT
        detail = sanitize((ran.stderr if ran else "").strip(), 300)
        raise DockerObjectError(f"no se pudo quitar {kind} {name}: {detail}")
    return Found.OURS
