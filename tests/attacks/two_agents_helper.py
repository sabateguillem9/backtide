"""What the two agents' lab asks as root (tests/attacks/two_agents_kit.py). Prints JSON.

The battery runs as the VM's plain user and the state of a real service is root's, so what reads a
black box or a volume, or rebuilds a container as backtide would, runs through ``sudo`` as this one
program. It runs only what is written here, on the lab's own paths.

    python -m two_agents_helper events <box folder> [<action>]
    python -m two_agents_helper verify <box folder>
    python -m two_agents_helper usage <workspace>
    python -m two_agents_helper snapshots <volume>
    python -m two_agents_helper load <config>
    python -m two_agents_helper recreate <config> <slug> <host path>
    python -m two_agents_helper selftest <config>
    python -m two_agents_helper tamper <db>
    python -m two_agents_helper count <db>
"""

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from backtide.blackbox import BlackBox, load_key
from backtide.jail import docker
from backtide.jail.config import create_env, docker_create_argv
from backtide.service.agents import load_installation
from backtide.service.config import STATE_CHECKPOINT, STATE_DB, STATE_KEY, ConfigError
from backtide.setup import selftest
from backtide.snapshots import SnapshotStore, btrfs


def box_at(folder: Path) -> BlackBox:
    return BlackBox(
        folder / STATE_DB,
        load_key(folder / STATE_KEY),
        checkpoint_path=folder / STATE_CHECKPOINT,
        readonly=True,
    )


def events(folder: str, action: str | None = None) -> list[dict[str, Any]]:
    with box_at(Path(folder)) as box:
        found = box.events(action=action) if action else box.events()
    return [
        {
            "seq": e.seq,
            "source": e.source,
            "action": e.action,
            "target": e.target,
            "details": e.details,
            "risk": e.risk,
        }
        for e in found
    ]


def verify(folder: str) -> dict[str, Any]:
    with box_at(Path(folder)) as box:
        report = box.verify()
    return {"ok": report.ok, "checked": report.checked}


def usage(workspace: str) -> dict[str, Any]:
    found = btrfs.qgroup_usage(Path(workspace))
    return {"referenced": found.referenced, "limit": found.limit}


def snapshots(volume: str) -> list[str]:
    return [s.id for s in SnapshotStore(Path(volume)).snapshots()]


def load(config: str) -> dict[str, Any]:
    try:
        found = load_installation(Path(config))
    except ConfigError as error:
        return {"ok": False, "error": str(error)}
    return {"ok": True, "agents": [c.slug for c in found.agents]}


def recreate(config: str, slug: str, host_path: str) -> dict[str, Any]:
    """The agent's container removed and made again as backtide would, with one more ``-v``. What
    someone with Docker could do under a running service: the Guardian is what answers."""
    agents = {c.slug: c for c in load_installation(Path(config)).agents}
    jail = agents[slug].jail_config()
    docker.run(["rm", "--force", jail.name])
    argv = docker_create_argv(jail)
    argv[1:1] = ["--volume", f"{host_path}:/mnt/vecino:ro"]
    docker.run(argv, env=create_env(jail))
    docker.run(["start", jail.name])
    return {"ok": True}


def self_test(config: str) -> list[dict[str, str]]:
    found = load_installation(Path(config)).main
    return [
        {"key": c.key, "status": c.status.value, "summary": c.summary}
        for c in selftest._verify(found)  # noqa: SLF001
    ]


def tamper(db: str) -> dict[str, Any]:
    """Changes a recorded event like a careful attacker with the file: lifts the triggers, makes the
    change and puts the very same ones back, so only the chain can tell."""
    connection = sqlite3.connect(db, isolation_level=None)
    try:
        triggers = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        ).fetchall()
        connection.execute("BEGIN IMMEDIATE")
        for name, _ in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')
        changed = connection.execute("UPDATE events SET target = 'otro' WHERE seq = 1").rowcount
        for _, sql in triggers:
            connection.execute(sql)
        connection.execute("COMMIT")
    finally:
        connection.close()
    return {"changed": changed}


def count(db: str) -> dict[str, int]:
    """How many events, with or without its key."""
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return {"events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]}
    finally:
        connection.close()


ORDERS = {
    "events": events,
    "verify": verify,
    "usage": usage,
    "snapshots": snapshots,
    "load": load,
    "recreate": recreate,
    "selftest": self_test,
    "tamper": tamper,
    "count": count,
}

if __name__ == "__main__":
    print(json.dumps(ORDERS[sys.argv[1]](*sys.argv[2:])))
