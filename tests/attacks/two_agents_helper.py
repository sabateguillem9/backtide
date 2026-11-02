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
    python -m two_agents_helper decide <control socket> <hold id>
    python -m two_agents_helper charge <box folder> <micro dollars>
    python -m two_agents_helper fake <config> <slug>
    python -m two_agents_helper link <control socket>
    python -m two_agents_helper agents <control socket>
    python -m two_agents_helper budget <control socket>
    python -m two_agents_helper trusted <control socket> <agent or ->
    python -m two_agents_helper untrust <control socket> <agent or -> <trust id>
    python -m two_agents_helper task <control socket> <agent> <prompt>
    python -m two_agents_helper task_status <control socket> <agent or -> <task id>
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
from backtide.service.control import (
    ControlError,
    ask_agents,
    ask_budget,
    ask_decide,
    ask_list,
    ask_task_start,
    ask_task_status,
    ask_untrust,
    ask_web_link,
)
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


def decide(control: str, hold_id: str) -> dict[str, Any]:
    """The owner says yes through the control socket, as `backtide aprobar` does."""
    return ask_decide(Path(control), hold_id, "approve", via="cli")


def charge(folder: str, micro: str) -> dict[str, Any]:
    """What an agent has spent, as its black box says: a model call cannot reach a provider here
    (invariant 8), so the money is written. With the service stopped: the box has one writer. It is
    the event a call that ended with no answer leaves (docs/33), and the ledger catches up with it
    when the service starts."""
    base = Path(folder)
    with BlackBox(
        base / STATE_DB, load_key(base / STATE_KEY), checkpoint_path=base / STATE_CHECKPOINT
    ) as box:
        details = {"flow_id": "lab", "why": "lab", "cost": {"usd_micro": int(micro)}}
        event = box.append("system", "budget_charged", "", details=details, risk=1)
    return {"seq": event.seq}


def fake(config: str, slug: str) -> dict[str, str]:
    """An agent's fake key: what is in its jail. No secret of anybody's."""
    agent = load_installation(Path(config)).agent(slug)
    return {"fake": agent.provider_keys["anthropic"].fake}


def agents(control: str) -> list[dict[str, Any]]:
    """Who the service has, and an empty list while it does not answer yet."""
    try:
        return ask_agents(Path(control), wait=0.0)
    except ControlError:
        return []


def budget(control: str) -> dict[str, Any]:
    return ask_budget(Path(control))


def _whose(agent: str) -> dict[str, str]:
    return {} if agent == "-" else {"agent": agent}


def trusted(control: str, agent: str) -> list[dict[str, Any]]:
    return ask_list(Path(control), "trusted", **_whose(agent))


def untrust(control: str, agent: str, trust_id: str) -> dict[str, Any]:
    return ask_untrust(Path(control), trust_id, **_whose(agent))


def link(control: str) -> dict[str, str]:
    return {"token": ask_web_link(Path(control))}


def task(control: str, agent: str, prompt: str) -> dict[str, Any]:
    return ask_task_start(Path(control), prompt, seconds=30, agent=agent)


def task_status(control: str, agent: str, task_id: str) -> dict[str, Any]:
    return ask_task_status(Path(control), task_id, **_whose(agent))


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
    "decide": decide,
    "charge": charge,
    "fake": fake,
    "link": link,
    "agents": agents,
    "budget": budget,
    "trusted": trusted,
    "untrust": untrust,
    "task": task,
    "task_status": task_status,
}

if __name__ == "__main__":
    print(json.dumps(ORDERS[sys.argv[1]](*sys.argv[2:])))
