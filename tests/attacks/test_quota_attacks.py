"""Evil-agent scenarios against the space cap (T03b), one real OpenClaw per scenario.

Each scenario starts the agent on its own 1 GiB Btrfs with simple quotas and its workspace
capped at TEST_CAP (the fixture of tests/integration/conftest.py), runs the attack INSIDE the
container and then rewinds or measures from the host. The fills and the rewind check reuse the
helpers of tests/integration/test_quota.py, which proved them with the same agent.
"""

import errno
import os
from collections.abc import Callable

from attack_kit import CONTAINER_WORK, Attack, scenario
from test_quota import (
    FILL_SECONDS,
    MARKER,
    NEAR_THE_CAP,
    assert_room_for_a_rewind,
    cap_of,
    rewind_agent,
)
from test_quota_assumptions import FILL_TIMEOUT, MIB, TEST_CAP, commit, mib, shares_extents, space

from backtide.snapshots import Reason, btrfs

MAX_ROUNDS = 6  # periodic snapshots between two rewriting passes, before giving up
SEED_FILES, SEED_MIB = 6, 16  # the data the rewrite pass overwrites: half of the cap
WRITE_PAST_THE_CAP = 256  # MiB, more than the cap itself
COPIES, COPY_MIB = 6, 16


def start(quota_agent: Callable[[int | None], object]):
    """The agent on a capped workspace, with the marker that the rewind must bring back, and
    the snapshot that holds it. Returns (agent, mount point of the volume, that snapshot)."""
    agent = quota_agent(TEST_CAP)
    agent.exec(["sh", "-c", f"echo before > {MARKER}"], check=True)
    return agent, agent.store.root.parent, agent.store.take(Reason.MANUAL)


def later(restarted: bool) -> str:
    """For the evidence: the agent crashed in the fill and the test had to start it again."""
    return " (tras caerse con el relleno, la prueba lo arrancó)" if restarted else ""


def referenced(agent) -> int:
    """Bytes charged to the workspace, after the write-back of what the agent left in cache."""
    os.sync()
    commit(agent.store.root.parent)
    usage = agent.store.workspace_usage()
    assert usage is not None
    return usage.referenced


@scenario("llenar-disco-reescribiendo")
def test_filling_by_rewriting(attack: Attack, quota_agent) -> None:
    agent, mnt, before = start(quota_agent)
    store, directory = agent.store, f"{CONTAINER_WORK}/rewrite"
    seed = attack.run_script(
        agent, "llenar_disco_reescribiendo", "seed", directory, str(SEED_FILES), str(SEED_MIB)
    )

    outcomes = []
    for _ in range(MAX_ROUNDS):
        store.take(Reason.PERIODIC)  # the service's snapshot: it pins what is there now
        outcomes.append(
            attack.run_script(
                agent,
                "llenar_disco_reescribiendo",
                "rewrite",
                directory,
                str(FILL_SECONDS),
                timeout=FILL_TIMEOUT + 120,
            )
        )
        if outcomes[-1]["errno"] != 0:
            break

    charged, full = referenced(agent), space(mnt)
    logical = sum(f.stat().st_size for f in (agent.workspace / "work" / "rewrite").iterdir())
    attack.check(
        "stopped",
        outcomes[-1]["errno"] == errno.EDQUOT
        and charged >= NEAR_THE_CAP * TEST_CAP
        and charged > 1.5 * logical,
        f"en la ronda {len(outcomes)} choca con su tope (EDQUOT, nunca ENOSPC): el espacio "
        f"cobrado llega a {mib(charged)} de {mib(TEST_CAP)} con solo {mib(logical)} de "
        f"archivos, porque cada instantánea retiene lo que reescribe; {full.summary()}",
    )
    assert seed["bytes"] == logical

    assert_room_for_a_rewind(full)
    rewound, restarted = rewind_agent(agent, before)
    attack.check(
        "recoverable",
        rewound.undo is not None and cap_of(store.workspace) == (TEST_CAP, None),
        f"con {len(store.snapshots())} instantáneas apiladas, rebobina: la marca vuelve, los "
        f"archivos reescritos desaparecen, el agente responde{later(restarted)} y el workspace "
        f"nuevo tiene su tope",
    )


@scenario("llenar-metadatos-y-rebobinar")
def test_filling_metadata_then_rewinding(attack: Attack, quota_agent) -> None:
    agent, mnt, before = start(quota_agent)

    outcome = attack.run_script(
        agent,
        "llenar_metadatos_y_rebobinar",
        f"{CONTAINER_WORK}/filler",
        str(FILL_SECONDS),
        timeout=FILL_TIMEOUT + 120,
    )

    charged, full = referenced(agent), space(mnt)
    attack.check(
        "stopped",
        outcome["errno"] == errno.EDQUOT and charged >= NEAR_THE_CAP * TEST_CAP,
        f"{outcome['files']} archivos pequeños en {outcome['seconds']} s y se para con EDQUOT al "
        f"llamar a {outcome['call']}: el espacio cobrado llega a {mib(charged)} de "
        f"{mib(TEST_CAP)}; {full.summary()}",
    )

    assert_room_for_a_rewind(full)
    rewound, restarted = rewind_agent(agent, before)
    attack.check(
        "recoverable",
        rewound.undo is not None and not (agent.workspace / "work" / "filler").exists(),
        f"acaba rebobinado: la marca está de vuelta, los {outcome['files']} archivos ya no "
        f"están, el agente responde{later(restarted)} y el workspace nuevo tiene su tope de "
        f"{mib(TEST_CAP)}",
    )


@scenario("reflink-copy-file-range")
def test_cheap_copies(attack: Attack, quota_agent, battery_sensor) -> None:
    agent, _, _ = start(quota_agent)
    directory = f"{CONTAINER_WORK}/reflink"
    host = agent.workspace / "work" / "reflink"
    start_usage = referenced(agent)

    attack.watch(battery_sensor, agent.jail)
    outcome = attack.run_script(
        agent, "reflink_copy_file_range", directory, str(COPY_MIB), str(COPIES)
    )

    growth = referenced(agent) - start_usage
    sharing = [
        name for name in outcome["copies"] if shares_extents(host / name, host / "original.bin")
    ]
    wanted = (COPIES + 1) * COPY_MIB * MIB  # the original and every copy, each paid in full
    raw = outcome["raw"]
    attack.check(
        "stopped",
        raw["copy_file_range"] == -errno.EXDEV
        and raw["ficlone"] == -95
        and raw["ficlonerange"] == -95
        and outcome["cp_always_returncode"] != 0
        and outcome["identical"]
        and sharing == []
        and growth >= NEAR_THE_CAP * wanted,
        f"copy_file_range da EXDEV, FICLONE y FICLONERANGE dan EOPNOTSUPP y cp --reflink=always "
        f"falla; las {COPIES} copias que sí salen (cp y shutil caen a copiar de verdad) son "
        f"idénticas y no comparten ningún bloque: el espacio cobrado sube {mib(growth)} de "
        f"{mib(wanted)} esperados",
    )

    recorded = attack.recorded_exec(argv="reflink")
    attack.check(
        "recorded",
        bool(recorded),
        f"el sensor grabó {len(recorded)} exec del ataque en {attack.container_short} (el "
        "proceso; el copy_file_range/FICLONE concreto no, docs/23 decisión 6)",
    )


@scenario("quitar-su-propio-tope")
def test_lifting_the_cap(attack: Attack, quota_agent, battery_sensor) -> None:
    agent, mnt, _ = start(quota_agent)
    store = agent.store
    workspace_id = store.workspace_id()

    attack.watch(battery_sensor, agent.jail)
    outcome = attack.run_script(
        agent,
        "quitar_su_propio_tope",
        btrfs.fsid(store.root),
        str(workspace_id),
        f"{CONTAINER_WORK}/past-the-cap",
        str(WRITE_PAST_THE_CAP),
        timeout=FILL_TIMEOUT + 120,
    )

    attempts = outcome["attempts"]
    ioctls = {
        k: v
        for k, v in attempts.items()
        if k in ("limit_none", "quota_disable", "qgroup_assign", "qgroup_create")
    }
    sysfs = {k: v for k, v in attempts.items() if k not in ioctls}
    cap_seen = outcome["cap_seen"]
    attack.check(
        "stopped",
        all(code == 95 for code in ioctls.values())
        and all(
            code in (errno.EROFS, errno.ENOENT, errno.EACCES, errno.EPERM)
            for code in sysfs.values()
        )
        and cap_seen in (TEST_CAP, -errno.ENOENT)
        and cap_of(store.workspace) == (TEST_CAP, None)
        and store.workspace_id() == workspace_id
        and btrfs.quota_mode(mnt) == "squota"
        and outcome["stopped_by"] == errno.EDQUOT
        and outcome["written"] < WRITE_PAST_THE_CAP * MIB,
        f"los {len(ioctls)} ioctl de cuotas fallan con EOPNOTSUPP (95) y los {len(sysfs)} archivos "
        f"de sysfs no se pueden escribir; el tope sigue en {mib(TEST_CAP)} y las cuotas siguen "
        f"activas; al escribir más allá, para con EDQUOT tras {mib(outcome['written'])}",
    )

    recorded = attack.recorded_exec(argv="past-the-cap")
    attack.check(
        "recorded",
        bool(recorded),
        f"el sensor grabó {len(recorded)} exec del intento en {attack.container_short}",
    )
