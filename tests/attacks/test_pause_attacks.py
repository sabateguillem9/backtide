"""Evil-agent scenario of the pause by space (T04d-2), with `backtide vigilar` as a process on a
1 GiB volume with simple quotas, a 64 MiB cap and the real OpenClaw:

- ``pausar-por-espacio``: the agent fills its workspace to just under the cap, waits for backtide's
  snapshot and deletes after it, which is charged with no quota check (A13): the workspace ends
  past its cap. The space thread sees it (P3) and freezes the agent for real; a rewind (the
  frozen agent is killed, never woken) gives a whole new cap and the agent runs again.

The other cases of the pause (metadata and data below the minimum, `backtide seguir`, the service
killed with the agent frozen) are in tests/integration/test_space_pause.py, whose service
fixture and helpers this reuses. Freezing in the middle of a rewind (`docker stop`,
`wait_ready`) is proved with fakes in tests/test_service_guardian.py.
"""

import math
import time
from datetime import UTC, datetime

import pytest
from attack_kit import CONTAINER_WORK, Attack, scenario
from risk_kit import peak, rules_of, summary
from test_space_pause import (  # noqa: F401 - `service` is a fixture, used by name
    CAP,
    cgroup_freeze,
    service,
    state,
    wait_frozen,
)

from backtide.snapshots import btrfs
from backtide.snapshots.space import MIB
from tests.integration.service_kit import Service, exec_in_agent, run_cli, wait_until

SCRIPT = "pausar_por_espacio"
BATCH = 1000  # files per fill (~3 MiB), so the fill stops short of the cap, never at it
FILL_TO = CAP - 10 * MIB  # settled usage to fill up to
OVER = 4 * MIB  # how far past the cap the deletes must take the workspace
LEAF = 16 * 1024  # what a delete is charged (measured: 19 KiB with the tree's own overhead)
SETTLE = 1.0  # seconds the usage must stay put to be the real one


@scenario("pausar-por-espacio")
def test_going_past_the_cap_freezes_the_agent(attack: Attack, service: Service) -> None:  # noqa: F811
    first = service.snapshots()[0].id
    small = f"{CONTAINER_WORK}/small"
    used = fill_near_the_cap(attack, service, small)
    full_at = datetime.now(UTC)
    wait_until(
        lambda: any(snap.taken_at > full_at for snap in service.snapshots()),
        60,
        "a snapshot of the full workspace",
        context=service.diagnosis,
    )
    # The cap of T03b stops the writes, but not the deletes after a snapshot: they copy leaves
    # and are charged with no check. As many leaves as it takes to end OVER the cap. In the
    # background: the agent may be frozen before the script ends, and a `docker exec` waiting
    # for it would hang.
    seq_before_delete = service.box.head()[0]  # type: ignore[index]
    leaves = math.ceil((CAP + OVER - used) / LEAF)
    exec_in_agent(service, f"python3 -c '{_source()}' delete {small} {leaves} >/dev/null 2>&1 &")
    wait_frozen(service, "P3")

    found = state(service)
    usage = btrfs.qgroup_usage(service.store.workspace)
    attack.check(
        "stopped",
        found["Paused"] is True and cgroup_freeze(found["Pid"]) == "1" and usage.referenced > CAP,
        f"el espacio de trabajo pasó de su tope ({usage.referenced} > {CAP} bytes) borrando tras "
        "una instantánea, y el hilo de espacio congeló al agente de verdad (docker pause, "
        "cgroup.freeze = 1)",
    )
    pause = next(e for e in service.events("space_pause") if "P3" in e.details["conditions"])
    attack.check(
        "recorded",
        pause.risk == 2 and pause.details["frozen"] is True,
        f"system/space_pause {{conditions: {pause.details['conditions']}, frozen: true}} con "
        f"riesgo {pause.risk}, y un aviso que dice qué retiene el espacio",
    )

    # Risk (T08): the pause is the service's own event (risk 2), and so is what the agent did to
    # cause it: ~700 deletes in seconds, which the watcher has to fold into a summary (the
    # fill emptied its bucket), rated 2 by the rules ("100 or more in a minute, folded"), or 3
    # once the summary's ``lasting.delete`` (the folded deletes of files from before) adds up
    # to 100 with the loose ones (mass-delete-severe).
    def deleted() -> list:
        return [
            e
            for e in service.events(source="file")
            if e.seq > seq_before_delete and e.action in ("delete", "summary")
        ]

    wait_until(
        lambda: peak(deleted()) >= 2,
        60,
        "the rules to rate the deletes",
        context=service.diagnosis,
    )
    # The attack's ~1.000 deletes are rated 2, or 3 when the folded ones of files from before
    # reach 100 with the loose ones, or when all the folded ones reach 1.000 (the real OpenClaw,
    # running meanwhile, churns its own cache: measured 360-470 deletes). Both are the rules
    # working.
    attack.check(
        "risk",
        pause.risk == 2
        and peak(deleted()) in (2, 3)
        and bool(rules_of(deleted()) & {"mass-delete", "mass-delete-folded"}),
        f"la pausa lleva riesgo {pause.risk} (la fija el servicio) y los borrados que la causan "
        f"salen con riesgo 2 o 3 por las reglas (3 cuando los plegados de archivos que ya "
        f"existían suman 100 con los sueltos, o todos los plegados 1.000). "
        f"{summary(deleted())}",
    )
    rewound = run_cli(service, "rebobinar", "--si", first)
    after = state(service)
    resumed = service.events("space_resume")
    attack.check(
        "recoverable",
        rewound.returncode == 0
        and after["Running"] is True
        and after["Paused"] is False
        and bool(resumed)
        and resumed[-1].details["by"] == "rewind",
        "rebobinar al agente congelado lo mata (no lo despierta), le da un tope nuevo y, en "
        "verde, vuelve a arrancar con la pausa cerrada",
    )


def fill_near_the_cap(attack: Attack, svc: Service, directory: str) -> int:
    """Fill in batches until the settled usage is within 10 MiB of the cap, and return it.

    Filling until EDQUOT was not deterministic: the quota also counts what the transaction
    reserved, and in about half the runs the usage fell by ~30 MiB right after the fill (35 MiB of
    a 64 MiB cap), so the fixed ~11 MiB of copied leaves of the delete never reached the cap and
    P3 never came. And a fill that touches the cap can trip P3 itself and freeze the script.
    Below its cap the workspace is not over it: that was this test's assumption, not the pause."""
    used = settled_usage(svc)
    for _ in range(100):
        if used >= FILL_TO:
            return used
        filled = attack.run_script(svc.jail, SCRIPT, "fill", directory, str(BATCH))
        assert not filled["errno"], filled
        used = settled_usage(svc)
    pytest.fail(f"the workspace holds only {used} bytes after 100 fills")


def settled_usage(svc: Service) -> int:
    """The workspace's ``referenced`` once it has stayed the same for ``SETTLE`` seconds (at most
    30 s: the real OpenClaw may keep writing)."""
    value = btrfs.qgroup_usage(svc.store.workspace).referenced
    started = steady_since = time.monotonic()
    while time.monotonic() - steady_since < SETTLE and time.monotonic() - started < 30:
        time.sleep(0.1)
        now = btrfs.qgroup_usage(svc.store.workspace).referenced
        if now != value:
            value, steady_since = now, time.monotonic()
    return value


def _source() -> str:
    from attack_manifest import SCRIPTS_DIR  # noqa: PLC0415

    text = (SCRIPTS_DIR / f"{SCRIPT}.py").read_text()
    assert "'" not in text, "the script goes inside single quotes"
    return text
