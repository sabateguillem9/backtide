"""Evil-agent scenario of the risk rules (T08), with `backtide vigilar` as a process and the real
OpenClaw: the attack runs INSIDE the agent's jail, and the test reads what backtide did from the
host (the black box, the snapshots, the service's log).

- ``avalancha-de-eventos-de-riesgo``: thousands of deletes in a row, every one of them past the
  line of risk 3. The answer to risk 3 (an evidence snapshot and an alert) must be grouped: a
  snapshot at most every two minutes and one alert per rule per minute, whatever the number of
  events, and the black box must stay whole.
- ``borrar-con-el-cubo-vacio``: the agent spends the watcher's token bucket with harmless
  creates and then deletes a project, so that most deletes are folded into a summary and few are
  recorded one by one. Neither count alone reaches its line; the rules add the loose deletes and
  the summary's ``lasting.delete``, and the deletion is risk 3 with its evidence snapshot.
"""

import time
from collections.abc import Callable

from attack_kit import CONTAINER_WORK, Attack, files_under, scenario
from risk_kit import at_risk, peak, rules_of, summary
from watcher_kit import WITHIN, calm, file_events, in_snapshot, last_seq, started

from backtide.analyzer.respond import ALERT_EVERY, EVIDENCE_EVERY
from tests.integration.service_kit import Service, wait_until

SCRIPT = "avalancha_de_eventos_de_riesgo"
FOLDER = "work/risk"
SEVERE = {"mass-delete-severe", "mass-delete-folded-severe"}


@scenario("avalancha-de-eventos-de-riesgo")
def test_a_flood_of_events_of_risk_3(
    attack: Attack, make_real_service: Callable[..., Service]
) -> None:
    service = started(make_real_service)
    calm(service)
    attack.run_script(service.jail, SCRIPT, "build", f"{CONTAINER_WORK}/risk")
    # A snapshot that has the files, so that the deletes point at something to rewind to.
    holding: list = []

    def snapshotted() -> bool:
        holding[:] = [
            snap
            for snap in service.snapshots()
            if in_snapshot(service, snap.id, f"{FOLDER}/f1499").exists()
        ]
        return bool(holding)

    wait_until(snapshotted, WITHIN, "a snapshot with the 1.500 files", context=service.diagnosis)
    baseline = holding[0]
    first_seq = last_seq(service)
    began = time.monotonic()
    outcome = attack.run_script(
        service.jail, SCRIPT, "storm", f"{CONTAINER_WORK}/risk", timeout=300
    )
    assert outcome["deleted"] >= 4000, outcome

    def ours() -> list:
        """The events of the attack: its own paths, and the summaries (the watcher folds what
        does not fit its 5 a second after the first 1.000, so thousands of deletes are a few
        summaries that carry the count)."""
        return [
            e
            for e in file_events(service, since_seq=first_seq)
            if e.action == "summary" or e.target.startswith(FOLDER)
        ]

    def accounted() -> int:
        return sum(1 for e in ours() if e.action == "delete") + sum(
            e.details["counts"].get("delete", 0) for e in ours() if e.action == "summary"
        )

    wait_until(
        lambda: (
            accounted() >= outcome["deleted"] * 0.9
            and at_risk(ours(), 3)
            and service.events("evidence", "snapshot")
        ),
        WITHIN,
        "every delete accounted for, rated 3, and the evidence snapshot",
        context=service.diagnosis,
    )
    time.sleep(6)  # the watcher's last dumps and the responder's last answers
    elapsed = time.monotonic() - began
    events = ours()
    risky = at_risk(events, 3)
    evidence = [e for e in service.events("evidence", "snapshot") if e.seq > first_seq]
    alerts = service.log_text().count("Riesgo máximo")
    allowed_snapshots = 1 + int(elapsed // EVIDENCE_EVERY)
    allowed_alerts = len(SEVERE) * (1 + int(elapsed // ALERT_EVERY)) + 1

    attack.check(
        "stopped",
        service.require_process().poll() is None
        and service.jail.is_running()
        and len(evidence) <= allowed_snapshots
        and 1 <= alerts <= allowed_alerts,
        f"{outcome['deleted']} borrados en {outcome['seconds']} s: {len(risky)} eventos de riesgo "
        f"3 (cada resumen lleva miles), {len(evidence)} instantánea(s) de evidencia (tope "
        f"{allowed_snapshots}: una cada {EVIDENCE_EVERY:.0f} s) y {alerts} aviso(s) (tope "
        f"{allowed_alerts}: uno por regla cada {ALERT_EVERY:.0f} s); el servicio y el agente "
        "siguen vivos",
    )
    attack.check(
        "recorded",
        accounted() >= outcome["deleted"] * 0.9 and service.box.verify().ok,
        f"{accounted()} de los {outcome['deleted']} borrados están contados en la caja negra "
        f"(sueltos o plegados en resúmenes) y la cadena verifica. {summary(events)}",
    )
    attack.check(
        "risk",
        peak(events) == 3 and bool(rules_of(risky) & SEVERE),
        f"los borrados pasan a riesgo 3 por las reglas {sorted(rules_of(risky) & SEVERE)} y se "
        "quedan ahí mientras dura la avalancha",
    )
    # Recoverable: a snapshot from before the storm still has every file, and the black box
    # tells the deletes with pointers to snapshots (the exactness of each pointer is the
    # watcher's own scenarios; here the storm must not lose the way back).
    one_by_one = [e for e in events if e.action == "delete" and e.target.startswith(FOLDER + "/")]
    kept = files_under(in_snapshot(service, baseline.id, FOLDER))
    pointing = sum(1 for e in one_by_one if e.snapshot_id)
    attack.check(
        "recoverable",
        kept >= 1500 and pointing >= len(one_by_one) > 0,
        f"{baseline.id}, la de antes de la avalancha, conserva los {kept} archivos, y los "
        f"{len(one_by_one)} borrados que la caja negra cuenta uno a uno apuntan a una "
        "instantánea: rebobinar a la de antes lo devuelve todo",
    )
    assert service.stop() == 0
    assert service.box.verify().ok


# -- borrar-con-el-cubo-vacio ----------------------------------------------------------------------

BUCKET_SCRIPT = "borrar_con_el_cubo_vacio"
PROJECT = "work/cubo"
JUNK = 1200  # more than the bucket's burst of 1.000


@scenario("borrar-con-el-cubo-vacio")
def test_deleting_after_emptying_the_bucket(
    attack: Attack, make_real_service: Callable[..., Service]
) -> None:
    service = started(make_real_service)
    calm(service)
    before_build = last_seq(service)
    built = attack.run_script(service.jail, BUCKET_SCRIPT, "build", f"{CONTAINER_WORK}/cubo")
    assert built["files"] == 150, built

    def creates_accounted() -> tuple[int, int]:
        """The project's paths below ``work/cubo`` (5 folders and 150 files) that the watcher
        has already written to the black box: each path once if it has a record of its own,
        and what summaries fold under ``work/cubo`` (they count by the first two levels).

        Not only ``create``: a file made before the watcher arms its new folder, and written
        right after, can reach the window as a write before the folder's walk reports it,
        and then its record is a ``modify``. And not only records of their own: OpenClaw's
        start-up can spend most of the bucket's 1.000 tokens, ``calm`` gives back 5 a second,
        and then the creates beyond that are folded into a summary."""
        after = file_events(service, since_seq=before_build)
        own = {
            e.target
            for e in after
            if e.action in ("create", "modify") and e.target.startswith(PROJECT + "/")
        }
        folded = sum(
            entry["count"]
            for e in after
            if e.action == "summary"
            for entry in e.details.get("dirs", [])
            if entry["dir"] == PROJECT
        )
        return len(own), folded

    def creates_written() -> bool:
        """Every path below the project is out of the watcher's 2 s window, and so is the
        project folder, whose create came before them. Until then a snapshot can already hold
        the files while the deletes would land in the same window as the creates, and a create
        and a delete in one window are a ``transient`` delete (it destroys nothing that existed
        before), which no rule counts."""
        return sum(creates_accounted()) >= 155

    def creates_context() -> str:
        loose, folded = creates_accounted()
        summaries = [
            (e.details.get("counts"), e.details.get("dirs", [])[:5])
            for e in file_events(service, "summary", since_seq=before_build)
        ]
        return (
            f"{loose} paths with a record of their own and {folded} folded below {PROJECT}; "
            f"summaries: {summaries}\n{service.diagnosis()}"
        )

    wait_until(creates_written, WITHIN, "the project's creates", context=creates_context)
    holding: list = []

    def snapshotted() -> bool:
        holding[:] = [
            snap
            for snap in service.snapshots()
            if files_under(in_snapshot(service, snap.id, PROJECT)) == 155  # and 5 folders
        ]
        return bool(holding)

    wait_until(snapshotted, WITHIN, "a snapshot with the 150 files", context=service.diagnosis)
    baseline = holding[0]
    first_seq = last_seq(service)
    outcome = attack.run_script(
        service.jail,
        BUCKET_SCRIPT,
        "burn-and-wreck",
        f"{CONTAINER_WORK}/cubo",
        f"{CONTAINER_WORK}/cubo-junk",
        str(JUNK),
    )
    assert outcome["gone"] and outcome["deleted"] == 156, outcome

    def ours() -> list:
        """The project's own deletes, and the summaries (which fold what did not fit)."""
        return [
            e
            for e in file_events(service, since_seq=first_seq)
            if e.action == "summary" or (e.action == "delete" and e.target.startswith(PROJECT))
        ]

    def loose() -> int:
        return sum(1 for e in ours() if e.action == "delete")

    def lasting() -> int:
        return sum(
            e.details.get("lasting", {}).get("delete", 0) for e in ours() if e.action == "summary"
        )

    def folded() -> int:
        return sum(
            e.details.get("counts", {}).get("delete", 0) for e in ours() if e.action == "summary"
        )

    wait_until(
        lambda: (
            loose() + lasting() >= outcome["deleted"]
            and peak(ours()) == 3
            and [e for e in service.events("evidence", "snapshot") if e.seq > first_seq]
        ),
        WITHIN,
        "every delete accounted for (loose or folded), rated 3, and the evidence snapshot",
        context=lambda: (
            f"{service.diagnosis()}\nloose {loose()}, lasting {lasting()}, "
            f"folded {folded()}: {summary(ours())}"
        ),
    )
    events = ours()
    # The attack worked: the bucket was empty, so neither count alone reaches its line of 3
    # (100 loose deletes, 1.000 folded ones). Without that, this scenario proves nothing.
    assert loose() < 100 and folded() < 1000 and lasting() > 0, (loose(), folded(), lasting())
    (evidence, *_) = [e for e in service.events("evidence", "snapshot") if e.seq > first_seq]
    attack.check(
        "recorded",
        loose() + lasting() >= outcome["deleted"] and service.box.verify().ok,
        f"el agente crea {outcome['junk']} archivos vacíos y borra los {outcome['deleted']} del "
        f"proyecto en {outcome['seconds']} s: la caja negra graba {loose()} borrados sueltos y "
        f"pliega el resto en resúmenes ({folded()} borrados, {lasting()} de archivos que ya "
        "existían), y la cadena verifica",
    )
    attack.check(
        "risk",
        peak(events) == 3
        and "mass-delete-severe" in rules_of(at_risk(events, 3))
        and evidence.snapshot_id is not None
        and (service.store.snapshots_dir / evidence.snapshot_id).is_dir(),
        f"ni los {loose()} sueltos llegan a 100 ni los {folded()} plegados a 1.000, pero la regla "
        f"mass-delete-severe los suma ({loose()} + {lasting()}): riesgo 3, con la instantánea de "
        f"evidencia {evidence.snapshot_id}. {summary(events)}",
    )
    kept = files_under(in_snapshot(service, baseline.id, PROJECT))
    attack.check(
        "recoverable",
        kept == 155,
        f"{baseline.id}, la de antes del borrado, conserva el proyecto entero ({kept} archivos "
        "y carpetas)",
    )
    assert service.stop() == 0
    assert service.box.verify().ok
