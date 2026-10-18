"""One shared Tetragon for the evil-agent battery (T07-4): the ``recorded`` dimension.

docs/23, section 9. A scenario's attack runs as ``docker exec … python3 -c "<script>"`` inside
the agent, so each attack is an ``exec`` and its connections are ``net/connect``. This module
runs the real sensor once per test module (never two at a time: one privileged Tetragon per VM),
with its own black box, and attributes the events to whichever agent container a scenario points
it at (``watch``). The ``Attack`` handle reads this black box to check ``recorded``.

- The sensor is the production ``SensorJail`` with a unique, pid-tagged name (like the service
  tests), ``file_perm = 644`` so this non-root pytest can read Tetragon's file, and always
  stopped (SIGTERM, so Tetragon unloads its eBPF programs) and removed, even when a test fails.
- The reader is the production ``TetragonReader`` writing to a real ``BlackBox`` (so what the
  scenarios read is exactly what backtide would record, struck and cut the same way). No rules
  run here: T07 does not score (docs/23, decision 12), so the ``risk`` of these scenarios stays
  ``pending:T07`` in the manifest.
- ``watch(container_id, run)`` points the reader at an agent and proves the whole path with a
  probe (``/bin/true <nonce>`` by ``docker exec``), the only signal that the kernel, Tetragon,
  the file and the reader all work for THAT container (T07-1, P13). It also takes the baseline
  of Tetragon's loss counters; ``check_losses()`` records what grew since, as the production
  heartbeat does (``KernelLoss``, ``system/sensor_gap {kind: kernel_lost}``, risk 2).
- ``known(secrets)`` gives the reader the exact secrets to strike (the agent's Gateway token),
  as ``runner.build_sensor`` does in production (``KnownScrubber`` with ``cut_tails``).
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from backtide.blackbox import BlackBox, Event, create_key
from backtide.blackbox.model import Source
from backtide.blackbox.redact import KnownScrubber
from backtide.jail import docker as jail_docker
from backtide.jail.sensor import SensorJail, SensorJailConfig
from backtide.sensors.tetragon import ReaderConfig, TetragonReader, wait_ready
from backtide.service.process_sensor import KernelLoss, kernel_lost_details
from tests.integration.sensor_kit import (
    SENSOR_PREFIX,
    SENSOR_START_TIMEOUT,
    remove_sensor,
    remove_stale_sensors,
)
from tests.integration.service_kit import wait_until

PROBE_TIMEOUT = 15.0


class BatterySensor:
    """Tetragon plus its reader and a black box, for one test module. ``start()`` brings it up,
    ``watch`` aims it at an agent, ``stop()`` tears it down (always)."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        name = f"{SENSOR_PREFIX}{os.getpid()}-{uuid4().hex[:12]}"
        self.config = SensorJailConfig(state_dir=state_dir / "sensor", name=name, file_perm="644")
        self.jail = SensorJail(self.config)
        key = create_key(state_dir / "blackbox.key")
        self.box = BlackBox(
            state_dir / "blackbox.db",
            key,
            checkpoint_path=state_dir / "checkpoint.json",
        )
        self._reader: TetragonReader | None = None
        self._container: str | None = None
        self._scrubber: KnownScrubber | None = None
        self.losses = KernelLoss(self.jail.loss_counters)

    @property
    def reader(self) -> TetragonReader:
        assert self._reader is not None, "the battery sensor is not started"
        return self._reader

    def start(self) -> None:
        remove_stale_sensors()
        self.box.open()
        self.jail.prepare()
        if self.jail.exists():
            self.jail.remove()
        self.jail.create()
        self.jail.start()
        wait_until(
            self.jail.serving,
            SENSOR_START_TIMEOUT,
            "the battery's Tetragon to serve",
            interval=0.5,
        )
        self._reader = TetragonReader(
            ReaderConfig(events_dir=self.config.events_dir, cursor_file=self.config.cursor_file),
            self.box,
            scrub=self._scrub,
        )
        self._reader.start()

    def known(self, secrets: list[str]) -> None:
        """The exact secrets the reader strikes from now on (production: the Gateway token and
        the providers' keys)."""
        self._scrubber = KnownScrubber(secrets, cut_tails=True)

    def _scrub(self, text: str) -> str:
        scrubber = self._scrubber
        return scrubber.text(text) if scrubber is not None else text

    def check_losses(self) -> dict[str, int]:
        """What Tetragon lost since ``watch`` (or the last check), recorded as the heartbeat
        records it. Empty: nothing lost."""
        grew = self.losses.check()
        if grew:
            self.box.append(
                Source.SYSTEM,
                "sensor_gap",
                self.config.name,
                details=kernel_lost_details(grew),
                risk=2,
            )
        return grew

    def watch(self, container_id: str, run: Callable[..., Any]) -> int:
        """Attribute events to ``container_id`` and prove the whole path with a probe run by
        ``run`` (an agent's ``exec``). Returns the black box's seq right after, so a scenario
        only looks at what its own attack adds."""
        self._container = container_id
        self.reader.set_agent(container_id)

        def launch(nonce: str) -> None:
            run(["/bin/true", nonce], check=False, timeout=PROBE_TIMEOUT)

        wait_ready(self.reader, launch, timeout=self.config.ready_timeout)
        self.losses.baseline()
        return self.mark()

    def mark(self) -> int:
        """The black box's current head seq (0 when empty)."""
        head = self.box.head()
        return head[0] if head is not None else 0

    def events(self, source: str, *, action: str | None = None, since: int = 0) -> list[Event]:
        found = self.box.events(source=source, since_seq=since)
        return [e for e in found if action in (None, e.action)]

    def events_text(self) -> str:
        """Everything Tetragon wrote to its file (644 here; the folder is still 0700)."""
        return "".join(
            path.read_text(errors="replace")
            for path in sorted(self.config.events_dir.glob("*.log"))
        )

    def sensor_logs(self) -> str:
        """``docker logs`` of the sensor's container: a secret must not leak there either.
        Tetragon runs at ``log-level warn`` (no event data), so this stays small."""
        try:
            result = jail_docker.run(
                ["logs", self.config.name], check=False, max_output=4 * 1024 * 1024
            )
        except jail_docker.JailError:
            return ""
        return (result.stdout or "") + (result.stderr or "")

    def stop(self) -> None:
        if self._reader is not None:
            self._reader.stop()
            self._reader = None
        remove_sensor(self.config.name)
        self.box.close()
