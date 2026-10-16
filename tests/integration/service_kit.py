"""The real service in the VM: `vigia vigilar` as a process, watching the real OpenClaw.

Used by test_activity.py, test_service.py and test_idle.py (T04b-2). Nothing here is a fake:
the service is the real command (tests/integration/service_main.py), the agent is the real
OpenClaw in its jail, and the tests read what happened the way a person would, from the black
box and the snapshot store.

The agent can be frozen (``docker pause``) to get a quiet workspace. That is a test tool, not
a product feature (the pause by space is T04d-2): OpenClaw, idle, still writes its SQLite every
~10 s (docs/19, section 2 and the measurement in T04b-2), so "nothing changed" only exists while
the agent is frozen.
"""

import os
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from vigia.blackbox import BlackBox, BlackBoxError, Event, load_key
from vigia.jail import AgentJail
from vigia.jail import docker as jail_docker
from vigia.service.config import Secret, ServiceConfig
from vigia.snapshots import Snapshot, SnapshotStore, btrfs

REPO = Path(__file__).resolve().parents[2]
CYCLE = 3.0  # seconds between two cycles of a test service (the real one is 120)
STARTUP_TIMEOUT = 240.0  # first pull excluded: boot + OpenClaw ready
STOP_TIMEOUT = 120.0
LOG_TAIL = 4000


def wait_until(
    predicate: Callable[[], object],
    timeout: float,
    what: str,
    *,
    interval: float = 0.25,
    context: Callable[[], str] = lambda: "",
) -> None:
    """Poll until ``predicate`` is true or fail with ``what`` and whatever ``context`` adds."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out after {timeout:.0f} s waiting for {what}\n{context()}")
        time.sleep(interval)


@dataclass
class Service:
    """One `vigia vigilar` process and the folders it works on.

    ``config`` is what it reads; ``jail`` and ``store`` are handles for the tests to look at the
    agent and the snapshots (they never start or stop anything on their own)."""

    config: ServiceConfig
    config_path: Path
    jail: AgentJail
    store: SnapshotStore
    log_path: Path
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _box: BlackBox | None = field(default=None, repr=False)

    # Running it

    def start(self) -> None:
        """Launch `vigia vigilar` (it is not necessarily ready: see ``wait_ready``)."""
        assert self.process is None or self.process.poll() is not None, "already running"
        self.process = self.launch()

    def launch(self) -> subprocess.Popen[bytes]:
        """Another `vigia vigilar` on the same config (to see it refused, or to start again)."""
        log = open(self.log_path, "ab")  # noqa: SIM115 - closed by the child's end
        try:
            return subprocess.Popen(
                [sys.executable, "-m", "tests.integration.service_main", str(self.config_path)],
                cwd=REPO,
                env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        finally:
            log.close()  # the child has its own copy

    def wait_ready(self, timeout: float = STARTUP_TIMEOUT) -> None:
        """Wait until the agent is running AND recorded as started by this process."""
        process = self.require_process()
        before = len(self.events("agent_start"))
        wait_until(
            lambda: (
                process.poll() is not None
                or (len(self.events("agent_start")) > before and self.jail.is_running())
            ),
            timeout,
            "the service to start the agent",
            context=self.diagnosis,
        )
        assert process.poll() is None, f"the service exited early\n{self.diagnosis()}"

    def stop(self, number: signal.Signals = signal.SIGTERM) -> int:
        """Signal the service and wait until it ends. Returns its exit code."""
        process = self.require_process()
        process.send_signal(number)
        return self.wait_exit()

    def wait_exit(self, timeout: float = STOP_TIMEOUT) -> int:
        process = self.require_process()
        try:
            return process.wait(timeout)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the service did not end in {timeout:.0f} s\n{self.diagnosis()}")

    def kill(self) -> None:
        """SIGKILL: the service dies without stopping anything."""
        process = self.require_process()
        process.kill()
        process.wait(30)

    def shutdown(self) -> None:
        """The end of a test: stop the service the normal way if it is running, then make sure
        nothing is left."""
        process = self.process
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                pass  # cleanup() kills it
        self.cleanup()

    def cleanup(self) -> None:
        """Leave nothing behind: the service, the agent and its network."""
        process = self.process
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(30)
        if self._box is not None:
            self._box.close()
        errors = []
        for step in (self.jail.remove, self.jail.remove_network):
            try:
                step()
            except Exception as error:  # noqa: BLE001 - every step is tried, the first is raised
                errors.append(error)
        if errors:
            raise errors[0]

    def require_process(self) -> subprocess.Popen[bytes]:
        assert self.process is not None, "the service was never started"
        return self.process

    # Looking at it

    @property
    def box(self) -> BlackBox:
        """The black box, read-only, opened once the service has made it."""
        if self._box is None:
            problems: list[Exception] = []

            def open_it() -> bool:
                if not self.config.blackbox_db.exists():
                    return False
                try:
                    candidate = BlackBox(
                        self.config.blackbox_db,
                        load_key(self.config.blackbox_key),
                        checkpoint_path=self.config.blackbox_checkpoint,
                        readonly=True,
                    )
                    candidate.head()
                except BlackBoxError as error:  # the service is still creating it
                    problems.append(error)
                    return False
                self._box = candidate
                return True

            wait_until(
                open_it,
                60,
                "the black box to be readable",
                context=lambda: f"last error: {problems[-1:]}",
            )
        assert self._box is not None
        return self._box

    def events(self, action: str | None = None, source: str | None = None) -> list[Event]:
        if not self.config.blackbox_db.exists():
            return []
        found = self.box.events(source=source)
        return [event for event in found if action in (None, event.action)]

    def snapshots(self) -> list[Snapshot]:
        return self.store.snapshots()

    def takes(self, trigger: str | None = None) -> list[Event]:
        return [
            event
            for event in self.events("take", "snapshot")
            if trigger in (None, event.details.get("trigger"))
        ]

    def log_text(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except OSError as error:
            return f"(no log: {error})"

    def diagnosis(self) -> str:
        process = self.process
        state = "never started" if process is None else f"exit code {process.poll()}"
        actions = [f"{e.source}/{e.action}" for e in self.events()][-30:]
        return (
            f"service: {state}\nlast events: {actions}\n"
            f"service log (tail):\n{self.log_text()[-LOG_TAIL:]}"
        )

    # The agent, frozen on demand

    def freeze(self) -> None:
        """``docker pause``: every process of the agent stops, so the workspace is quiet."""
        if not self.jail.is_paused():
            jail_docker.run(["pause", self.jail.config.name])
        assert self.jail.is_paused()

    def thaw(self) -> None:
        if self.jail.is_paused():
            jail_docker.run(["unpause", self.jail.config.name])
        assert not self.jail.is_paused()

    def wait_quiet(self, cycles: int = 3) -> None:
        """With the agent frozen: wait until no snapshot has appeared for ``cycles`` cycles,
        which means every write from before the freeze has been snapshotted."""
        last_count = len(self.snapshots())
        last_change = time.monotonic()

        def settled() -> bool:
            nonlocal last_count, last_change
            count = len(self.snapshots())
            if count != last_count:
                last_count, last_change = count, time.monotonic()
            return time.monotonic() - last_change > cycles * CYCLE + 1

        wait_until(settled, 120, "the workspace to be quiet", context=self.diagnosis)

    def wait_snapshot_after(self, count: int, timeout: float) -> list[Snapshot]:
        """Wait until there are more than ``count`` snapshots; return them."""
        wait_until(
            lambda: len(self.snapshots()) > count,
            timeout,
            f"a snapshot beyond the {count} that exist",
            context=self.diagnosis,
        )
        return self.snapshots()

    def workspace_ctransid(self) -> int:
        return btrfs.subvolume_info(self.store.workspace).ctransid


def make_service(
    root: Path,
    state_dir: Path,
    names: tuple[str, str],
    *,
    cycle_interval: float = CYCLE,
) -> Service:
    """Write the config and token of a service for the btrfs folder ``root`` (nothing runs
    yet). ``names`` are the container and network names, from the fixtures' cleanup scheme."""
    container, network = names
    token = secrets.token_urlsafe(32)
    state_dir.chmod(0o700)
    token_file = state_dir / "gateway.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    config_path = state_dir.parent / f"{state_dir.name}.toml"
    config_path.write_text(
        f'state_dir = "{state_dir}"\n'
        f'volume = "{root}"\n'
        f"cycle_interval = {cycle_interval}\n"
        "[agent]\n"
        f'name = "{container}"\n'
        f'network = "{network}"\n'
        f"uid = {os.getuid()}\n"
        f"gid = {os.getgid()}\n"
        'memory = "2g"\n'
        'cpus = "2"\n'
    )
    config_path.chmod(0o600)
    config = ServiceConfig.from_file(config_path)
    assert isinstance(config.gateway_token, Secret)
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    store = SnapshotStore(root)
    return Service(config, config_path, jail, store, state_dir.parent / f"{state_dir.name}.log")
