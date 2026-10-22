"""The real service in the VM: `backtide vigilar` as a process, watching the real OpenClaw.

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
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, BlackBoxError, Event, load_key
from backtide.jail import AgentJail
from backtide.jail import docker as jail_docker
from backtide.service.config import Secret, ServiceConfig
from backtide.service.guardian import Guardian
from backtide.service.runner import build_guardian, run_guardian, take_lock
from backtide.snapshots import Snapshot, SnapshotStore, btrfs
from tests.integration.proxy_kit import remove_proxy, test_proxy

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
    """One `backtide vigilar` process and the folders it works on.

    ``config`` is what it reads; ``jail`` and ``store`` are handles for the tests to look at the
    agent and the snapshots (they never start or stop anything on their own)."""

    config: ServiceConfig
    config_path: Path
    jail: AgentJail
    store: SnapshotStore
    log_path: Path
    # The launcher of `backtide vigilar` and what it gets after the config (test_space_pause.py
    # runs one that sets the cap through the test's sudo command).
    main: str = "tests.integration.service_main"
    main_args: tuple[str, ...] = ()
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _box: BlackBox | None = field(default=None, repr=False)

    # Running it

    def start(self) -> None:
        """Launch `backtide vigilar` (it is not necessarily ready: see ``wait_ready``)."""
        assert self.process is None or self.process.poll() is not None, "already running"
        self.process = self.launch()

    def launch(self) -> subprocess.Popen[bytes]:
        """Another `backtide vigilar` on the same config (to see it refused, or to start again)."""
        log = open(self.log_path, "ab")  # noqa: SIM115 - closed by the child's end
        try:
            return subprocess.Popen(
                [sys.executable, "-m", self.main, str(self.config_path), *self.main_args],
                cwd=REPO,
                env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        finally:
            log.close()  # the child has its own copy

    def wait_agent_start(self, before: int, timeout: float = STARTUP_TIMEOUT) -> None:
        """Wait until there are more than ``before`` ``agent_start`` events and the agent runs:
        for a Guardian that is not this object's process (``guardian_in_process``)."""
        wait_until(
            lambda: len(self.events("agent_start")) > before and self.jail.is_running(),
            timeout,
            "the agent to be started",
            context=self.diagnosis,
        )

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
        try:
            self.jail.remove()
        except Exception as error:  # noqa: BLE001 - every step is tried, the first is raised
            errors.append(error)
        errors += remove_proxy(self.config)  # the proxy is on the agent's network: first
        try:
            self.jail.remove_network()
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


@contextmanager
def guardian_in_process(service: Service) -> Iterator[Guardian]:
    """The real service of ``service`` (same lock, same parts from ``build_guardian``, same
    ``run_guardian``), but run by this test process in a thread instead of as `backtide vigilar`:
    until the control socket exists (T04c-2) that is the only way to call ``Guardian.rewind``
    while it runs. Yields once the agent is started and watched; stops it like a SIGTERM
    would (the agent stops and ``service_stop`` is recorded) when the block ends."""
    lock = take_lock(service.config.lock_file)
    try:
        # No process sensor here: one privileged Tetragon per VM (test_sensor_exec.py runs it).
        guardian, alerts, box = build_guardian(
            service.config, jail=service.jail, sensor=False, proxy=test_proxy(service.config)
        )
        stop = threading.Event()
        failures: list[BaseException] = []

        def run() -> None:
            try:
                run_guardian(guardian, alerts, box, stop=stop, handle_signals=False)
            except BaseException as error:  # noqa: BLE001 - handed to the test below
                failures.append(error)

        before = len(service.events("agent_start"))
        thread = threading.Thread(target=run, name="test-guardian", daemon=True)
        thread.start()
        try:
            wait_until(
                lambda: (
                    failures
                    or not thread.is_alive()
                    or (len(service.events("agent_start")) > before and service.jail.is_running())
                ),
                STARTUP_TIMEOUT,
                "the in-process service to start the agent",
                context=service.diagnosis,
            )
            if failures:
                raise failures[0]
            yield guardian
        finally:
            stop.set()
            thread.join(STOP_TIMEOUT)
            if thread.is_alive():
                pytest.fail(f"the in-process service did not stop\n{service.diagnosis()}")
        if failures:
            raise failures[0]
    finally:
        lock.close()


REWIND_KILL_TIMEOUT = STARTUP_TIMEOUT + STOP_TIMEOUT


def kill_a_rewind(service: Service, target: str, when: str) -> subprocess.CompletedProcess[str]:
    """Run the real service in another process (tests/integration/rewind_main.py), rewind to
    ``target`` and SIGKILL that process from inside the rewind: ``when`` is "before" (the agent
    is stopped, the swap has not happened) or "after" (swapped, undo point published, nothing
    rearmed or started). The service of ``service`` must not be running. Returns the dead
    process (its return code is -SIGKILL)."""
    assert service.process is None or service.process.poll() is not None, "stop it first"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.integration.rewind_main",
            str(service.config_path),
            target,
            when,
        ],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=REWIND_KILL_TIMEOUT,
        check=False,
    )


CLI_TIMEOUT = 300.0


def run_cli(
    service: Service, command: str, *args: str, timeout: float = CLI_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    """The real `backtide <command> --config <the service's> <args>` as a process of its own
    (tests/integration/cli_main.py), with no terminal: `rebobinar` needs ``--si``. Returns the
    finished process; the tests read its exit code and what it printed."""
    return subprocess.run(
        [sys.executable, "-m", "tests.integration.cli_main", command, "--config",
         str(service.config_path), *args],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO), "PYTHONUNBUFFERED": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )  # fmt: skip


def snapshot_holds(service: Service, snapshot_id: str | None, files: dict[str, str]) -> bool:
    """Whether ``snapshot_id`` has each of ``files`` (paths inside the agent's folder) with
    exactly that text."""
    if snapshot_id is None:
        return False
    base = service.store.snapshots_dir / snapshot_id / "agente"
    try:
        return all((base / name).read_text() == text for name, text in files.items())
    except OSError:
        return False


def workspace_holds(service: Service, files: dict[str, str]) -> bool:
    base = service.store.workspace / "agente"
    try:
        return all((base / name).read_text() == text for name, text in files.items())
    except OSError:
        return False


def exec_in_agent(service: Service, script: str) -> str:
    """``sh -c script`` inside the agent, as the agent; it must succeed. Returns its stdout."""
    result = service.jail.exec(["sh", "-c", script], timeout=60)
    assert result.returncode == 0, (script, result.stdout, result.stderr)
    return result.stdout


def write_in_agent(service: Service, files: dict[str, str]) -> None:
    """Write ``files`` (paths inside the agent's folder) from inside the agent, through the real
    bind mount. The texts must not contain a single quote."""
    for name, text in files.items():
        path = f"/workspace/{name}"
        exec_in_agent(
            service, f"mkdir -p \"$(dirname '{path}')\" && printf '%s' '{text}' > '{path}'"
        )


MARKER = "work/marker.txt"
REWIND_WITHIN = CYCLE + 30  # a cycle, the sync, the snapshot and a loaded VM


def interrupted_rewind(service: Service, when: str) -> tuple[str, int]:
    """Start ``service`` (`backtide vigilar`), get a snapshot with ``marker = v1``, change it to
    v2, stop the service, and then rewind to the v1 snapshot in a process that is SIGKILLed
    ``when`` ("before"/"after" the swap): see ``kill_a_rewind``. Returns the target and the
    workspace id from before. The service is left stopped."""
    service.start()
    service.wait_ready()
    write_in_agent(service, {MARKER: "v1\n"})
    wait_until(
        lambda: snapshot_holds(service, service.snapshots()[-1].id, {MARKER: "v1\n"}),
        REWIND_WITHIN,
        "a snapshot with v1",
        context=service.diagnosis,
    )
    target = service.snapshots()[-1].id
    write_in_agent(service, {MARKER: "v2\n"})
    assert service.stop() == 0
    workspace_before = service.store.workspace_id()
    dead = kill_a_rewind(service, target, when)
    assert dead.returncode == -signal.SIGKILL, (dead.returncode, dead.stdout, dead.stderr[-3000:])
    assert "rewinding" in dead.stdout
    return target, workspace_before


# [budget] of the tests' services (T11): no price page, and caps no test reaches by accident.
TEST_BUDGET = "auto_prices = false\ndaily_usd = 100000\nmonthly_usd = 100000\nmax_inflight = 64\n"


def make_service(
    root: Path,
    state_dir: Path,
    names: tuple[str, str],
    *,
    cycle_interval: float = CYCLE,
    workspace_limit: int | None = None,
    proxy_toml: str = "",
    real_keys: Mapping[str, str] | None = None,
    agent_memory: str = "2g",
    budget_toml: str = TEST_BUDGET,
) -> Service:
    """Write the config and token of a service for the btrfs folder ``root`` (nothing runs
    yet). ``names`` are the container and network names, from the fixtures' cleanup scheme.

    ``proxy_toml`` goes at the end of ``[proxy]`` (``allow_hosts``, ``[[proxy.providers]]``),
    and ``real_keys`` (provider name -> a key the TEST made, never a real one) are written to
    ``<state_dir>/keys/<name>.key`` (0600, in a 0700 folder) as an installation would.

    ``budget_toml`` is the body of ``[budget]`` (T11). By default (``TEST_BUDGET``) the prices
    do not update themselves (a test never reads the real pricing page: invariant 8) and the caps
    are out of reach (the fake models are unknown, so each call is charged by excess);
    tope-de-gasto sets its own cap of cents and points ``prices_url`` at a fake page."""
    container, network = names
    token = secrets.token_urlsafe(32)
    state_dir.chmod(0o700)
    token_file = state_dir / "gateway.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    if real_keys:
        keys = state_dir / "keys"
        keys.mkdir(mode=0o700, exist_ok=True)
        for name, value in real_keys.items():
            key_file = keys / f"{name}.key"
            key_file.write_text(value + "\n")
            key_file.chmod(0o600)
    config_path = state_dir.parent / f"{state_dir.name}.toml"
    config_path.write_text(
        f'state_dir = "{state_dir}"\n'
        f'volume = "{root}"\n'
        f"cycle_interval = {cycle_interval}\n"
        + (f"workspace_limit = {workspace_limit}\n" if workspace_limit is not None else "")
        + "[budget]\n"
        + budget_toml
        + "[agent]\n"
        f'name = "{container}"\n'
        f'network = "{network}"\n'
        f"uid = {os.getuid()}\n"
        f"gid = {os.getgid()}\n"
        f'memory = "{agent_memory}"\n'
        'cpus = "2"\n'
        # The proxy's CA is group-readable by the proxy's gid: without root, only this user's.
        "[proxy]\n"
        f'name = "{container}-px"\n'  # under the cleanup's prefixes, with this run's pid
        f'network = "{network}-out"\n'
        f"uid = {os.getuid()}\n"
        f"gid = {os.getgid()}\n" + proxy_toml
    )
    config_path.chmod(0o600)
    config = ServiceConfig.from_file(config_path)
    assert isinstance(config.gateway_token, Secret)
    jail = AgentJail(replace(config.jail_config(), allow_shared_ids=True))
    store = SnapshotStore(root)
    return Service(config, config_path, jail, store, state_dir.parent / f"{state_dir.name}.log")
