"""The leak guard (tests/docker_leaks.py) with a fake Docker: what counts as a leak, what is left
alone, the order of the removal and what is reported."""

import subprocess

import pytest

from tests import docker_leaks
from tests.docker_leaks import Inventory, Item, Leaks


def item(name: str, ident: str | None = None, status: str = "") -> Item:
    return Item(ident or f"id-{name}", name, status)


def inventory(
    containers: tuple[Item, ...] = (),
    networks: tuple[Item, ...] = (),
    volumes: tuple[str, ...] = (),
) -> Inventory:
    builtin = tuple(item(name) for name in ("bridge", "host", "none"))
    return Inventory(containers, builtin + networks, volumes)


class FakeDocker:
    """Records every command; ``fail`` maps the start of a command to (exit code, stderr)."""

    def __init__(self, fail: dict[str, tuple[int, str]] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.fail = fail or {}

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(args)
        for start, (code, stderr) in self.fail.items():
            if " ".join(args).startswith(start):
                return subprocess.CompletedProcess(args, code, "", stderr)
        return subprocess.CompletedProcess(args, 0, "", "")


def test_nothing_new_is_no_leak() -> None:
    before = inventory((item("a"),), (item("net"),), ("v1",))
    assert not docker_leaks.find_leaks(before, before).any()


def test_new_containers_networks_and_volumes_are_leaks() -> None:
    before = inventory((item("a"),), volumes=("v1",))
    after = inventory(
        (item("a"), item("backtide-sensor", status="Up 3 hours")),
        (item("backtide-salida-net"),),
        ("v1", "v2"),
    )
    leaks = docker_leaks.find_leaks(before, after)
    assert [c.name for c in leaks.containers] == ["backtide-sensor"]
    assert [n.name for n in leaks.networks] == ["backtide-salida-net"]
    assert leaks.volumes == ["v2"]


def test_a_stopped_container_is_a_leak_too() -> None:
    after = inventory((item("old", status="Exited (0) 3 days ago"),))
    assert [c.name for c in docker_leaks.find_leaks(inventory(), after).containers] == ["old"]


def test_dockers_own_networks_and_the_demo_are_left_alone() -> None:
    after = inventory(
        (item("backtide-demo-agent"), item("vigia-demo-agent")),
        (item("backtide-demo-net"), item("vigia-demo-net")),
    )
    # bridge, host and none are new relative to an empty "before" with no networks at all
    leaks = docker_leaks.find_leaks(Inventory(), after)
    assert leaks.containers == [] and leaks.networks == []


def test_test_objects_of_another_live_pytest_are_left_alone_but_dead_ones_are_not() -> None:
    other = f"backtide-test-agent-{99999}-abc123"
    after = inventory((item(other),))
    alive = docker_leaks.find_leaks(inventory(), after, alive=lambda pid: pid == 99999)
    dead = docker_leaks.find_leaks(inventory(), after, alive=lambda pid: False)
    assert alive.containers == []
    assert [c.name for c in dead.containers] == [other]


def test_our_own_pids_objects_are_never_taken_for_another_run() -> None:
    import os

    name = f"backtide-test-net-{os.getpid()}-abc"
    assert not docker_leaks.is_another_run(name, alive=lambda pid: True)
    assert docker_leaks.is_another_run("backtide-test-net-1-abc", alive=lambda pid: True)
    assert not docker_leaks.is_another_run("something-else", alive=lambda pid: True)


def test_removal_goes_containers_with_volumes_then_networks_then_volumes() -> None:
    docker = FakeDocker()
    leaks = Leaks(
        containers=[item("c1", "id1"), item("c2", "id2")],
        networks=[item("n1", "nid1")],
        volumes=["vol1"],
    )

    docker_leaks.remove_leaks(leaks, docker)

    assert docker.commands == [
        ["rm", "--force", "--volumes", "id1", "id2"],
        ["network", "rm", "nid1"],
        ["volume", "rm", "vol1"],
    ]
    assert leaks.errors == []
    assert leaks.volumes == ["vol1"]  # an orphan: it is reported


def test_a_volume_that_went_with_its_container_is_no_orphan() -> None:
    docker = FakeDocker({"volume rm": (1, "Error: No such volume: vol1")})
    leaks = Leaks(containers=[item("c1")], volumes=["vol1"])

    docker_leaks.remove_leaks(leaks, docker)

    assert leaks.volumes == [] and leaks.errors == []


def test_a_volume_in_use_by_somebody_else_is_not_ours() -> None:
    docker = FakeDocker({"volume rm": (1, "volume is in use - [abc]")})
    leaks = Leaks(volumes=["vol1"])
    docker_leaks.remove_leaks(leaks, docker)
    assert leaks.volumes == [] and leaks.errors == []


def test_what_cannot_be_removed_is_reported_not_hidden() -> None:
    docker = FakeDocker({"network rm": (1, "error while removing network: active endpoints")})
    leaks = Leaks(networks=[item("n1", "nid1")])

    docker_leaks.remove_leaks(leaks, docker)

    assert leaks.any()
    assert "n1" in leaks.errors[0] and "active endpoints" in leaks.errors[0]


def test_the_report_names_every_leaked_object() -> None:
    leaks = Leaks(
        containers=[item("backtide-sensor", status="Up 3 hours")],
        networks=[item("backtide-salida-net")],
        volumes=["a" * 64],
        errors=["docker network rm x: busy"],
    )
    text = "\n".join(docker_leaks.report_lines(leaks))
    for expected in ("backtide-sensor", "Up 3 hours", "backtide-salida-net", "aaaa", "busy"):
        assert expected in text


def test_collect_takes_a_second_inventory_and_cleans_the_difference() -> None:
    class Daemon(FakeDocker):
        def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
            self.commands.append(args)
            outputs = {
                "ps": "id1\tkeep\tUp 1 hour\nid2\tleaked\tUp 2 seconds\n",
                "network": "n0\tbridge\nn1\tleaked-net\n",
                "volume": "v1\n",
            }
            if (
                args[0] in outputs
                and args[:2] != ["network", "rm"]
                and args[:2] != ["volume", "rm"]
            ):
                return subprocess.CompletedProcess(args, 0, outputs[args[0]], "")
            return subprocess.CompletedProcess(args, 0, "", "")

    docker = Daemon()
    before = Inventory(containers=(Item("id1", "keep"),), networks=(Item("n0", "bridge"),))

    leaks = docker_leaks.collect(before, docker)

    assert [c.name for c in leaks.containers] == ["leaked"]
    assert [n.name for n in leaks.networks] == ["leaked-net"]
    assert ["rm", "--force", "--volumes", "id2"] in docker.commands


def test_an_unreachable_docker_is_an_error_not_silence() -> None:
    docker = FakeDocker({"ps": (1, "Cannot connect to the Docker daemon")})
    with pytest.raises(RuntimeError, match="Cannot connect"):
        docker_leaks.take_inventory(docker)


def test_status_and_ids_survive_a_real_looking_listing() -> None:
    class Daemon(FakeDocker):
        def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
            out = {"ps": "abc\tbacktide-proxy\tUp 5 minutes (healthy)\n"}.get(args[0], "")
            return subprocess.CompletedProcess(args, 0, out, "")

    found = docker_leaks.take_inventory(Daemon())
    assert found.containers == (Item("abc", "backtide-proxy", "Up 5 minutes (healthy)"),)


# The hooks, in a pytest session of their own

HOOKS = (
    "from tests.docker_leaks import (pytest_collection_finish, pytest_sessionfinish, "
    "pytest_terminal_summary)\n"
)
VM_TEST = "import pytest\n\n@pytest.mark.integration\ndef test_vm():\n    pass\n"


@pytest.fixture
def fake_daemon(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    """A Docker whose second inventory has a leaked container."""
    docker = FakeDocker()
    inventories = iter([inventory(), inventory((item("backtide-sensor", "idx", "Up 2 hours"),))])
    monkeypatch.setattr(docker_leaks, "_docker", docker)
    monkeypatch.setattr(docker_leaks, "take_inventory", lambda *_: next(inventories))
    return docker


def test_a_session_that_leaks_fails_and_names_the_leak(
    pytester: pytest.Pytester, fake_daemon: FakeDocker
) -> None:
    pytester.makeconftest(HOOKS)
    pytester.makepyfile(VM_TEST)

    result = pytester.runpytest_inprocess("-m", "integration", "-p", "no:cacheprovider")

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*DOCKER LEAK*", "*container backtide-sensor (Up 2 hours)*"])
    assert ["rm", "--force", "--volumes", "idx"] in fake_daemon.commands


def test_a_session_that_does_not_leak_passes(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(docker_leaks, "_docker", FakeDocker())
    monkeypatch.setattr(docker_leaks, "take_inventory", lambda *_: inventory())
    pytester.makeconftest(HOOKS)
    pytester.makepyfile(VM_TEST)

    result = pytester.runpytest_inprocess("-m", "integration", "-p", "no:cacheprovider")

    assert result.ret == pytest.ExitCode.OK
    assert "DOCKER LEAK" not in result.stdout.str()


def test_a_session_with_no_vm_test_never_touches_docker(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: object) -> Inventory:
        raise AssertionError("a unit test session must not call docker")

    monkeypatch.setattr(docker_leaks, "take_inventory", refuse)
    pytester.makeconftest(HOOKS)
    pytester.makepyfile("def test_unit():\n    pass\n")

    assert pytester.runpytest_inprocess("-p", "no:cacheprovider").ret == pytest.ExitCode.OK


def test_a_docker_that_does_not_answer_fails_the_session(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> Inventory:
        raise RuntimeError("docker ps failed (1): daemon down")

    monkeypatch.setattr(docker_leaks, "take_inventory", broken)
    pytester.makeconftest(HOOKS)
    pytester.makepyfile(VM_TEST)

    result = pytester.runpytest_inprocess("-m", "integration", "-p", "no:cacheprovider")

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*DOCKER LEAK GUARD*daemon down*"])
