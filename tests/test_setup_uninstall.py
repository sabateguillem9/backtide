"""`backtide desinstalar` (T13-4; docs/25, section 5), on the Mac with the installer's fake machine.

Every test installs first, with the same fake machine as tests/test_setup_install.py (real files
under a temporary folder, a fake Docker, systemd and accounts), and then uninstalls.
"""

import json
import os
from pathlib import Path

import pytest

from backtide.setup import images, layout, manifest, units
from backtide.setup.install import SAVED_CONFIG
from backtide.setup.uninstall import Options, Uninstaller, UninstallError
from tests.test_setup_install import (
    DOCKER_FPR,
    UBUNTU,
    Machine,
    Prompter,
    changes,
    docker_id,
    installer,
    new_machine,
)

HOST = "servidor-de-prueba"


class Answering(Prompter):
    """The installer's Prompter, plus the typed answer the uninstaller asks for."""

    def __init__(self, *, typed: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.typed = typed

    def answer(self, question: str) -> str:
        self.asked.append(question)
        return self.typed


def remover(machine: Machine, prompter: Prompter | None = None, **options) -> Uninstaller:
    return Uninstaller(
        host=machine,
        run=machine.run,
        prompter=prompter or Answering(),
        options=Options(**{"yes": True, **options}),
        paths=machine.paths,
        owner=(os.getuid(), os.getgid()),
        hostname=HOST,
    )


def said(prompter: Prompter) -> str:
    return "\n".join(prompter.said)


@pytest.fixture
def machine(tmp_path: Path) -> Machine:
    built = new_machine(tmp_path / "machine")
    installer(built, no_key=True).install()
    key = built.paths.keys_dir / "anthropic.key"
    key.write_text("sk-ant-api03-made-up\n")  # as the Settings page would leave it
    key.chmod(0o600)
    return built


CHANGING = ("systemctl", "docker", "userdel", "groupdel", "dnf", "env", "rpmkeys", "rpm")


def changing(calls: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    looks = {("docker", "--version"), ("docker", "ps", "--all", "--quiet")}
    return [
        argv
        for argv in calls
        if argv[0] in CHANGING
        and argv[:2] not in (("docker", "info"), ("systemctl", "is-active"))
        and "inspect" not in argv
        and argv not in looks
    ]


# The default: everything but the data


def test_the_default_removes_backtide_and_keeps_the_data(machine: Machine) -> None:
    p = machine.paths
    image_inode = os.lstat(p.volume_image).st_ino
    key_bytes = (p.state_dir / "blackbox.key").read_bytes()
    prompter = Answering()
    assert remover(machine, prompter).uninstall()
    for gone in (p.config_dir, p.opt_dir, p.bin_link, p.volume_mount, p.daemon_json,
                 *(p.unit_dir / name for name in units.render_units())):  # fmt: skip
        assert not os.path.lexists(gone), gone
    assert machine.containers == {} and machine.networks == {} and machine.images == set()
    assert machine.users == {} and machine.groups == set()
    assert not machine.mounted and not machine.channel_mounted
    # The data: the black box and its key, the volume (same file), the keys, the config's copy.
    assert (p.state_dir / "blackbox.key").read_bytes() == key_bytes
    assert (p.state_dir / "blackbox.db").exists()
    assert os.lstat(p.volume_image).st_ino == image_inode
    assert (p.keys_dir / "anthropic.key").exists()
    assert (p.state_dir / SAVED_CONFIG).exists()
    assert oct(os.lstat(p.state_dir / SAVED_CONFIG).st_mode & 0o777) == "0o600"
    left = manifest.load(p.manifest)
    assert left.created["units"] == [] and left.created["images"] == []
    assert left.created["users"] == [] and left.created["networks"] == []
    assert "containers" not in left.facts and "daemon_json" not in left.facts
    text = said(prompter)
    assert str(p.state_dir) in text and "volver a instalar" in text
    assert "Docker se queda" in text


def test_the_agent_is_stopped_before_anything_else(machine: Machine) -> None:
    machine.calls.clear()
    remover(machine).uninstall()
    first = changing(machine.calls)[0]
    assert first == ("systemctl", "stop", layout.SERVICE_UNIT)
    stop_agent = machine.calls.index(
        ("docker", "stop", "--time", "30", docker_id("backtide-agente"))
    )
    assert stop_agent < next(i for i, a in enumerate(machine.calls) if a[:2] == ("docker", "rm"))
    disable = [a for a in machine.calls if a[:3] == ("systemctl", "disable", "--now")]
    assert [a[3] for a in disable][:2] == [layout.SERVICE_UNIT, layout.WEB_UNIT]


def test_a_second_run_says_there_is_nothing_to_remove(machine: Machine) -> None:
    remover(machine).uninstall()
    machine.calls.clear()
    prompter = Answering()
    assert remover(machine, prompter).uninstall() is False
    assert "No queda nada de backtide que quitar" in said(prompter)
    assert changing(machine.calls) == []


def test_installing_again_carries_on_with_the_data(machine: Machine) -> None:
    p = machine.paths
    config = p.config_file.read_text().replace("daily_usd = 5", "daily_usd = 7")
    p.config_file.write_text(config)
    key_bytes = (p.state_dir / "blackbox.key").read_bytes()
    image_inode = os.lstat(p.volume_image).st_ino
    remover(machine).uninstall()
    p.program.parent.mkdir(parents=True)  # install.sh puts the program back
    p.program.write_text("#!/bin/sh\n")
    machine.calls.clear()
    prompter = Prompter()
    installer(machine, prompter, no_key=True).install()
    assert (p.state_dir / "blackbox.key").read_bytes() == key_bytes
    assert os.lstat(p.volume_image).st_ino == image_inode
    assert not [a for a in machine.calls if a[0] == "mkfs.btrfs" and "--version" not in a]
    assert "daily_usd = 7" in p.config_file.read_text()  # the person's config came back
    assert not (p.state_dir / SAVED_CONFIG).exists()
    assert set(machine.containers) == {"backtide-agente", "backtide-egress", "backtide-sensor"}
    # And it can be uninstalled again, as fully as the first time.
    remover(machine).uninstall()
    assert machine.containers == {} and machine.images == set() and machine.users == {}


def test_an_uninstall_cut_at_any_step_goes_on_from_there(tmp_path: Path) -> None:
    for number, prefix in enumerate(
        [
            ("systemctl", "disable"),
            ("docker", "rm"),
            ("systemctl", "restart", "docker.service"),
            ("userdel",),
        ]
    ):
        machine = new_machine(tmp_path / f"m{number}")
        installer(machine, no_key=True).install()
        machine.fail[prefix] = 1
        with pytest.raises(UninstallError):
            remover(machine).uninstall()
        assert remover(machine).uninstall(), prefix
        assert machine.containers == {} and machine.users == {} and machine.networks == {}
        assert not machine.paths.opt_dir.exists() and not machine.paths.config_dir.exists()
        assert machine.paths.volume_image.exists()


# --borrar-datos


def test_erasing_the_data_asks_for_the_machines_name(machine: Machine) -> None:
    for typed in ("", "otra-maquina", "backtide"):
        prompter = Answering(interactive=True, typed=typed)
        with pytest.raises(UninstallError, match="no coincide"):
            remover(machine, prompter, yes=False, erase_data=True).uninstall()
        assert HOST in prompter.asked[-1]
    assert machine.paths.state_dir.exists() and machine.paths.opt_dir.exists()
    assert set(machine.containers) == {"backtide-agente", "backtide-egress", "backtide-sensor"}
    prompter = Answering(interactive=True, typed=HOST)
    remover(machine, prompter, yes=False, erase_data=True).uninstall()
    assert not machine.paths.state_dir.exists()
    assert not machine.paths.volume_image.exists()
    assert "para siempre" in said(prompter)


def test_erasing_after_a_default_uninstall_removes_what_was_kept(machine: Machine) -> None:
    remover(machine).uninstall()
    prompter = Answering()
    assert remover(machine, prompter, erase_data=True).uninstall()
    assert not machine.paths.state_dir.exists()
    assert "No está" in "\n".join(_run_again(machine))


def _run_again(machine: Machine) -> list[str]:
    prompter = Answering()
    assert remover(machine, prompter).uninstall() is False
    return prompter.said


def test_erasing_everything_at_once(machine: Machine) -> None:
    remover(machine, erase_data=True).uninstall()
    root = machine.root
    left = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    print(left)
    # Only the folders a fresh machine already had (and Docker's, which stays).
    assert not any("backtide" in name for name in left if "docker" not in name), left


def test_erasing_never_deletes_a_volume_that_is_still_mounted(machine: Machine) -> None:
    machine.fail[("systemctl", "disable", "--now", units.volume_unit_name())] = 1
    with pytest.raises(UninstallError):
        remover(machine, erase_data=True).uninstall()
    assert machine.mounted and machine.paths.volume_image.exists()
    assert machine.paths.state_dir.exists()


# Safety


def test_a_manifest_others_could_write_is_refused(machine: Machine) -> None:
    machine.paths.manifest.chmod(0o644)
    machine.calls.clear()
    with pytest.raises(UninstallError, match="manifiesto"):
        remover(machine).uninstall()
    assert changing(machine.calls) == []
    assert set(machine.containers) == {"backtide-agente", "backtide-egress", "backtide-sensor"}


def test_a_manifest_that_is_a_link_is_refused(machine: Machine, tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    real.write_bytes(machine.paths.manifest.read_bytes())
    real.chmod(0o600)
    machine.paths.manifest.unlink()
    machine.paths.manifest.symlink_to(real)
    with pytest.raises(UninstallError, match="manifiesto"):
        remover(machine).uninstall()
    assert machine.paths.opt_dir.exists()


def test_a_state_folder_others_can_write_is_refused(machine: Machine) -> None:
    machine.paths.state_dir.chmod(0o777)
    try:
        with pytest.raises(UninstallError, match="lo pueden escribir otros"):
            remover(machine).uninstall()
    finally:
        machine.paths.state_dir.chmod(0o710)
    assert machine.paths.opt_dir.exists()


def test_a_path_outside_backtides_folders_is_never_removed(machine: Machine) -> None:
    """A manifest is root's, but a bug or a hand edit could still name /etc/passwd."""
    victim = machine.root / "etc" / "passwd"
    victim.write_text("root:x:0:0::/root:/bin/sh\n")
    outside = machine.root / "home" / "someone"
    outside.mkdir(parents=True)
    data = json.loads(machine.paths.manifest.read_text())
    data["created"]["files"] += [str(victim), str(machine.paths.config_dir / ".." / "passwd")]
    data["created"]["dirs"].append(str(outside))
    machine.paths.manifest.write_text(json.dumps(data))
    prompter = Answering()
    remover(machine, prompter, erase_data=True).uninstall()
    assert victim.exists() and outside.exists()
    assert "no es una ruta de backtide" in said(prompter)


def test_a_container_without_backtides_label_is_left_alone(machine: Machine) -> None:
    machine.containers["backtide-agente"] = {"com.example": "mine"}  # someone's, same name
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert machine.containers == {"backtide-agente": {"com.example": "mine"}}
    assert "no lleva la etiqueta de backtide" in said(prompter)
    agent = docker_id("backtide-agente")
    touched = [a for a in machine.calls if a[:2] in (("docker", "rm"), ("docker", "stop"))]
    assert touched and all(a[-1] != agent for a in touched)  # the other two went, by their IDs
    assert said(prompter).count("el contenedor backtide-agente:") == 1  # said once, in stop()


def test_a_network_without_backtides_label_is_left_alone(machine: Machine) -> None:
    machine.network_labels["backtide-salida-net"] = {}
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert set(machine.networks) == {"backtide-salida-net"}
    assert "backtide-salida-net" in manifest.load(machine.paths.manifest).created["networks"]


def test_a_network_in_use_is_left_and_the_next_run_removes_it(machine: Machine) -> None:
    machine.busy_networks.add("backtide-agente-net")
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert "backtide-agente-net" in machine.networks
    assert "Queda sin quitar" in said(prompter)
    machine.busy_networks.clear()
    remover(machine).uninstall()
    assert machine.networks == {}


def test_claude_codes_image_is_the_one_removed(machine: Machine, tmp_path: Path) -> None:
    """D27: an install with --perfil claude-code pulled Claude Code's image; uninstalling takes
    that one (and says its size), and never OpenClaw's, which it did not pull."""
    other = new_machine(tmp_path / "other")
    openclaw = images.AGENTS["openclaw"].ref
    other.images.add(openclaw)  # someone's own, there before
    installer(other, no_key=True, profile="claude-code").install()
    assert images.AGENTS["claude-code"].ref in other.images
    prompter = Answering()
    remover(other, prompter).uninstall()
    assert other.images == {openclaw}
    assert "unos 3,4 GiB" in said(prompter)


def test_an_image_of_someone_else_is_never_removed(machine: Machine, tmp_path: Path) -> None:
    other = new_machine(tmp_path / "other")
    pinned = images.pinned()
    other.images.add(pinned[0].ref)  # OpenClaw's was there before backtide
    installer(other, no_key=True).install()
    remover(other).uninstall()
    assert other.images == {pinned[0].ref}


def test_nothing_changes_without_permission(machine: Machine) -> None:
    machine.calls.clear()
    with pytest.raises(UninstallError, match="--si"):
        remover(machine, Answering(interactive=False), yes=False).uninstall()
    with pytest.raises(UninstallError, match="permiso"):
        remover(machine, Answering(interactive=True, answers=False), yes=False).uninstall()
    assert changing(machine.calls) == []


def test_dry_run_changes_nothing(machine: Machine) -> None:
    machine.calls.clear()
    prompter = Answering()
    remover(machine, prompter, dry_run=True, erase_data=True).uninstall()
    assert changing(machine.calls) == []
    assert machine.paths.opt_dir.exists() and machine.paths.state_dir.exists()
    assert "PARA SIEMPRE" in said(prompter)


def test_the_persons_own_files_in_etc_backtide_stay(machine: Machine) -> None:
    prices = machine.paths.config_dir / "prices.toml"
    prices.write_text("# mine\n")
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert prices.exists() and not machine.paths.config_file.exists()
    assert "prices.toml" in said(prompter)


def test_the_black_box_is_given_roots_group_before_the_web_user_goes(machine: Machine) -> None:
    """The kept black box is 0640 with backtide-web's group: once the group is gone, a new one
    could get its number and read it. It goes to root's group first."""
    others = [g for g in os.getgroups() if g != os.getgid()]
    if not others:
        pytest.skip("the tests' user has a single group")
    m = remover(machine)
    m.owner = (os.getuid(), others[0])  # "root's group", different from the web's stand-in
    m.uninstall()
    for path in (machine.paths.state_dir, machine.paths.blackbox_db):
        assert os.lstat(path).st_gid == others[0], path
    assert machine.calls.index(("userdel", layout.WEB_USER)) > 0


# Docker


def test_docker_settings_go_back_as_they_were(tmp_path: Path) -> None:
    """A daemon.json the person had: their settings stay; the two backtide set go back to their
    values (live-restore false), with selinux-enabled first (a restart, live-restore still on)
    and live-restore last (a reload)."""
    machine = new_machine(tmp_path / "m")
    machine.docker = True
    daemon = machine.paths.daemon_json
    daemon.parent.mkdir(parents=True)
    daemon.write_text('{"log-driver": "journald", "live-restore": false}\n')
    installer(machine, no_key=True).install()
    settings = json.loads(daemon.read_text())
    assert settings["selinux-enabled"] is True and settings["live-restore"] is True
    settings["max-concurrent-downloads"] = 2  # the person's, added since
    daemon.write_text(json.dumps(settings))
    machine.calls.clear()
    remover(machine).uninstall()
    assert json.loads(daemon.read_text()) == {
        "log-driver": "journald",
        "live-restore": False,
        "max-concurrent-downloads": 2,
    }
    restart = machine.calls.index(("systemctl", "restart", "docker.service"))
    reload = machine.calls.index(("systemctl", "reload", "docker.service"))
    assert restart < reload
    assert not (machine.paths.state_dir / "docker-daemon.json.antes").exists()


def test_a_daemon_json_backtide_made_keeps_what_the_person_added(machine: Machine) -> None:
    daemon = machine.paths.daemon_json
    settings = json.loads(daemon.read_text())
    daemon.write_text(json.dumps({**settings, "max-concurrent-downloads": 2}))
    remover(machine).uninstall()
    assert json.loads(daemon.read_text()) == {"max-concurrent-downloads": 2}
    prompter = Answering()
    assert remover(machine, prompter).uninstall() is False  # theirs now: nothing left to do
    assert daemon.exists()


def test_a_busy_volume_stops_the_uninstall_and_says_why(machine: Machine) -> None:
    machine.fail[("systemctl", "disable", "--now", units.volume_unit_name())] = 1
    with pytest.raises(UninstallError, match="algo lo está usando"):
        remover(machine).uninstall()
    assert machine.paths.opt_dir.exists() and machine.paths.bin_link.is_symlink()
    assert machine.calls.index(("systemctl", "stop", layout.SERVICE_UNIT)) < machine.calls.index(
        ("systemctl", "disable", "--now", units.volume_unit_name())
    )  # the agent was stopped first anyway
    assert remover(machine).uninstall()
    assert not machine.paths.opt_dir.exists()


def test_a_daemon_json_backtide_made_goes(machine: Machine) -> None:
    assert machine.paths.daemon_json.exists()
    remover(machine).uninstall()
    assert not machine.paths.daemon_json.exists()


def test_docker_stays_unless_asked(machine: Machine) -> None:
    remover(machine).uninstall()
    assert machine.docker
    assert machine.paths.dnf_repo.exists() and machine.paths.rpm_key.exists()
    assert not any(argv[:3] == ("dnf", "-y", "remove") for argv in machine.calls)


def test_quitar_docker_removes_docker_its_repository_and_its_key(machine: Machine) -> None:
    prompter = Answering()
    remover(machine, prompter, remove_docker=True).uninstall()
    assert not machine.docker
    remove = ("dnf", "-y", "remove", "docker-ce", "docker-ce-cli", "containerd.io")
    assert (*remove, "docker-buildx-plugin") in machine.calls
    assert ("rpmkeys", "--delete", DOCKER_FPR["fedora"]) in machine.calls
    assert not machine.paths.dnf_repo.exists() and not machine.paths.rpm_key.exists()


def test_quitar_docker_on_ubuntu(tmp_path: Path) -> None:
    machine = new_machine(tmp_path / "m")
    machine.distro, machine.selinux = UBUNTU, False
    installer(machine, no_key=True).install()
    remover(machine, remove_docker=True).uninstall()
    assert not machine.docker
    assert not machine.paths.apt_source.exists() and not machine.paths.apt_keyring.exists()


def test_docker_with_other_containers_is_never_removed(machine: Machine) -> None:
    machine.containers["web-de-alguien"] = {}
    prompter = Answering()
    remover(machine, prompter, remove_docker=True).uninstall()
    assert machine.docker and machine.paths.dnf_repo.exists()
    assert "no son de backtide" in said(prompter)
    assert "web-de-alguien" in machine.containers


def test_a_docker_that_was_there_is_never_removed(tmp_path: Path) -> None:
    machine = new_machine(tmp_path / "m")
    machine.docker = machine.docker_selinux = True
    installer(machine, no_key=True).install()
    prompter = Answering()
    remover(machine, prompter, remove_docker=True).uninstall()
    assert machine.docker
    assert not any(argv[:2] == ("dnf", "-y") and "remove" in argv for argv in machine.calls)
    assert "no lo instaló esta instalación de backtide" in said(prompter)


def test_the_installer_never_removes_a_container_without_the_label(
    machine: Machine, tmp_path: Path
) -> None:
    """T13-3's review: on a version change, `docker rm --force` by name only if it is ours."""
    first = installer(machine, no_key=True)
    first.release = tmp_path / "releases/0.1.0-aaaaaaaaaaaa"
    first.install()
    machine.containers["backtide-egress"] = {}
    newer = installer(machine, no_key=True)
    newer.release = tmp_path / "releases/0.2.0-cccccccccccc"
    from backtide.setup.install import InstallError

    with pytest.raises(InstallError, match="no lleva la etiqueta"):
        newer.install()
    assert "backtide-egress" in machine.containers
    assert ("docker", "rm", "--force", docker_id("backtide-egress")) not in machine.calls


def test_no_uninstall_changes_happen_through_a_link_in_its_folders(machine: Machine) -> None:
    """/etc/backtide replaced by a link to somewhere else: nothing there is removed."""
    elsewhere = machine.root / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "backtide.toml").write_text("keep\n")
    import shutil

    shutil.rmtree(machine.paths.config_dir)
    machine.paths.config_dir.symlink_to(elsewhere)
    with pytest.raises(UninstallError, match="sin seguir enlaces|no es una carpeta"):
        remover(machine).uninstall()
    assert (elsewhere / "backtide.toml").read_text() == "keep\n"


def test_changes_are_only_the_uninstallers(machine: Machine) -> None:
    """Sanity: the installer's own `changes` sees no install command in an uninstall."""
    machine.calls.clear()
    remover(machine).uninstall()
    assert not any(argv[0] in ("useradd", "mkfs.btrfs") for argv in changes(machine.calls))


# The review of T13-4 (revisor-seguridad R, guardian-invariantes G)


def test_quitar_docker_never_removes_a_docker_that_does_not_answer(machine: Machine) -> None:
    """R2: `docker ps` failing is no proof there is nothing else on it."""
    machine.fail[("docker", "ps", "--all", "--quiet")] = 5
    prompter = Answering()
    remover(machine, prompter, remove_docker=True).uninstall()
    assert machine.docker and machine.paths.dnf_repo.exists()
    assert not any(argv[:3] == ("dnf", "-y", "remove") for argv in machine.calls)
    assert "no responde" in said(prompter)


def test_quitar_docker_never_removes_docker_without_its_command(machine: Machine) -> None:
    machine.docker = False  # `docker --version` finds nothing, the packages may still be there
    prompter = Answering()
    remover(machine, prompter, remove_docker=True).uninstall()
    assert not any(argv[:3] == ("dnf", "-y", "remove") for argv in machine.calls)
    assert machine.paths.dnf_repo.exists() and "no responde" in said(prompter)


def test_a_cut_after_the_config_still_leaves_the_command_to_run_again(machine: Machine) -> None:
    """R4: the command and the program go last, so a run that stops can be run again."""
    machine.fail[("userdel",)] = 1
    with pytest.raises(UninstallError):
        remover(machine).uninstall()
    assert machine.paths.bin_link.is_symlink() and machine.paths.opt_dir.exists()
    assert not machine.paths.config_dir.exists()
    assert remover(machine).uninstall()
    assert not machine.paths.bin_link.is_symlink()


def test_the_group_goes_after_its_user_and_only_when_nobody_holds_it(machine: Machine) -> None:
    """R5 + G6: userdel first; groupdel only once no account has it as its primary group."""
    machine.usergroups = False  # a userdel that leaves the user's group behind
    remover(machine).uninstall()
    userdel = machine.calls.index(("userdel", layout.WEB_USER))
    groupdel = machine.calls.index(("groupdel", layout.WEB_USER))
    assert userdel < groupdel
    assert machine.groupdels == [(layout.WEB_USER, [])]  # nobody had gid 990 at that moment


def test_a_group_someone_else_still_uses_is_left(machine: Machine) -> None:
    machine.usergroups = False
    machine.users["alguien"] = 1000
    machine.primary_gid["alguien"] = 990  # backtide-web's gid as their primary group
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert ("groupdel", layout.WEB_USER) not in machine.calls
    assert layout.WEB_USER in machine.groups and "alguien" in machine.users
    assert "grupo principal de alguien" in said(prompter)


def test_a_group_whose_user_was_left_is_left(machine: Machine) -> None:
    machine.usergroups = False
    machine.fail[("userdel",)] = 1  # cut at userdel: the next run removes both, in order
    with pytest.raises(UninstallError):
        remover(machine).uninstall()
    assert ("groupdel", layout.WEB_USER) not in machine.calls
    remover(machine).uninstall()
    assert machine.users == {} and machine.groups == set()


def test_only_backtides_own_units_and_account_are_ever_touched(machine: Machine) -> None:
    """G3: by exact name. sshd.service in the manifest is never stopped; `nobody` (nologin and
    /nonexistent, like backtide-web) is never deleted."""
    data = json.loads(machine.paths.manifest.read_text())
    data["created"]["units"].append("sshd.service")
    data["created"]["users"].append("nobody")
    data["created"]["groups"].append("nobody")
    machine.paths.manifest.write_text(json.dumps(data))
    machine.users["nobody"] = 65534
    machine.groups.add("nobody")
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert not [argv for argv in machine.calls if "sshd.service" in argv]
    assert not [argv for argv in machine.calls if argv[-1] == "nobody"]
    assert "nobody" in machine.users and "nobody" in machine.groups
    text = said(prompter)
    assert "sshd.service: no es de backtide" in text and "usuario nobody" in text


def test_a_dotdot_path_is_never_removed_in_the_default_mode(machine: Machine) -> None:
    """G2: /etc/backtide/../passwd is under /etc/backtide only as text."""
    victim = machine.root / "etc" / "passwd"
    victim.write_text("root:x:0:0::/root:/bin/sh\n")
    sneaky = f"{machine.paths.config_dir}/../passwd"
    data = json.loads(machine.paths.manifest.read_text())
    data["created"]["files"].append(sneaky)
    machine.paths.manifest.write_text(json.dumps(data))
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert victim.read_text() == "root:x:0:0::/root:/bin/sh\n"
    assert f"{sneaky}: está en el manifiesto pero no es una ruta de backtide" in said(prompter)


@pytest.mark.parametrize("where", ["opt", "state"])
def test_nothing_is_deleted_with_something_mounted_under_it(machine: Machine, where: str) -> None:
    """G1: a bind mount of the agent's volume (here, a witness folder) under /opt/backtide, or
    under /var/lib/backtide with --borrar-datos: nothing changes, not even the agent stops."""
    folder = machine.paths.opt_dir if where == "opt" else machine.paths.state_dir
    eco = folder / "eco"
    eco.mkdir()
    witness = eco / "trabajo-del-agente.txt"
    witness.write_text("no se borra\n")
    machine.extra_mounts.append(eco)
    machine.calls.clear()
    with pytest.raises(UninstallError, match="hay algo montado"):
        remover(machine, erase_data=where == "state").uninstall()
    assert witness.read_text() == "no se borra\n"
    assert changing(machine.calls) == []
    assert machine.paths.bin_link.is_symlink() and machine.paths.config_dir.exists()


def test_a_mount_under_the_state_is_fine_when_the_data_is_kept(machine: Machine) -> None:
    eco = machine.paths.state_dir / "eco"
    eco.mkdir()
    machine.extra_mounts.append(eco)
    assert remover(machine).uninstall()
    assert eco.exists() and not machine.paths.opt_dir.exists()


def test_an_unreadable_mountinfo_stops_before_anything(machine: Machine) -> None:
    machine.mountinfo_readable = False
    machine.calls.clear()
    with pytest.raises(UninstallError, match="mountinfo"):
        remover(machine, erase_data=True).uninstall()
    assert changing(machine.calls) == []
    assert machine.paths.state_dir.exists() and machine.paths.opt_dir.exists()


def test_an_old_manifest_without_the_containers_still_finds_them(machine: Machine) -> None:
    """R6: a manifest from before T13-4 did not list the containers: this version's names are
    looked at, and one of them without the label is said, not removed."""
    data = json.loads(machine.paths.manifest.read_text())
    del data["facts"]["containers"]
    machine.paths.manifest.write_text(json.dumps(data))
    machine.containers["backtide-sensor"] = {}  # someone's busybox with that name
    prompter = Answering()
    remover(machine, prompter).uninstall()
    assert machine.containers == {"backtide-sensor": {}}
    assert "el contenedor backtide-sensor: no lleva la etiqueta" in said(prompter)


def test_daemon_json_keeps_its_mode_on_install_and_uninstall(tmp_path: Path) -> None:
    """R8: an existing daemon.json of 0600 is never opened to 0644; at most 0644."""
    machine = new_machine(tmp_path / "m")
    machine.docker = True
    daemon = machine.paths.daemon_json
    daemon.parent.mkdir(parents=True)
    daemon.write_text('{"log-driver": "journald"}\n')
    daemon.chmod(0o600)
    installer(machine, no_key=True).install()
    assert json.loads(daemon.read_text())["selinux-enabled"] is True
    assert oct(daemon.stat().st_mode & 0o777) == "0o600"
    remover(machine).uninstall()
    assert json.loads(daemon.read_text()) == {"log-driver": "journald"}
    assert oct(daemon.stat().st_mode & 0o777) == "0o600"


def test_erasing_takes_all_of_etc_backtide_with_it(machine: Machine) -> None:
    """G4: with --borrar-datos, /etc/backtide goes whole, a prices.toml of yours included (the
    guide says so); without it, that file stays."""
    prices = machine.paths.config_dir / "prices.toml"
    prices.write_text("# mine\n")
    remover(machine, erase_data=True).uninstall()
    assert not machine.paths.config_dir.exists()
    guide = (Path(__file__).parents[1] / "docs" / "guide" / "cli-reference.md").read_text()
    assert "`/etc/backtide` goes whole, your own `prices.toml` included" in guide
