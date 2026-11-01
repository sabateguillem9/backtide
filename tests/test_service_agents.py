"""Several agents' configuration (T26-2a, docs/47 sections 6.2, 6.3 and 6.8).

Nothing here runs two agents (T26-2b does): this is what each agent is called, where its files
live, what `agents/<slug>.toml` may say, and above all that an installation made before all this
reads and starts exactly as it did: same paths, same names, same ids, same black box.
"""

import dataclasses
import os
import shutil
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, BlackBoxError, load_key
from backtide.jail import AgentJail
from backtide.jail import identity as who
from backtide.notify import Alert, AlertLevel
from backtide.service.agents import MAX_AGENTS, Installation, load_installation
from backtide.service.config import ConfigError, ServiceConfig, ensure_state_folder
from backtide.service.runner import (
    open_black_box,
    open_installation_box,
    record_installation_start,
    serve,
)
from backtide.setup import layout as setup_layout
from backtide.web import agents as web_agents
from tests.test_blackbox_tamper import tamper

TOKEN = "T0kenForTestsOnly_" + "a1B2c3D4e5F6g7H8i9J0" * 2
OTHER_TOKEN = "Another0Token_" + "Z9y8X7w6V5u4T3s2R1q0" * 2
REAL_KEY = "sk-test-made-up-anthropic-key-0123456789"
PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A machine of today: ``state/`` (0700) with its token, ``volume/`` and ``etc/backtide.toml``,
    and no ``agents`` anywhere."""
    (tmp_path / "state").mkdir(mode=0o700)
    (tmp_path / "volume").mkdir()
    (tmp_path / "etc").mkdir(mode=0o755)
    private(tmp_path / "state" / "gateway.token", TOKEN + "\n")
    write_main(tmp_path)
    return tmp_path


def private(path: Path, text: str, mode: int = 0o600) -> None:
    path.write_text(text)
    path.chmod(mode)


def write_main(home: Path, extra: str = "", *, provider: bool = True) -> Path:
    path = home / "etc" / "backtide.toml"
    private(
        path,
        f'state_dir = "{home / "state"}"\nvolume = "{home / "volume"}"\n{extra}'
        + (PROVIDER if provider else ""),
    )
    return path


def add_agent(home: Path, slug: str, text: str | None = None, *, number: int = 1) -> Path:
    """``etc/agents/<slug>.toml``, a Claude Code on its own volume unless ``text`` says else."""
    folder = home / "etc" / "agents"
    folder.mkdir(mode=0o755, exist_ok=True)
    path = folder / f"{slug}.toml"
    if text is None:
        text = claude_code(home, slug, number)
    private(path, text)
    return path


def claude_code(home: Path, slug: str, number: int, extra: str = "") -> str:
    return (
        f'number = {number}\nname = "Revisor {number}"\n'
        f'volume = "{home / "agent-volumes" / slug}"\n{extra}\n'
        '[agent]\nprofile = "claude-code"\n'
    )


def main_config(home: Path) -> Path:
    return home / "etc" / "backtide.toml"


def everything_in(folder: Path) -> list[str]:
    return sorted(str(p.relative_to(folder)) for p in folder.rglob("*"))


# --- the slug: its one rule, and it can never leave its folder ------------------------------------


@pytest.mark.parametrize(
    "slug",
    [
        "..",
        ".",
        "../x",
        "a/b",
        "/etc",
        "a\\b",
        "A",
        "Revisor",
        "-a",
        "a-",
        "a_b",
        "a.b",
        "a b",
        "",
        "a" * 33,
        "a\n",
        "a\x00b",
        "ñu",
        "١",  # an Arabic digit: \d would take it
        None,
        7,
        b"revisor",
    ],
)
def test_a_slug_outside_the_rule_is_refused(slug: object) -> None:
    with pytest.raises(who.SlugError):
        who.check_slug(slug)


@pytest.mark.parametrize("slug", ["a", "7", "revisor", "a-b", "a--b", "a" * 32, "0x"])
def test_a_slug_inside_the_rule_passes(slug: str) -> None:
    assert who.check_slug(slug) == slug


@pytest.mark.parametrize("slug", sorted(who.RESERVED_SLUGS))
def test_a_reserved_name_is_never_an_agents_slug(slug: str) -> None:
    assert who.SLUG.fullmatch(slug)  # a good shape: it is the list that stops it
    with pytest.raises(who.SlugError, match="reserved"):
        who.check_slug(slug)


def test_the_slugs_that_would_take_the_main_agents_docker_names_are_reserved() -> None:
    """``agente`` would get ``backtide-agente-net`` and ``salida`` ``backtide-salida-net``, the
    networks of every installation of today."""
    main = {"backtide-agente", "backtide-egress", "backtide-sensor",
            "backtide-agente-net", "backtide-salida-net"}  # fmt: skip
    for slug in ("agente", "salida"):
        assert who.agent_network(slug) in main or who.egress_network(slug) in main
        assert slug in who.RESERVED_SLUGS
    for slug in ("revisor", "net", "egress", "sensor"):
        taken = {who.agent_container(slug), who.proxy_container(slug),
                 who.agent_network(slug), who.egress_network(slug)}  # fmt: skip
        assert not taken & main


def test_the_web_uses_the_same_rule_for_a_slug() -> None:
    assert web_agents.SLUG is who.SLUG
    assert web_agents.MAIN_SLUG == who.MAIN_SLUG == "principal"
    assert web_agents.MAX_NAME == who.MAX_NAME


# --- the number: the ids ------------------------------------------------------------------------


def test_each_number_has_ids_of_its_own_and_none_of_the_main_agents() -> None:
    assert who.agent_id(1) == 61101
    assert who.proxy_id(1) == 61201
    ids = [i for n in range(1, who.MAX_NUMBER + 1) for i in (who.agent_id(n), who.proxy_id(n))]
    assert len(set(ids)) == len(ids)
    assert all(i in who.AGENT_ID_RANGE for i in ids)
    assert 61000 not in who.AGENT_ID_RANGE and 61001 not in who.AGENT_ID_RANGE


# --- an installation of before: exactly what it was -----------------------------------------------


def test_an_installation_of_before_keeps_every_path_name_and_id(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    state, volume = home / "state", home / "volume"
    assert config.slug == "principal" and config.number == 0
    assert config.agent_dir == state
    assert config.blackbox_db == state / "blackbox.db"
    assert config.blackbox_key == state / "blackbox.key"
    assert config.blackbox_checkpoint == state / "blackbox.checkpoint"
    assert config.gateway_token_file == state / "gateway.token"
    assert config.agent_config_dir == state / "openclaw"
    assert config.pending_file == state / "rewind.pending"
    assert config.proxy_ca_dir == state / "proxy-ca"
    assert config.agent_ca_dir == state / "agent-ca"
    assert config.proxy_channel_dir == state / "proxy-channel"
    assert config.keys_dir == state / "keys"
    assert config.sensor_dir == state / "sensor"
    assert config.control_socket == state / "control.sock"
    assert config.lock_file == state / "backtide.lock"
    assert config.workspace == volume / "workspace"
    jail, proxy = config.jail_config(), config.proxy_jail_config()
    assert (jail.name, jail.network, jail.uid, jail.gid) == (
        "backtide-agente", "backtide-agente-net", 61000, 61000,
    )  # fmt: skip
    assert (proxy.name, proxy.network, proxy.agent_network, proxy.uid, proxy.gid) == (
        "backtide-egress", "backtide-salida-net", "backtide-agente-net", 61001, 61001,
    )  # fmt: skip
    assert (proxy.agent_uid, proxy.agent_gid) == (61000, 61000)
    assert config.sensor_jail_config().name == "backtide-sensor"


def test_a_main_agent_with_its_own_names_keeps_them(home: Path) -> None:
    """Whatever a backtide.toml of before says of its containers still holds."""
    write_main(home, '[agent]\nname = "mio"\nnetwork = "mi-red"\nuid = 62000\ngid = 62000\n')
    jail = ServiceConfig.from_file(main_config(home)).jail_config()
    assert (jail.name, jail.network, jail.uid, jail.gid) == ("mio", "mi-red", 62000, 62000)


def test_reading_an_installation_of_before_makes_nothing_new(home: Path) -> None:
    write_main(home, provider=False)  # one with a provider makes its keys, as it always has
    before = everything_in(home)
    installation = load_installation(main_config(home))
    assert everything_in(home) == before
    assert isinstance(installation, Installation)
    assert installation.others == ()
    assert installation.agents == (installation.main,)
    assert installation.main.slug == "principal"
    assert installation.main.blackbox_db == ServiceConfig.from_file(main_config(home)).blackbox_db


def test_an_empty_agents_folder_changes_nothing(home: Path) -> None:
    (home / "etc" / "agents").mkdir(mode=0o755)
    assert load_installation(main_config(home)).others == ()


def test_a_black_box_of_before_goes_on_with_the_same_chain_after_a_start(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The heart of it: the events of an old box stay, the chain goes on and it verifies. The
    installation's box is apart, and the old box gets nothing the service did not write."""
    import backtide.service.runner as runner  # noqa: PLC0415

    config = ServiceConfig.from_file(main_config(home))
    with open_black_box(config) as box:
        first = box.append("system", "service_start", "")
        box.append("exec", "run", "ls")
    key = config.blackbox_key.read_bytes()
    monkeypatch.setattr(runner, "run_guardian", lambda *a, **k: None)
    serve(config, jail=AgentJail(config.jail_config()), handle_signals=False)
    assert config.blackbox_key.read_bytes() == key
    reopened = BlackBox(config.blackbox_db, load_key(config.blackbox_key),
                        checkpoint_path=config.blackbox_checkpoint)  # fmt: skip
    with reopened:
        events = reopened.events()
        assert reopened.verify().ok
        assert [e.action for e in events] == ["service_start", "run"]
        assert events[0].hash == first.hash
        reopened.append("exec", "run", "pwd")
        assert reopened.verify().ok
    assert config.installation_db != config.blackbox_db
    assert config.installation_db.exists()


# --- `agents/<slug>.toml` ------------------------------------------------------------------------


def test_an_agents_file_gives_it_its_names_ids_and_folders(home: Path) -> None:
    add_agent(home, "revisor", number=3)
    (main, agent) = load_installation(main_config(home)).agents
    assert main.slug == "principal"
    folder = home / "state" / "agents" / "revisor"
    assert (agent.slug, agent.number, agent.display_name) == ("revisor", 3, "Revisor 3")
    assert agent.agent_dir == folder
    assert agent.blackbox_db == folder / "blackbox.db"
    assert agent.blackbox_key == folder / "blackbox.key"
    assert agent.blackbox_checkpoint == folder / "blackbox.checkpoint"
    assert agent.gateway_token_file == folder / "gateway.token"
    assert agent.agent_config_dir == folder / "claude-code"
    assert agent.pending_file == folder / "rewind.pending"
    assert agent.proxy_ca_dir == folder / "proxy-ca"
    assert agent.agent_ca_dir == folder / "agent-ca"
    assert agent.proxy_channel_dir == folder / "proxy-channel"
    assert agent.volume == home / "agent-volumes" / "revisor"
    jail, proxy = agent.jail_config(), agent.proxy_jail_config()
    assert (jail.name, jail.network, jail.uid, jail.gid) == (
        "backtide-revisor-agente", "backtide-revisor-net", 61103, 61103,
    )  # fmt: skip
    assert (proxy.name, proxy.network, proxy.agent_network, proxy.uid, proxy.gid) == (
        "backtide-revisor-egress", "backtide-revisor-salida", "backtide-revisor-net", 61203, 61203,
    )  # fmt: skip
    assert (proxy.agent_uid, proxy.agent_gid) == (61103, 61103)


def test_what_is_the_machines_stays_one(home: Path) -> None:
    add_agent(home, "revisor")
    main, agent = load_installation(main_config(home)).agents
    assert agent.state_dir == main.state_dir
    assert agent.control_socket == main.control_socket
    assert agent.web_socket == main.web_socket
    assert agent.lock_file == main.lock_file
    assert agent.keys_dir == main.keys_dir
    assert agent.sensor_dir == main.sensor_dir
    assert agent.rules_file == main.rules_file
    assert agent.sensor_jail_config().name == main.sensor_jail_config().name
    assert agent.installation_db == main.installation_db


def test_the_agents_follow_their_numbers_after_the_main_one(home: Path) -> None:
    add_agent(home, "zeta", number=1)
    add_agent(home, "alfa", number=2)
    assert [a.slug for a in load_installation(main_config(home)).agents] == [
        "principal", "zeta", "alfa",
    ]  # fmt: skip


def test_each_agent_has_its_own_fake_key_and_they_share_the_real_one(home: Path) -> None:
    keys = home / "state" / "keys"
    keys.mkdir(mode=0o700)
    private(keys / "anthropic.key", REAL_KEY)
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    main, uno, dos = load_installation(main_config(home)).agents
    fakes = [c.provider_keys["anthropic"].fake for c in (main, uno, dos)]
    assert len(set(fakes)) == 3
    for config in (main, uno, dos):
        assert config.provider_keys["anthropic"].real.reveal() == REAL_KEY
    assert (keys / "anthropic.fake").read_text().strip() == fakes[0]
    fake = home / "state" / "agents" / "uno" / "anthropic.fake"
    assert fake.read_text().strip() == fakes[1]
    assert fake.stat().st_mode & 0o777 == 0o600
    assert not (home / "state" / "agents" / "uno" / "anthropic.key").exists()
    # And a second read keeps them: a fake key is made once.
    assert (
        load_installation(main_config(home)).agents[1].provider_keys["anthropic"].fake == fakes[1]
    )


def test_an_agents_proxy_keeps_what_the_machine_lets_out_and_its_own_limits(home: Path) -> None:
    write_main(
        home,
        '[proxy]\nallow_hosts = ["example.org"]\nname = "mi-proxy"\nmemory = "2g"\n',
    )
    add_agent(
        home,
        "revisor",
        claude_code(home, "revisor", 1) + '[proxy]\nmemory = "512m"\ncpus = "0.5"\n',
    )
    agent = load_installation(main_config(home)).others[0]
    assert "example.org" in agent.proxy_settings().allow_hosts
    assert [p.name for p in agent.proxy_settings().providers] == ["anthropic"]
    proxy = agent.proxy_jail_config()
    assert proxy.name == "backtide-revisor-egress"  # the main one's name stays the main one's
    assert (proxy.memory, proxy.cpus) == ("512m", "0.5")
    # Without limits of its own, the machine's.
    add_agent(home, "revisor", claude_code(home, "revisor", 1))
    assert load_installation(main_config(home)).others[0].proxy_jail_config().memory == "2g"


def test_an_openclaw_agent_reads_its_own_token_never_the_main_ones(home: Path) -> None:
    folder = home / "state" / "agents"
    folder.mkdir(mode=0o700)
    (folder / "garra").mkdir(mode=0o700)
    private(folder / "garra" / "gateway.token", OTHER_TOKEN + "\n")
    add_agent(
        home,
        "garra",
        f'number = 1\nvolume = "{home / "agent-volumes" / "garra"}"\n',
    )
    main, agent = load_installation(main_config(home)).agents
    assert main.gateway_token.reveal() == TOKEN
    assert agent.gateway_token.reveal() == OTHER_TOKEN
    assert agent.jail_config().gateway_token == OTHER_TOKEN


def test_an_openclaw_agent_without_its_token_is_a_clear_error(home: Path) -> None:
    add_agent(home, "garra", f'number = 1\nvolume = "{home / "v"}"\n')
    with pytest.raises(ConfigError, match="gateway token file") as raised:
        load_installation(main_config(home))
    assert TOKEN not in str(raised.value)


def test_the_agents_folders_are_private_and_ours(home: Path) -> None:
    add_agent(home, "revisor")
    load_installation(main_config(home))
    for folder in (home / "state" / "agents", home / "state" / "agents" / "revisor"):
        assert folder.stat().st_mode & 0o777 == 0o700


# --- what a file may not say ----------------------------------------------------------------------


def test_a_file_named_outside_the_rule_stops_the_load(home: Path) -> None:
    (home / "etc" / "agents").mkdir(mode=0o755)
    private(home / "etc" / "agents" / "Mal Nombre.toml", "number = 1\n")
    with pytest.raises(ConfigError, match="slug"):
        load_installation(main_config(home))


@pytest.mark.parametrize("slug", ["principal", "agente", "salida", "nuevo"])
def test_a_reserved_slug_as_a_file_stops_the_load(home: Path, slug: str) -> None:
    add_agent(home, slug)
    with pytest.raises(ConfigError, match="reserved"):
        load_installation(main_config(home))


def test_a_name_that_climbs_out_never_reaches_a_folder(home: Path) -> None:
    add_agent(home, "..hidden")
    with pytest.raises(ConfigError, match="slug"):
        load_installation(main_config(home))
    assert not (home / "state" / "agents").exists()


@pytest.mark.parametrize("slug", ["../fuera", "a/b", "..", "principal", "agente"])
def test_a_config_made_by_hand_cannot_climb_out_either(home: Path, slug: str) -> None:
    config = ServiceConfig.from_file(main_config(home))
    with pytest.raises(ConfigError):
        dataclasses.replace(config, slug=slug, number=1)


def test_other_files_in_the_folder_are_not_agents(home: Path) -> None:
    add_agent(home, "revisor")
    private(home / "etc" / "agents" / "revisor.toml.antes", "esto no es toml")
    private(home / "etc" / "agents" / ".oculto", "ni esto")
    assert [a.slug for a in load_installation(main_config(home)).others] == ["revisor"]


def test_a_folder_named_like_an_agents_file_is_refused(home: Path) -> None:
    (home / "etc" / "agents" / "revisor.toml").mkdir(parents=True)
    (home / "etc" / "agents").chmod(0o755)
    with pytest.raises(ConfigError, match="not a regular file"):
        load_installation(main_config(home))


def test_a_symlinked_agents_file_is_refused(home: Path) -> None:
    real = home / "elsewhere.toml"
    private(real, claude_code(home, "revisor", 1))
    (home / "etc" / "agents").mkdir(mode=0o755)
    (home / "etc" / "agents" / "revisor.toml").symlink_to(real)
    with pytest.raises(ConfigError, match="symlink"):
        load_installation(main_config(home))


def test_a_file_others_can_write_is_refused(home: Path) -> None:
    path = add_agent(home, "revisor")
    path.chmod(0o664)
    with pytest.raises(ConfigError, match="writable by group or others"):
        load_installation(main_config(home))


def test_a_folder_of_files_that_is_a_link_or_open_is_refused(home: Path) -> None:
    other = home / "other"
    other.mkdir(mode=0o755)
    private(other / "revisor.toml", claude_code(home, "revisor", 1))
    (home / "etc" / "agents").symlink_to(other)
    with pytest.raises(ConfigError, match="symlink"):
        load_installation(main_config(home))
    (home / "etc" / "agents").unlink()
    (home / "etc" / "agents").mkdir(mode=0o777)
    (home / "etc" / "agents").chmod(0o777)
    with pytest.raises(ConfigError, match="writable by group or others"):
        load_installation(main_config(home))


def test_a_state_folder_that_is_a_link_is_refused(home: Path) -> None:
    add_agent(home, "revisor")
    target = home / "elsewhere"
    target.mkdir(mode=0o700)
    (home / "state" / "agents").symlink_to(target)
    with pytest.raises(ConfigError, match="symlink"):
        load_installation(main_config(home))
    assert everything_in(target) == []


@pytest.mark.parametrize(
    ("extra", "said"),
    [
        ('gateway_token = "x"\n', "gateway_token"),
        ('state_dir = "/tmp/x"\n', "state_dir"),
        ('cycle_interval = 1\n', "cycle_interval"),
        ("sensor = {}\n", "sensor"),
        ("budget = {}\n", "budget"),
        ("slug = \"otro\"\n", "slug"),
    ],
)  # fmt: skip
def test_a_setting_of_the_machine_or_unknown_is_refused(home: Path, extra: str, said: str) -> None:
    add_agent(home, "revisor", extra + claude_code(home, "revisor", 1))
    with pytest.raises(ConfigError, match=said):
        load_installation(main_config(home))


@pytest.mark.parametrize("key", ["name", "network", "uid", "gid", "config_dir", "hostname"])
def test_what_the_slug_and_number_decide_is_never_an_agent_setting(home: Path, key: str) -> None:
    value = '"x"' if key in ("name", "network", "config_dir", "hostname") else "62000"
    add_agent(home, "revisor", claude_code(home, "revisor", 1) + f"{key} = {value}\n")
    with pytest.raises(ConfigError, match=key):
        load_installation(main_config(home))


@pytest.mark.parametrize(
    "setting",
    ['name = "x"', 'network = "x"', "uid = 62000", "gid = 62000", 'image = "x"',
     'allow_hosts = ["x"]', 'api_key = "sk-x"', "providers = []"],
)  # fmt: skip
def test_the_proxys_table_only_takes_limits(home: Path, setting: str) -> None:
    add_agent(home, "revisor", claude_code(home, "revisor", 1) + f"[proxy]\n{setting}\n")
    with pytest.raises(ConfigError, match=r"\[proxy\]"):
        load_installation(main_config(home))


@pytest.mark.parametrize(
    "setting",
    ["privileged = true", 'cap_add = ["SYS_ADMIN"]', 'volumes = ["/:/host"]', "ports = [80]",
     'network_mode = "host"'],
)  # fmt: skip
def test_nothing_of_the_jail_is_an_agent_setting_here_either(home: Path, setting: str) -> None:
    add_agent(home, "revisor", claude_code(home, "revisor", 1) + f"{setting}\n")
    with pytest.raises(ConfigError):
        load_installation(main_config(home))


@pytest.mark.parametrize(
    "number", ["0", "-1", "100", "1.5", '"1"', "true"], ids=lambda value: f"number={value}"
)
def test_a_number_out_of_range_is_refused(home: Path, number: str) -> None:
    text = claude_code(home, "revisor", 1).replace("number = 1", f"number = {number}")
    add_agent(home, "revisor", text)
    with pytest.raises(ConfigError, match="number"):
        load_installation(main_config(home))


def test_a_file_without_a_number_or_a_volume_is_refused(home: Path) -> None:
    text = claude_code(home, "revisor", 1)
    add_agent(home, "revisor", text.replace("number = 1\n", ""))
    with pytest.raises(ConfigError, match="number"):
        load_installation(main_config(home))
    add_agent(home, "revisor", 'number = 1\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="volume"):
        load_installation(main_config(home))


def test_a_file_that_is_not_toml_says_so_without_quoting_it(home: Path) -> None:
    add_agent(home, "revisor", "sk-ant-api03-secreto = = =\n")
    with pytest.raises(ConfigError, match="not valid TOML") as raised:
        load_installation(main_config(home))
    assert "sk-ant" not in str(raised.value)


@pytest.mark.parametrize(
    "name",
    ['""', '"   "', f'"{"x" * 49}"', "7", r'"dos\nlineas"', r'"con\u001b[31mcolor"', r'"a‮b"'],
    ids=["empty", "blank", "long", "number", "newline", "escape", "bidi"],
)
def test_a_name_to_show_is_short_and_has_no_control_characters(home: Path, name: str) -> None:
    text = f'number = 1\nname = {name}\nvolume = "{home / "v"}"\n[agent]\nprofile = "claude-code"\n'
    add_agent(home, "revisor", text)
    with pytest.raises(ConfigError, match="name"):
        load_installation(main_config(home))


def test_the_name_to_show_is_optional_and_any_language(home: Path) -> None:
    add_agent(
        home, "uno", f'number = 1\nvolume = "{home / "v1"}"\n[agent]\nprofile = "claude-code"\n'
    )
    add_agent(
        home,
        "dos",
        f'number = 2\nname = "Revisión ñ 日本"\nvolume = "{home / "v2"}"\n'
        '[agent]\nprofile = "claude-code"\n',
    )
    uno, dos = load_installation(main_config(home)).others
    assert uno.display_name is None
    assert dos.display_name == "Revisión ñ 日本"


# --- together: nothing shared ---------------------------------------------------------------------


def test_two_agents_cannot_share_a_number(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=1)
    with pytest.raises(ConfigError, match="61101"):
        load_installation(main_config(home))


def test_at_most_eight_agents_counting_the_main_one(home: Path) -> None:
    assert MAX_AGENTS == 8
    for number in range(1, MAX_AGENTS):
        add_agent(home, f"a{number}", number=number)
    assert len(load_installation(main_config(home)).agents) == MAX_AGENTS
    add_agent(home, "otro", number=50)
    with pytest.raises(ConfigError, match="at most 8"):
        load_installation(main_config(home))


def test_the_main_agents_own_uid_cannot_be_a_neighbours(home: Path) -> None:
    write_main(home, "[agent]\nuid = 61101\ngid = 61101\n")
    add_agent(home, "revisor", number=1)
    with pytest.raises(ConfigError, match="61101"):
        load_installation(main_config(home))


def test_the_main_agents_own_names_cannot_be_a_neighbours(home: Path) -> None:
    write_main(home, '[agent]\nname = "backtide-revisor-agente"\n')
    add_agent(home, "revisor")
    with pytest.raises(ConfigError, match="backtide-revisor-agente"):
        load_installation(main_config(home))
    write_main(home, '[proxy]\nnetwork = "backtide-revisor-salida"\n')
    with pytest.raises(ConfigError, match="backtide-revisor-salida"):
        load_installation(main_config(home))


def test_a_neighbours_volume_is_refused_shared_nested_or_holding_it(home: Path) -> None:
    shared = home / "volume"
    add_agent(home, "uno", f'number = 1\nvolume = "{shared}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="volume"):
        load_installation(main_config(home))
    # The path docs/47 first gave: inside the main agent's own volume, where it would be mounted
    # on the main agent's filesystem and hidden by nothing but its mount.
    nested = shared / "uno"
    add_agent(home, "uno", f'number = 1\nvolume = "{nested}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="volume"):
        load_installation(main_config(home))
    add_agent(home, "uno", number=1)
    other = home / "agent-volumes" / "uno" / "dentro"
    add_agent(home, "dos", f'number = 2\nvolume = "{other}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="volume"):
        load_installation(main_config(home))


def test_an_agents_volume_can_never_be_in_the_state(home: Path) -> None:
    inside = home / "state" / "agents" / "uno" / "volumen"
    add_agent(home, "uno", f'number = 1\nvolume = "{inside}"\n[agent]\nprofile = "claude-code"\n')
    with pytest.raises(ConfigError, match="black box"):
        load_installation(main_config(home))


def test_an_image_behind_a_volume_is_nobody_elses(home: Path) -> None:
    write_main(home, f'volume_image = "{home / "main.img"}"\nmax_volume_bytes = 1000\n')
    add_agent(
        home,
        "uno",
        claude_code(home, "uno", 1,
                    f'volume_image = "{home / "main.img"}"\nmax_volume_bytes = 1000\n'),
    )  # fmt: skip
    with pytest.raises(ConfigError, match="main.img"):
        load_installation(main_config(home))
    add_agent(
        home,
        "uno",
        claude_code(home, "uno", 1,
                    f'volume_image = "{home / "volume" / "x.img"}"\nmax_volume_bytes = 1000\n'),
    )  # fmt: skip
    with pytest.raises(ConfigError, match="x.img"):
        load_installation(main_config(home))


def test_an_agents_image_and_limit_are_read(home: Path) -> None:
    image = home / "state" / "agents" / "uno" / "volume.img"
    add_agent(
        home,
        "uno",
        claude_code(home, "uno", 1,
                    f'volume_image = "{image}"\nmax_volume_bytes = 2000\nworkspace_limit = 500\n'),
    )  # fmt: skip
    agent = load_installation(main_config(home)).others[0]
    assert (agent.volume_image, agent.max_volume_bytes, agent.workspace_limit) == (image, 2000, 500)


def test_an_image_in_the_state_can_only_be_its_own(home: Path) -> None:
    add_agent(home, "dos", number=2)
    state = home / "state"
    for target in (
        state / "agents" / "dos" / "blackbox.db",
        state / "blackbox.db",
        state / "installation" / "blackbox.db",
        state / "keys" / "anthropic.key",
        state / "agents" / "uno" / "otra.img",
    ):
        add_agent(
            home,
            "uno",
            claude_code(home, "uno", 1, f'volume_image = "{target}"\nmax_volume_bytes = 1000\n'),
        )
        with pytest.raises(ConfigError, match="volume_image"):
            load_installation(main_config(home))


def test_a_link_cannot_hide_that_a_volume_is_a_neighbours(home: Path) -> None:
    volumes = home / "agent-volumes"
    (volumes / "dos").mkdir(parents=True)
    (volumes / "uno").symlink_to(volumes / "dos")
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    with pytest.raises(ConfigError, match="share a folder"):
        load_installation(main_config(home))


def test_a_copied_folder_is_refused_and_no_secret_is_said(home: Path) -> None:
    """``cp -a agents/uno agents/dos``: one fake key and one chain for two agents."""
    add_agent(home, "uno", number=1)
    uno = load_installation(main_config(home)).others[0]
    with open_black_box(uno) as box:
        box.append("exec", "run", "algo")
    fake = uno.provider_keys["anthropic"].fake
    shutil.copytree(uno.agent_dir, uno.agents_dir / "dos")
    add_agent(home, "dos", number=2)
    with pytest.raises(ConfigError, match="share a secret") as raised:
        load_installation(main_config(home))
    assert fake not in str(raised.value)


def test_a_copied_black_box_key_alone_is_refused(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    _, uno, dos = load_installation(main_config(home)).agents
    open_black_box(uno)  # makes its key
    shutil.copy2(uno.blackbox_key, dos.blackbox_key)
    with pytest.raises(ConfigError, match="share a secret"):
        load_installation(main_config(home))


@pytest.mark.parametrize("taken", [61101, 61201])
def test_an_agent_whose_ids_are_an_accounts_is_refused(
    home: Path, monkeypatch: pytest.MonkeyPatch, taken: int
) -> None:
    def account(number: int) -> object:
        if number == taken:
            return object()
        raise KeyError(number)

    add_agent(home, "uno", number=1)
    assert load_installation(main_config(home)).others
    monkeypatch.setattr("pwd.getpwuid", account)
    with pytest.raises(ConfigError, match=str(taken)):
        load_installation(main_config(home))


def test_a_group_with_an_agents_id_is_refused_too(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def group(number: int) -> object:
        if number == 61101:
            return object()
        raise KeyError(number)

    add_agent(home, "uno", number=1)
    monkeypatch.setattr("grp.getgrgid", group)
    with pytest.raises(ConfigError, match="61101"):
        load_installation(main_config(home))


def test_a_taken_id_of_another_number_stops_nobody(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_agent(home, "uno", number=2)

    def account(number: int) -> object:
        if number == 61101:
            return object()
        raise KeyError(number)

    monkeypatch.setattr("pwd.getpwuid", account)
    assert len(load_installation(main_config(home)).others) == 1


# --- invariant 1: the agent sees nothing of backtide, nor of its neighbours ---------------------


def test_only_its_own_two_folders_may_be_mounted_from_the_state(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    _, uno, dos = load_installation(main_config(home)).agents
    state = next(p for p in uno.agent_protected() if p.path == uno.state_dir)
    assert set(state.allowed_inside) == {uno.agent_config_dir, uno.agent_ca_dir}
    assert uno.jail_config().config_dir == uno.agent_config_dir
    assert uno.jail_config().ca_dir == uno.agent_ca_dir
    for neighbour in (dos.agent_config_dir, dos.agent_ca_dir, dos.blackbox_db, dos.agent_dir):
        assert not any(neighbour.is_relative_to(folder) for folder in state.allowed_inside)


def test_a_neighbours_folders_and_the_black_boxes_cannot_be_mounted(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    main, uno, dos = load_installation(main_config(home)).agents
    config = uno.jail_config()
    dataclasses.replace(config, config_dir=uno.agent_config_dir)  # its own: fine
    for host in (
        dos.agent_config_dir,  # a neighbour's config
        dos.agent_ca_dir,
        dos.agent_dir,  # its black box, its fake keys
        main.state_dir,  # backtide's state
        main.agent_config_dir,  # the main agent's config
        uno.installation_dir,  # the installation's box
        uno.agents_dir,  # every agent's folder at once
        uno.agent_dir,  # its own black box and key
        uno.keys_dir,
    ):
        with pytest.raises(ValueError, match="must never see|holds|inside"):
            dataclasses.replace(config, config_dir=host)


def test_a_main_agents_config_folder_can_never_hold_the_neighbours(home: Path) -> None:
    for folder in (
        home / "state" / "agents",
        home / "state" / "agents" / "revisor",
        home / "state" / "installation",
    ):
        write_main(home, f'[agent]\nconfig_dir = "{folder}"\n')
        with pytest.raises(ConfigError, match="config_dir"):
            ServiceConfig.from_file(main_config(home))


def test_the_new_paths_are_protected_for_the_main_agent_too(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    paths = {p.path for p in config.agent_protected()}
    assert {config.installation_dir, config.agents_dir, config.blackbox_db} <= paths
    for host in (config.agents_dir, config.agents_dir / "revisor", config.installation_dir):
        with pytest.raises(ValueError, match="must never see|holds|inside"):
            dataclasses.replace(config.jail_config(), config_dir=host)


def test_the_token_of_an_agent_does_not_show_in_its_config(home: Path) -> None:
    add_agent(home, "revisor")
    agent = load_installation(main_config(home)).others[0]
    fake = agent.provider_keys["anthropic"].fake
    assert fake not in repr(agent)
    assert TOKEN not in repr(agent)


# --- the black boxes: one chain per agent, and the installation's --------------------------------


def test_each_agent_has_its_own_chain_and_key(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    main, uno, dos = load_installation(main_config(home)).agents
    boxes = [open_black_box(c).open() for c in (main, uno, dos)]
    try:
        boxes[0].append("exec", "run", "del principal")
        for _ in range(3):
            boxes[1].append("exec", "run", "del uno")
        assert boxes[2].events() == []
        assert [len(b.events()) for b in boxes] == [1, 3, 0]
        assert all(b.verify().ok for b in boxes)
        assert boxes[1].events()[0].prev_hash == boxes[0].events()[0].prev_hash  # both genesis
    finally:
        for box in boxes:
            box.close()
    keys = {c.blackbox_key.read_bytes() for c in (main, uno, dos)}
    assert len(keys) == 3
    assert uno.blackbox_key.stat().st_mode & 0o777 == 0o600


def test_a_key_of_another_agent_opens_nothing(home: Path) -> None:
    add_agent(home, "uno", number=1)
    add_agent(home, "dos", number=2)
    _, uno, dos = load_installation(main_config(home)).agents
    with open_black_box(uno) as box:
        box.append("exec", "run", "algo")
    with open_black_box(dos):
        pass
    foreign = BlackBox(uno.blackbox_db, load_key(dos.blackbox_key),
                       checkpoint_path=uno.blackbox_checkpoint)  # fmt: skip
    with foreign, pytest.raises(BlackBoxError):
        foreign.append("exec", "run", "encima")


def test_the_installations_box_is_a_chain_of_its_own(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    assert config.installation_dir == home / "state" / "installation"
    assert config.installation_db == config.installation_dir / "blackbox.db"
    assert config.installation_key == config.installation_dir / "blackbox.key"
    assert config.installation_checkpoint == config.installation_dir / "blackbox.checkpoint"
    with open_installation_box(config) as box:
        box.append("system", "agent_created", "revisor")
        assert box.verify().ok
    assert config.installation_dir.stat().st_mode & 0o777 == 0o700
    assert config.installation_key.stat().st_mode & 0o777 == 0o600
    assert not config.blackbox_db.exists()
    with open_installation_box(config) as box:
        assert [e.target for e in box.events()] == ["revisor"]
        assert box.verify().ok


def test_the_installations_box_without_its_key_is_refused(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    with open_installation_box(config) as box:
        box.append("system", "x", "")
    config.installation_key.unlink()
    with pytest.raises(BlackBoxError, match="falta su"):
        open_installation_box(config)
    assert not config.installation_key.exists()


class Sink:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def submit(self, alert: Alert) -> bool:
        self.alerts.append(alert)
        return True


def test_a_start_is_written_to_the_installations_box(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    sink = Sink()
    record_installation_start(config, sink)
    record_installation_start(config, sink)
    assert sink.alerts == []
    with open_installation_box(config) as box:
        events = box.events()
        assert box.verify().ok
    assert [e.action for e in events] == ["service_start", "service_start"]
    assert events[0].source == "system"
    assert events[0].details == {"agents": ["principal"]}


def test_a_chain_that_does_not_verify_is_told_and_not_extended(home: Path) -> None:
    config = ServiceConfig.from_file(main_config(home))
    sink = Sink()
    record_installation_start(config, sink)
    record_installation_start(config, sink)
    assert sink.alerts == []
    with tamper(config.installation_db) as conn:
        conn.execute("UPDATE events SET target = 'otro' WHERE seq = 1")
    record_installation_start(config, sink)
    (alert,) = sink.alerts
    assert alert.level is AlertLevel.ERROR
    assert "does not verify" in alert.body
    with open_installation_box(config) as box:
        assert len(box.events()) == 2


def _break_with_a_garbage_db(config: ServiceConfig) -> None:
    with open_installation_box(config) as box:
        box.append("system", "x", "")
    for suffix in ("", "-wal", "-shm"):
        Path(f"{config.installation_db}{suffix}").unlink(missing_ok=True)
    config.installation_db.write_bytes(b"this is not a database" * 100)


def _break_with_a_lost_key(config: ServiceConfig) -> None:
    with open_installation_box(config) as box:
        box.append("system", "x", "")
    config.installation_key.unlink()


def _break_with_a_link(config: ServiceConfig) -> None:
    target = config.state_dir.parent / "elsewhere"
    target.mkdir(mode=0o700)
    config.installation_dir.symlink_to(target)


def _break_with_a_file(config: ServiceConfig) -> None:
    config.installation_dir.write_text("not a folder")


@pytest.mark.parametrize(
    "breaks",
    [_break_with_a_garbage_db, _break_with_a_lost_key, _break_with_a_link, _break_with_a_file],
)
def test_a_broken_installations_box_is_told_and_never_stops_the_agent(
    home: Path, breaks: object, caplog: pytest.LogCaptureFixture
) -> None:
    """The agent's own box is what records it: losing the installation's is said out loud and
    the service goes on, as it would have before this box existed."""
    config = ServiceConfig.from_file(main_config(home))
    breaks(config)  # type: ignore[operator]
    sink = Sink()
    with caplog.at_level("ERROR"):
        record_installation_start(config, sink)
    (alert,) = sink.alerts
    assert alert.level is AlertLevel.ERROR
    assert "instalación" in alert.title
    assert any("installation" in record.getMessage() for record in caplog.records)


def test_a_service_with_a_broken_installations_box_still_runs(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import backtide.service.runner as runner  # noqa: PLC0415

    config = ServiceConfig.from_file(main_config(home))
    _break_with_a_link(config)
    ran: list[bool] = []
    monkeypatch.setattr(runner, "run_guardian", lambda *a, **k: ran.append(True))
    serve(config, jail=AgentJail(config.jail_config()), handle_signals=False)
    assert ran == [True]


# --- helpers and what else knows the ids ----------------------------------------------------------


def test_a_state_folder_is_made_private_and_a_bad_one_refused(tmp_path: Path) -> None:
    folder = tmp_path / "x"
    ensure_state_folder(folder, "the folder")
    assert folder.stat().st_mode & 0o777 == 0o700
    ensure_state_folder(folder, "the folder")  # already there: fine
    folder.chmod(0o710)  # the web's way into a folder of the state (D25): fine too
    ensure_state_folder(folder, "the folder")
    folder.chmod(0o770)
    with pytest.raises(ConfigError, match="writable by group or others"):
        ensure_state_folder(folder, "the folder")
    with pytest.raises(ConfigError, match="cannot make"):
        ensure_state_folder(tmp_path / "no" / "parent", "the folder")


def test_the_volumes_of_the_other_agents_live_beside_the_main_ones_not_in_it() -> None:
    assert not setup_layout.AGENT_VOLUMES.is_relative_to(setup_layout.VOLUME_MOUNT)
    assert not setup_layout.VOLUME_MOUNT.is_relative_to(setup_layout.AGENT_VOLUMES)
    assert not setup_layout.AGENT_VOLUMES.is_relative_to(setup_layout.STATE_DIR)
    assert setup_layout.AGENT_CONFIGS == setup_layout.CONFIG_DIR / "agents"


def test_a_real_looking_installed_layout_passes_as_a_whole(home: Path) -> None:
    """The shape T26-2b and T26-6a will write, with every setting a file can hold."""
    state = home / "state"
    private(state / "rules.toml", "")
    os.mkdir(state / "keys", 0o700)
    private(state / "keys" / "anthropic.key", REAL_KEY)
    add_agent(
        home,
        "revisor",
        f'number = 4\nname = "Revisor"\nvolume = "{home / "agent-volumes" / "revisor"}"\n'
        f'volume_image = "{state / "agents" / "revisor" / "volume.img"}"\n'
        "max_volume_bytes = 32212254720\nworkspace_limit = 1073741824\n"
        '[agent]\nprofile = "claude-code"\nmemory = "1g"\ncpus = "1"\n'
        '[proxy]\nmemory = "256m"\n',
    )
    agent = load_installation(main_config(home)).others[0]
    assert agent.jail_config().memory == "1g"
    assert agent.proxy_jail_config().memory == "256m"
    assert agent.ca_paths().gid == 61204
    assert agent.sensor_reader_config().agent_name == "backtide-revisor-agente"
