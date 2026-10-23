"""The agent profile (T17a-2, docs/34 sections 6 and 7): what it may fill in, and that it can
never change the jail's security. OpenClaw's own jail, byte for byte, is
test_jail_openclaw_snapshot.py."""

import dataclasses
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from backtide.gate.provider_tools import check_profile_param
from backtide.jail import agent as agent_module
from backtide.jail.agent import AgentJail
from backtide.jail.config import (
    AgentJailConfig,
    container_env,
    docker_create_argv,
    jail_env_names,
    token_env,
)
from backtide.jail.docker import JailError
from backtide.jail.profile import (
    CUSTOM_NAME,
    RESERVED_ENV,
    REVIEWED_ALLOW_HOSTS,
    AgentProfile,
    ProfileError,
    image_env_problem,
    image_secret,
    is_reserved_env,
)
from backtide.jail.profiles import DEFAULT_PROFILE, OPENCLAW
from backtide.jail.profiles.openclaw import ModelProvider, UnrewindableConfig
from backtide.jail.verify import container_problems
from backtide.service.config import Secret, ServiceConfig

TOKEN = "t" * 43
IMAGE = "ghcr.io/acme/agent@sha256:" + "a" * 64
WORKSPACE = Path("/srv/bt/volume/workspace")
CONFIG_DIR = Path("/srv/bt/state/openclaw")  # the paths of the snapshot
CA_DIR = Path("/srv/bt/state/agent-ca")
FAKE = "backtide-fake-anthropic-" + "k" * 32
CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

# Every field a profile has. A new one is a decision: add it here only if it is the agent's,
# never the jail's (docs/34, section 6).
PROFILE_FIELDS = {
    "name", "version", "image", "entrypoint", "command", "workdir", "workspace_dirs", "env",
    "proxy_url_env", "ca_file_env", "token_env", "fake_key_env", "config_names",
    "render_config", "check_config", "ready_log_line", "ready_probe", "ready_answer",
    "rewind_notice_lines", "provider_params", "check_providers", "provider_env", "mode", "shell",
    "allow_hosts",
}  # fmt: skip
# What decides the jail's security: AgentJailConfig's or fixed, never a profile's.
SECURITY_FIELDS = (
    "uid", "gid", "user", "privileged", "cap_add", "capabilities", "security_opt",
    "seccomp_profile", "read_only", "tmpfs", "tmp_size", "sys_masks", "mounts", "volumes",
    "binds", "network", "networks", "dns", "ports", "publish", "extra_hosts", "devices",
    "hostname", "memory", "pids_limit", "cpus", "restart", "log_driver", "home", "proxy_url",
    "ca_file", "allow_shared_ids", "protected", "workspace", "config_dir", "ca_dir",
)  # fmt: skip


def profile(**changes: Any) -> AgentProfile:
    fields: dict[str, Any] = {
        "name": "test-agent",
        "version": "1.0",
        "image": IMAGE,
        "entrypoint": "tini",
        "command": ("-s", "--", "agent"),
    }
    return AgentProfile(**(fields | changes))


def jail_config(agent: AgentProfile = OPENCLAW, **changes: Any) -> AgentJailConfig:
    fields: dict[str, Any] = {
        "workspace": WORKSPACE,
        "config_dir": CONFIG_DIR,
        "ca_dir": CA_DIR,
        "gateway_token": TOKEN if getattr(agent, "token_env", None) else None,  # who uses it
        "profile": agent,
    }
    return AgentJailConfig(**(fields | changes))


# --- the type: no security field, ever ------------------------------------------------------


def test_a_profile_has_exactly_the_agents_fields() -> None:
    assert {field.name for field in dataclasses.fields(AgentProfile)} == PROFILE_FIELDS
    assert not PROFILE_FIELDS & set(SECURITY_FIELDS)


@pytest.mark.parametrize("name", SECURITY_FIELDS)
def test_a_profile_cannot_be_given_a_security_field(name: str) -> None:
    with pytest.raises(TypeError):
        profile(**{name: "anything"})


def test_a_profile_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        OPENCLAW.image = IMAGE  # type: ignore[misc]


def test_openclaw_is_the_default_profile() -> None:
    assert DEFAULT_PROFILE is OPENCLAW
    assert jail_config().profile is OPENCLAW
    assert AgentJailConfig(
        workspace=WORKSPACE, config_dir=CONFIG_DIR, ca_dir=CA_DIR, gateway_token=TOKEN
    ).image == (OPENCLAW.image)


def test_every_variable_the_jail_sets_is_reserved() -> None:
    names = jail_env_names()
    assert {"HOME", "DO_NOT_TRACK", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE"} <= names
    assert all(is_reserved_env(name) for name in names)
    assert all(is_reserved_env(name) for name in RESERVED_ENV)


RESERVED = (
    "HOME", "home", "DO_NOT_TRACK", "HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY",
    "no_proxy", "FTP_PROXY", "NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_OPTIONS",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "ld_audit", "BASH_ENV", "ENV", "PATH", "PYTHONPATH",
    "NODE_TLS_REJECT_UNAUTHORIZED", "GIT_SSL_NO_VERIFY",
    # By family, after the review of the profiles (L6): not a complete list, a floor.
    "No_proxy", "All_Proxy", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
    "GIT_CONFIG_PARAMETERS", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "GIT_EXEC_PATH",
    "PROMPT_COMMAND", "PS4", "BASH_FUNC_ls%%", "BASH_FUNC_x", "PERL5LIB", "PERL5OPT",
    "PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    "IBM_JAVA_OPTIONS", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONWARNINGS", "npm_config_prefix",
    "NPM_CONFIG_USERCONFIG", "GCONV_PATH", "GLIBC_TUNABLES", "DYLD_INSERT_LIBRARIES",
    "OPENSSL_CONF", "SSLKEYLOGFILE", "NODE_REPL_EXTERNAL_MODULE", "ZDOTDIR", "LUA_INIT",
)  # fmt: skip


@pytest.mark.parametrize("name", RESERVED)
def test_the_reserved_families(name: str) -> None:
    assert is_reserved_env(name)


@pytest.mark.parametrize(
    "name", ["NODE_ENV", "MY_AGENT_MODE", "XDG_CONFIG_HOME", "GITHUB_WORKSPACE", "TERM", "LANG"]
)
def test_what_is_not_reserved(name: str) -> None:
    assert not is_reserved_env(name)


@pytest.mark.parametrize("name", [n for n in RESERVED if n.replace("_", "").isalnum()])
@pytest.mark.parametrize(
    "where",
    [
        lambda name: {"env": ((name, "1"),)},
        lambda name: {"proxy_url_env": (name,)},
        lambda name: {"ca_file_env": (name,)},
        lambda name: {"token_env": name},
        lambda name: {"fake_key_env": ((name, "anthropic"),)},
    ],
    ids=["env", "proxy_url_env", "ca_file_env", "token_env", "fake_key_env"],
)
def test_a_profile_cannot_set_a_reserved_variable(name: str, where: Any) -> None:
    # GIT_CONFIG_KEY_0 and SSLKEYLOGFILE carry a secret's word: refused for that first.
    with pytest.raises(ValueError, match="set by the jail|never carry a secret|must end in _KEY"):
        profile(**where(name))


@pytest.mark.parametrize(
    "changes",
    [
        {"image": "ghcr.io/acme/agent:latest"},  # not pinned by digest
        {"image": "ghcr.io/acme/agent@sha256:abc"},
        {"entrypoint": "--privileged"},  # docker would read it as its own option
        {"entrypoint": "-v"},
        {"entrypoint": "tini agent"},
        {"entrypoint": ""},
        {"command": ["agent"]},  # a list, not a tuple
        {"command": ("agent\n--privileged",)},
        {"workdir": PurePosixPath("/etc")},
        {"workdir": PurePosixPath("/workspace/../etc")},
        {"workdir": PurePosixPath("work")},
        {"workdir": "/workspace/work"},  # a str, not a path
        {"workspace_dirs": ("work",)},  # HOME is /workspace/home
        {"workspace_dirs": ("home", "../x")},
        {"workspace_dirs": ("home", "home")},
        {"env": (("MY_API_KEY", "x"),)},  # a secret's name: the fake key has its own field
        {"env": (("GH_TOKEN", "x"),)},
        {"env": (("DB_PASSWORD", "x"),)},
        {"env": (("A", "line\nX=1"),)},
        {"env": (("1A", "x"),)},
        {"env": (("A", "1"), ("A", "2"))},
        {"env": (("A", "1"),), "proxy_url_env": ("A",)},  # the same variable twice
        {"fake_key_env": (("ANTHROPIC_API_KEY", "Not A Provider"),)},
        {"config_names": ("../openclaw.json",)},
        {"config_names": (".hidden",)},  # .<name>.tmp is the write in progress
        {"config_names": ("a/b.json",)},
        {"config_names": ("a.json", "a.json")},
        {"render_config": "not callable"},
        {"ready_log_line": "two\nlines"},
        {"rewind_notice_lines": ("",)},
        {"rewind_notice_lines": ["a list"]},
        {"provider_params": ("web_search",)},  # a provider-side tool: only the owner allows it
        {"provider_params": ("mcp_servers",)},
        {"provider_params": ("url_source",)},
        {"provider_params": ("param:",)},
        {"provider_params": ("param:Diagnostics",)},
        {"provider_params": ("param:diagnostics", "param:diagnostics")},
        # T17b-1: only the reviewed package registries, each once, as a tuple.
        {"allow_hosts": ["registry.npmjs.org"]},
        {"allow_hosts": ("example.com",)},
        {"allow_hosts": ("*.npmjs.org",)},
        {"allow_hosts": ("Registry.npmjs.org",)},
        {"allow_hosts": ("registry.npmjs.org.",)},
        {"allow_hosts": ("pypi.org", "pypi.org")},
        {"name": "Not A Name"},
        {"version": ""},
    ],
)
def test_invalid_profiles_are_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        profile(**changes)


def test_a_named_profile_may_list_the_reviewed_registries() -> None:
    """T17b-1 (docs/34, section 8): a programming agent's package registries go on the gate's
    allowed list, so an install is a read off the read budget. Only those reviewed in code."""
    hosts = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")
    assert set(hosts) == REVIEWED_ALLOW_HOSTS
    assert profile(allow_hosts=hosts).allow_hosts == hosts
    assert profile().allow_hosts == () and OPENCLAW.allow_hosts == ()


def test_the_custom_profile_lists_no_host() -> None:
    """Its hosts would come from the owner's TOML: those go in [proxy] allow_hosts, said there."""
    with pytest.raises(ValueError, match="allow_hosts"):
        profile(name=CUSTOM_NAME, allow_hosts=("pypi.org",))


@pytest.mark.parametrize(
    "line",
    ["a\x1b[2Jb", "a\u202eb", "a\u200bb", "a\tb", "a\x07b", "x" * 301],
    ids=["escape", "bidi", "zero-width", "tab", "bell", "too-long"],
)
def test_a_rewind_notice_line_is_printable_and_short(line: str) -> None:
    """Review of the profiles, L9: the lines go as they are to the terminal, Telegram and the
    web."""
    with pytest.raises(ValueError, match="printable text of at most 300"):
        profile(rewind_notice_lines=(line,))


def test_the_named_profiles_notice_lines_pass() -> None:
    assert OPENCLAW.rewind_notice_lines
    assert profile(rewind_notice_lines=("x" * 300, "Ñandú: ¿vuelve? «sí».")).rewind_notice_lines


# --- the image's own environment (review of the profiles, L6 and L8) -------------------------

# The two pinned images' own variables (docker image inspect in the VM): none is refused.
OPENCLAW_IMAGE_ENV = (
    "PATH=/home/node/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "NODE_VERSION=24.21.0", "YARN_VERSION=1.22.22", "COREPACK_HOME=/usr/local/share/corepack",
    "PLAYWRIGHT_BROWSERS_PATH=/home/node/.cache/ms-playwright", "NODE_ENV=production",
)  # fmt: skip
CLAUDE_CODE_IMAGE_ENV = (
    "PATH=/home/agent/.local/bin:/usr/local/share/npm-global/bin:/usr/local/sbin:/usr/local/bin"
    ":/usr/sbin:/usr/bin:/sbin:/bin",
    "NPM_CONFIG_PREFIX=/usr/local/share/npm-global",
    "NO_PROXY=localhost,127.0.0.1,::1,172.17.0.0/16",  # the jail's wins (not checked here)
    "BASH_ENV=/etc/sandbox-persistent.sh",  # the jail's wins
    "CLAUDE_ENV_FILE=/etc/sandbox-persistent.sh",
)
PYTHON_IMAGE_ENV = (
    "LANG=C.UTF-8", "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_VERSION=3.12.13", "PYTHON_SHA256=" + "7e" * 32, "PYTHONUNBUFFERED=1",
)  # fmt: skip


def _env_problems(entries: tuple[str, ...]) -> dict[str, str | None]:
    pairs = (entry.partition("=") for entry in entries)
    return {name: image_env_problem(name, value) for name, _, value in pairs}


@pytest.mark.parametrize(
    "entries", [OPENCLAW_IMAGE_ENV, PYTHON_IMAGE_ENV, CLAUDE_CODE_IMAGE_ENV[:2]], ids=str
)
def test_the_usual_images_own_variables_pass(entries: tuple[str, ...]) -> None:
    assert set(_env_problems(entries).values()) == {None}
    assert not any(image_secret(*entry.split("=", 1)) for entry in entries)


HOSTILE_IMAGE_ENV = {
    "LD_PRELOAD": "/workspace/work/evil.so",
    "LD_LIBRARY_PATH": "/usr/lib:/tmp/libs",
    "ld_audit": "/dev/shm/a.so",  # noqa: S108 - inside the container
    "NODE_OPTIONS": "--require /workspace/home/x.js",
    "node_options": "--import ./x.mjs",
    "PYTHONPATH": "/proc/self/cwd",
    "PYTHONSTARTUP": "~/.startup.py",
    "PERL5LIB": "lib",
    "PERL5OPT": "-Mx -I$HOME/lib",
    "RUBYLIB": "/usr/lib/ruby::/usr/lib/x",
    "PATH": "/usr/bin:.:/bin",
    "No_proxy": "*",
    "ALL_PROXY": "socks5://127.0.0.1:1080",
    "PROMPT_COMMAND": "true",
    "PS4": "$(id)",
    "BASH_FUNC_ls%%": "() { true; }",
    "ENV": "/etc/shrc",
    "GIT_CONFIG_COUNT": "1",
    "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/a.jar",
    "npm_config_userconfig": "/workspace/home/.npmrc",
    "GCONV_PATH": "/run/gconv",
}


@pytest.mark.parametrize(("name", "value"), HOSTILE_IMAGE_ENV.items(), ids=HOSTILE_IMAGE_ENV)
def test_an_images_loader_variable_pointing_at_the_agent_is_refused(name: str, value: str) -> None:
    why = image_env_problem(name, value)
    assert why is not None
    assert value not in why  # never quoted


def test_an_images_node_options_with_numbers_only_passes() -> None:
    assert image_env_problem("NODE_OPTIONS", "--max-old-space-size=4096") is None
    assert image_env_problem("NODE_OPTIONS", "--require x") is not None  # found from the cwd
    assert image_env_problem("LD_PRELOAD", "/usr/lib/libjemalloc.so.2") is None  # read-only
    assert image_env_problem("LD_PRELOAD", "") is None  # empty: nothing loaded


SECRET_IMAGE_ENV = {
    "LEAKED_API_TOKEN": "plain-looking-value-0",
    "DB_PASSWORD": "hunter2",
    "AWS_SECRET_ACCESS_KEY": "abcd",
    "SERVICE_CREDENTIALS": "x",
    "AGENT_SETTING": "sk-ant-api03-" + "Zz9" * 10,
}


@pytest.mark.parametrize(("name", "value"), SECRET_IMAGE_ENV.items(), ids=SECRET_IMAGE_ENV)
def test_an_images_secret_by_name_or_shape_is_refused(name: str, value: str) -> None:
    assert image_secret(name, value)


@pytest.mark.parametrize(
    "entry", ["GPG_KEY=7169605F", "NODE_SHA256=abc", "KEYRING_VERSION=1", "API_TOKEN="]
)
def test_the_images_public_names_pass(entry: str) -> None:
    assert not image_secret(*entry.split("=", 1))


def test_check_profile_param_only_allows_request_fields() -> None:
    assert check_profile_param("param:diagnostics") == "param:diagnostics"
    assert check_profile_param("param:client_metadata") == "param:client_metadata"
    for entry in ("web_search", "mcp_servers", "stored_prompt", "search_model", "param:", 3):
        with pytest.raises(ValueError):
            check_profile_param(entry)


def test_a_jail_config_needs_a_profile() -> None:
    with pytest.raises(ValueError, match="AgentProfile"):
        jail_config(agent="openclaw")  # type: ignore[arg-type]


def test_the_profile_image_is_the_default_and_an_override_is_still_pinned() -> None:
    other = profile()
    assert jail_config(other).image == IMAGE
    pinned = "ghcr.io/acme/other@sha256:" + "b" * 64
    assert jail_config(other, image=pinned).image == pinned
    with pytest.raises(ValueError, match="pinned"):
        jail_config(other, image="ghcr.io/acme/other:latest")


# --- what a profile changes in the argv, and what it cannot ---------------------------------

HOSTILE = profile(
    # All valid, and all trying: docker stops reading its options at the image, so these are
    # only the container's arguments.
    command=("--privileged", "-v", "/:/host", "--network", "host", "--user", "0:0"),
    workdir=PurePosixPath("/workspace/work"),
    env=(("AGENT_MODE", "--privileged"), ("XDG_CONFIG_HOME", "/workspace/home/.config")),
    proxy_url_env=("AGENT_PROXY_URL",),
    ca_file_env=("AGENT_CA_CERTIFICATE",),
    token_env="AGENT_GATEWAY_TOKEN",  # noqa: S106 - a name, not a secret
    fake_key_env=(("ANTHROPIC_API_KEY", "anthropic"), ("OPENAI_API_KEY", "openai")),
    config_names=("agent.toml",),
    render_config=lambda _config: {"agent.toml": "x = 1\n"},
)
PROVIDERS = (
    ModelProvider(name="anthropic", kind="anthropic", host="api.anthropic.com", fake_key=FAKE),
)


def _security_part(argv: list[str]) -> list[str]:
    """The argv up to the first variable: every security option, the mounts and the tmpfs."""
    return argv[: argv.index("--env")]


def test_a_profile_cannot_change_any_security_option_of_the_argv() -> None:
    openclaw = jail_config(model_providers=PROVIDERS)
    hostile = jail_config(HOSTILE, model_providers=PROVIDERS)
    assert _security_part(docker_create_argv(hostile)) == _security_part(
        docker_create_argv(openclaw)
    )


def test_the_jails_variables_always_win() -> None:
    jail = {name: value for name, value in container_env(jail_config()) if name in jail_env_names()}
    hostile = dict(container_env(jail_config(HOSTILE)))
    assert {name: hostile[name] for name in jail} == jail
    # The names the profile gave get the jail's values, never values of its own.
    assert hostile["AGENT_PROXY_URL"] == jail["HTTP_PROXY"]
    assert hostile["AGENT_CA_CERTIFICATE"] == jail["SSL_CERT_FILE"]


def test_the_profile_fills_in_only_its_part_of_the_argv() -> None:
    config = jail_config(HOSTILE, model_providers=PROVIDERS)
    argv = docker_create_argv(config)
    tail = argv[argv.index("--workdir") :]
    assert tail == [
        "--workdir", "/workspace/work", "--entrypoint", "tini", IMAGE, *HOSTILE.command,
    ]  # fmt: skip
    # The token and the fake key by name only: their values reach docker through its env.
    assert argv[argv.index("AGENT_GATEWAY_TOKEN") - 1] == "--env"
    assert argv[argv.index("ANTHROPIC_API_KEY") - 1] == "--env"
    assert TOKEN not in " ".join(argv) and FAKE not in " ".join(argv)
    # A provider without a fake key (openai is not configured) gets no variable.
    assert token_env(config) == {"AGENT_GATEWAY_TOKEN": TOKEN, "ANTHROPIC_API_KEY": FAKE}
    assert "OPENAI_API_KEY" not in argv


def test_a_profile_without_token_or_files_sends_neither() -> None:
    config = jail_config(profile())
    assert token_env(config) == {}
    assert config.config_files == ()
    assert "--workdir" not in docker_create_argv(config)
    with pytest.raises(ValueError, match="exactly one config file"):
        _ = config.config_file


def _good_info(config: AgentJailConfig) -> dict[str, Any]:
    """What verify.py accepts, from the snapshot of OpenClaw's, with the profile's parts."""
    snapshot = json.loads(
        (Path(__file__).parent / "fixtures" / "openclaw_jail_snapshot.json").read_text()
    )
    info = snapshot["configs"]["plain"]["good_info"]
    env = dict(entry.split("=", 1) for entry in snapshot["image_env"])
    env |= dict(container_env(config)) | token_env(config)
    info["Config"] |= {
        "Image": config.image,
        "Entrypoint": [config.profile.entrypoint],
        "Cmd": list(config.profile.command),
        "Env": [f"{name}={value}" for name, value in env.items()],
    }
    if config.profile.workdir is not None:
        info["Config"]["WorkingDir"] = str(config.profile.workdir)
    return info


def _problems(config: AgentJailConfig, info: dict[str, Any]) -> list[str]:
    snapshot = json.loads(
        (Path(__file__).parent / "fixtures" / "openclaw_jail_snapshot.json").read_text()
    )
    return container_problems(
        config, info, seccomp_profile=snapshot["seccomp_profile"], image_env=snapshot["image_env"]
    )


def test_verify_expects_the_profiles_command_workdir_and_secret_variables() -> None:
    config = jail_config(HOSTILE, model_providers=PROVIDERS)
    good = _good_info(config)
    assert _problems(config, good) == []
    wrong_dir = json.loads(json.dumps(good))
    wrong_dir["Config"]["WorkingDir"] = "/"
    assert _problems(config, wrong_dir) == ["WorkingDir is '/', not '/workspace/work'"]
    no_key = json.loads(json.dumps(good))
    no_key["Config"]["Env"] = [e for e in good["Config"]["Env"] if "ANTHROPIC_API_KEY" not in e]
    assert _problems(config, no_key) == ["its environment differs in ['ANTHROPIC_API_KEY']"]
    # OpenClaw's container is not this profile's jail.
    assert "Cmd is" in " ".join(_problems(config, _good_info(jail_config())))


def test_verify_still_checks_every_security_field_for_any_profile() -> None:
    config = jail_config(HOSTILE, model_providers=PROVIDERS)
    good = _good_info(config)
    for path, value in (
        ("HostConfig.Privileged", True),
        ("HostConfig.CapAdd", ["SYS_ADMIN"]),
        ("HostConfig.ReadonlyRootfs", False),
        ("HostConfig.Binds", ["/:/host"]),
        ("HostConfig.NetworkMode", "host"),
        ("Config.User", "0:0"),
    ):
        info = json.loads(json.dumps(good))
        section, name = path.split(".")
        info[section][name] = value
        assert _problems(config, info), path


# --- the jail with a profile: folders, config files, ready ----------------------------------


@pytest.fixture
def local(tmp_path: Path) -> dict[str, Any]:
    workspace = tmp_path / "root" / "workspace"
    workspace.mkdir(parents=True)
    ca_dir = tmp_path / "agent-ca"
    ca_dir.mkdir(mode=0o755)
    (ca_dir / "ca.pem").write_text(CERTIFICATE)
    return {
        "workspace": workspace,
        "config_dir": tmp_path / "agent-config",
        "ca_dir": ca_dir,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "allow_shared_ids": True,
    }


def test_prepare_workspace_creates_the_profiles_folders(local: dict[str, Any]) -> None:
    jail = AgentJail(AgentJailConfig(**local, profile=profile(workspace_dirs=("home", "src"))))
    jail.prepare_workspace()
    assert sorted(p.name for p in jail.config.agent_dir.iterdir()) == ["home", "src"]


def test_prepare_workspace_creates_the_profiles_working_folder(local: dict[str, Any]) -> None:
    """Review of the profiles, L5: backtide makes it, for the agent; Docker would otherwise
    create a missing one itself, as root."""
    agent = profile(workdir=PurePosixPath("/workspace/work/repo/src"))
    jail = AgentJail(AgentJailConfig(**local, profile=agent))
    jail.prepare_workspace()
    folder = jail.config.agent_dir / "work" / "repo" / "src"
    assert folder.is_dir() and not folder.is_symlink()
    assert folder.stat().st_uid == os.getuid() and stat.S_IMODE(folder.stat().st_mode) == 0o700
    jail.write_config()
    jail._check_mount_sources()  # noqa: SLF001 - what create() and start() check first


@pytest.mark.parametrize("link", ["work/repo", "work/repo/src", "work"])
def test_a_symlinked_working_folder_is_refused(local: dict[str, Any], link: str) -> None:
    """The agent controls everything below /workspace: its working folder, or any folder on
    the way to it, made a symlink is never followed, at prepare, create or start."""
    agent = profile(workdir=PurePosixPath("/workspace/work/repo/src"))
    jail = AgentJail(AgentJailConfig(**local, profile=agent))
    jail.prepare_workspace()
    jail.write_config()
    target = jail.config.agent_dir / link
    elsewhere = local["workspace"].parent / "elsewhere"
    (elsewhere / "repo" / "src").mkdir(parents=True)
    _replace_with_link(target, elsewhere if link == "work" else elsewhere / target.name)
    with pytest.raises(JailError, match="not a directory \\(a symlink"):
        jail._check_mount_sources()  # noqa: SLF001
    with pytest.raises(JailError, match="not a directory \\(a symlink"):
        jail.prepare_workspace()


def test_a_missing_working_folder_is_refused_at_start(local: dict[str, Any]) -> None:
    agent = profile(workdir=PurePosixPath("/workspace/work/repo"))
    jail = AgentJail(AgentJailConfig(**local, profile=agent))
    jail.prepare_workspace()
    jail.write_config()
    (jail.config.agent_dir / "work" / "repo").rmdir()
    with pytest.raises(JailError, match="repo is missing"):
        jail._check_mount_sources()  # noqa: SLF001


def _replace_with_link(path: Path, target: Path) -> None:
    for child in sorted(path.rglob("*"), reverse=True):
        child.rmdir()
    path.rmdir()
    path.symlink_to(target)


def test_a_profile_without_config_files_gets_an_empty_folder(local: dict[str, Any]) -> None:
    jail = AgentJail(AgentJailConfig(**local, profile=profile()))
    jail.prepare_workspace()
    jail.write_config()
    assert list(jail.config.config_dir.iterdir()) == []
    jail._check_mount_sources()  # the folder is still mounted, and must be empty
    (jail.config.config_dir / "stray").write_text("x")
    with pytest.raises(JailError, match="must be empty; found \\['stray'\\]"):
        jail.write_config()


def test_write_config_writes_the_profiles_files_after_its_check(local: dict[str, Any]) -> None:
    checked: list[Mapping[str, str]] = []
    agent = profile(
        config_names=("a.toml", "b.json"),
        render_config=lambda _config: {"a.toml": "a = 1\n", "b.json": "{}\n"},
        check_config=checked.append,
    )
    jail = AgentJail(AgentJailConfig(**local, profile=agent))
    jail.write_config()
    assert checked == [{"a.toml": "a = 1\n", "b.json": "{}\n"}]
    assert (jail.config.config_dir / "a.toml").read_text() == "a = 1\n"
    assert sorted(p.name for p in jail.config.config_dir.iterdir()) == ["a.toml", "b.json"]


def test_write_config_refuses_files_the_profile_did_not_declare(local: dict[str, Any]) -> None:
    agent = profile(config_names=("a.toml",), render_config=lambda _c: {"other.toml": ""})
    with pytest.raises(JailError, match="other.toml"):
        AgentJail(AgentJailConfig(**local, profile=agent)).write_config()
    assert not Path(local["config_dir"]).exists()


def test_a_refused_config_is_a_profile_error_and_never_written(local: dict[str, Any]) -> None:
    def refuse(_files: Mapping[str, str]) -> None:
        raise ProfileError("no")

    agent = profile(
        config_names=("a.toml",), render_config=lambda _c: {"a.toml": ""}, check_config=refuse
    )
    with pytest.raises(ProfileError):
        AgentJail(AgentJailConfig(**local, profile=agent)).write_config()
    assert not Path(local["config_dir"]).exists()
    assert issubclass(UnrewindableConfig, ProfileError)  # OpenClaw's, caught the same way


def test_without_a_ready_line_or_probe_running_is_ready(
    local: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_docker(*args: object, **kwargs: object) -> None:
        raise AssertionError("nothing to ask docker")

    monkeypatch.setattr(agent_module.docker, "run", no_docker)
    jail = AgentJail(AgentJailConfig(**local, profile=profile()))
    assert jail._logged_ready("") and jail._healthy()


# --- the service ----------------------------------------------------------------------------


def test_the_service_uses_the_default_profile_and_its_provider_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ServiceConfig(
        state_dir=tmp_path / "state", volume=tmp_path / "volume", gateway_token=Secret(TOKEN)
    )
    assert config.agent_profile is OPENCLAW
    assert config.jail_config().profile is OPENCLAW
    assert config.proxy_settings().allow_provider_tools == ()  # OpenClaw declares none
    agent = profile(provider_params=("param:diagnostics",))
    monkeypatch.setattr(ServiceConfig, "agent_profile", property(lambda _self: agent))
    assert config.proxy_settings().allow_provider_tools == ("param:diagnostics",)
    assert config.jail_config().profile is agent


def test_the_profiles_hosts_join_the_owners_allowed_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T17b-1: the owner's [proxy] allow_hosts first, then the profile's, each once."""
    config = ServiceConfig(
        state_dir=tmp_path / "state",
        volume=tmp_path / "volume",
        gateway_token=Secret(TOKEN),
        proxy={"allow_hosts": ["github.com", "pypi.org"]},
    )
    assert config.proxy_settings().allow_hosts == ("github.com", "pypi.org")  # OpenClaw: none
    agent = profile(allow_hosts=("registry.npmjs.org", "pypi.org"))
    monkeypatch.setattr(ServiceConfig, "agent_profile", property(lambda _self: agent))
    assert config.proxy_settings().allow_hosts == ("github.com", "pypi.org", "registry.npmjs.org")
    # Only what the owner did not list already is the profile's (no WebSocket there).
    assert config.proxy_settings().profile_hosts == ("registry.npmjs.org",)
