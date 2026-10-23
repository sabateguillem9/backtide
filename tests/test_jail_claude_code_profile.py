"""The Claude Code profile (T17a-4, docs/34 sections 4, 7 and 11): its jail, its settings file and
their check, its provider, its fields, the rewind notice, the shell commands, the first-run seed,
and npm's reviewed settings that only a named profile may set. OpenClaw's jail, byte for byte, is
still test_jail_openclaw_snapshot.py."""

import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from backtide.gate.providers import Providers, is_fake_key
from backtide.jail.config import container_env, create_env, docker_create_argv, token_env
from backtide.jail.profile import (
    MAX_PROMPT,
    REVIEWED_RESERVED_ENV,
    AgentProfile,
    ProfileError,
    ShellCommands,
    check_prompt,
)
from backtide.jail.profiles import NAMED, OPENCLAW, claude_code
from backtide.jail.profiles.claude_code import (
    CLAUDE,
    CLAUDE_CODE,
    IMAGE,
    SEED,
    SETTINGS,
    SETTINGS_FILE,
    UnsafeSettings,
    check_settings,
    render_settings,
    version_answer,
)
from backtide.service.config import ConfigError, ServiceConfig
from backtide.service.notice import rewind_notice
from backtide.service.runner import egress_policy

PROVIDER = '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\n'
TOML = f'[agent]\nprofile = "claude-code"\n[proxy]\n{PROVIDER}'
OTHER_IMAGE = "ghcr.io/acme/agent@sha256:" + "d" * 64


@pytest.fixture
def layout(tmp_path: Path) -> Path:
    (tmp_path / "state").mkdir(mode=0o700)
    (tmp_path / "volume").mkdir()
    return tmp_path


def load(layout: Path, text: str = TOML) -> ServiceConfig:
    path = layout / "backtide.toml"
    path.write_text(f'state_dir = "{layout / "state"}"\nvolume = "{layout / "volume"}"\n{text}')
    path.chmod(0o600)
    return ServiceConfig.from_file(path)


def profile_with(**changes: object) -> AgentProfile:
    fields = {
        "name": "claude-code",
        "version": "1",
        "image": IMAGE,
        "entrypoint": "tini",
        "command": ("--", "sleep", "infinity"),
    }
    return AgentProfile(**{**fields, **changes})  # type: ignore[arg-type]


# --- the profile and its jail -----------------------------------------------------------------


def test_claude_code_is_a_named_profile_of_the_shell_mode() -> None:
    assert NAMED["claude-code"] is CLAUDE_CODE
    profile = CLAUDE_CODE
    assert profile.mode == "shell" and profile.shell is not None
    assert profile.version == "2.1.306"
    assert profile.image == (
        "docker/sandbox-templates"
        "@sha256:30ec2b1bb76e3993aff912c553a5c249ad95b595249a32fde7158eafb71bda25"
    )
    assert (profile.entrypoint, profile.command) == ("tini", ("--", "sleep", "infinity"))
    assert profile.workdir == PurePosixPath("/workspace/work")
    assert profile.workspace_dirs == ("home", "work")
    assert profile.fake_key_env == (("ANTHROPIC_API_KEY", "anthropic"),)
    assert profile.provider_params == ("param:diagnostics",)
    assert profile.allow_hosts == ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")
    assert profile.token_env is None
    assert profile.config_names == ("claude.json",)
    assert OPENCLAW.mode == "service" and OPENCLAW.shell is None


def test_its_jail_from_backtide_toml(layout: Path) -> None:
    config = load(layout)
    assert config.agent_profile is CLAUDE_CODE
    assert config.gateway_token is None
    assert config.agent_config_dir == layout / "state" / "claude-code"
    jail = config.jail_config()
    argv = docker_create_argv(jail)
    tail = argv[argv.index("--workdir") :]
    assert tail == ["--workdir", "/workspace/work", "--entrypoint", "tini", IMAGE, "--", "sleep",
                    "infinity"]  # fmt: skip
    env = dict(container_env(jail))
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert env["CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"] == "1"
    for name, value in REVIEWED_RESERVED_ENV:
        assert env[name] == value
        assert ["--env", name] == argv[argv.index(name) - 1 : argv.index(name) + 1]  # by name
    assert (env["BASH_ENV"], env["CLAUDE_ENV_FILE"]) == ("/dev/null", "/dev/null")
    secrets = token_env(jail)
    assert list(secrets) == ["ANTHROPIC_API_KEY"]
    assert is_fake_key(secrets["ANTHROPIC_API_KEY"], "anthropic")
    assert not any(secrets["ANTHROPIC_API_KEY"] in arg for arg in argv)
    assert create_env(jail)["npm_config_audit"] == "false"
    assert "param:diagnostics" in config.proxy_settings().allow_provider_tools
    # T17b-1: npm's and PyPI's registries are on the gate's allowed list (no read budget), and
    # the audit's POST after an install is off (npm_config_audit, above).
    assert config.proxy_settings().allow_hosts == CLAUDE_CODE.allow_hosts
    assert egress_policy(config, Providers([])).allow_list().allows("files.pythonhosted.org")


def test_its_provider_must_be_anthropic_at_its_real_host(layout: Path) -> None:
    for provider in (
        '[[proxy.providers]]\nname = "anthropic"\nkind = "anthropic"\nhost = "a.example.com"\n',
        '[[proxy.providers]]\nname = "anthropic"\nkind = "openai"\nhost = "o.example.com"\n',
    ):
        with pytest.raises(ConfigError, match="Claude Code needs"):
            load(layout, f'[agent]\nprofile = "claude-code"\n[proxy]\n{provider}')
    with pytest.raises(ConfigError, match="'anthropic' is not one of"):
        load(layout, '[agent]\nprofile = "claude-code"\n')


def test_a_custom_setting_is_refused_for_it(layout: Path) -> None:
    with pytest.raises(ConfigError, match='only for profile = "custom"'):
        load(layout, f'[agent]\nprofile = "claude-code"\nentrypoint = ["sh"]\n[proxy]\n{PROVIDER}')


def test_its_image_may_be_replaced_by_another_pinned_one(layout: Path) -> None:
    config = load(layout, f'[agent]\nprofile = "claude-code"\nimage = "{OTHER_IMAGE}"\n'
                  f"[proxy]\n{PROVIDER}")  # fmt: skip
    assert config.jail_config().image == OTHER_IMAGE


def test_ready_means_the_pinned_claude_answers_its_version() -> None:
    assert CLAUDE_CODE.ready_probe == (CLAUDE, "--version")
    assert version_answer("2.1.306 (Claude Code)\n")
    assert not version_answer("2.1.308 (Claude Code)\n")
    assert not version_answer("")


# --- /config/claude.json ------------------------------------------------------------------------


def test_the_settings_are_exactly_the_measured_ones(layout: Path) -> None:
    files = render_settings(load(layout).jail_config())
    assert list(files) == [SETTINGS_FILE]
    assert json.loads(files[SETTINGS_FILE]) == {
        "skipWebFetchPreflight": True,
        "skipDangerousModePermissionPrompt": True,
        "permissions": {"deny": ["WebSearch"]},
    }
    check_settings(files)  # passes


@pytest.mark.parametrize(
    "change",
    [
        {"apiKeyHelper": "/workspace/home/key.sh"},
        {"env": {"HTTPS_PROXY": "http://elsewhere"}},
        {"hooks": {"PreToolUse": []}},
        {"statusLine": {"type": "command", "command": "id"}},
        {"permissions": {"deny": []}},
        {"permissions": {"deny": ["WebSearch"], "allow": ["Bash"]}},
        {"skipWebFetchPreflight": False},
        {"skipDangerousModePermissionPrompt": None},
        # Equal for Python, not the reviewed value (B2 of the review of T17a-4).
        {"skipWebFetchPreflight": 1},
        {"skipDangerousModePermissionPrompt": 1.0},
        {"permissions": {"deny": ["WebSearch"], "allow": []}},
    ],
)
def test_anything_else_in_the_settings_is_refused(change: dict[str, object]) -> None:
    settings = {**SETTINGS, **change}
    settings = {key: value for key, value in settings.items() if value is not None}
    with pytest.raises(UnsafeSettings) as refused:
        check_settings({SETTINGS_FILE: json.dumps(settings)})
    assert isinstance(refused.value, ProfileError)
    assert refused.value.paths  # names the keys...
    assert "elsewhere" not in str(refused.value) and "key.sh" not in str(refused.value)  # ...only


@pytest.mark.parametrize("text", ["", "{", "[]", '"x"'])
def test_settings_that_are_not_an_object_are_refused(text: str) -> None:
    with pytest.raises(UnsafeSettings):
        check_settings({SETTINGS_FILE: text})
    with pytest.raises(UnsafeSettings):
        check_settings({})


# --- the rewind notice --------------------------------------------------------------------------


def test_the_rewind_notice_says_what_is_lost() -> None:
    from datetime import UTC, datetime

    lines = CLAUDE_CODE.rewind_notice_lines
    assert any("--continue" in line for line in lines)
    assert any("se ha cortado" in line for line in lines)
    assert any("no vuelve" in line for line in lines)
    now = datetime(2026, 10, 22, 12, tzinfo=UTC)
    notice = rewind_notice(now, now=now, tz=UTC, agent_lines=lines)
    assert all(line in notice for line in lines)


# --- npm's reviewed settings (Decidido por defecto, revisable) ---------------------------------


def test_a_named_profile_may_set_exactly_the_reviewed_npm_settings() -> None:
    assert REVIEWED_RESERVED_ENV == {
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
    }
    profile_with(env=tuple(sorted(REVIEWED_RESERVED_ENV)))  # passes


@pytest.mark.parametrize(
    "pair",
    [
        ("npm_config_audit", "true"),
        ("npm_config_audit", "False"),
        ("NPM_CONFIG_AUDIT", "false"),
        ("npm_config_registry", "https://registry.example.com"),
        ("npm_config_script_shell", "/workspace/home/sh"),
        ("npm_config_fund", ""),
    ],
)
def test_any_other_npm_setting_is_refused_even_for_a_named_profile(pair: tuple[str, str]) -> None:
    with pytest.raises(ValueError, match="set by the jail, never by a profile"):
        profile_with(env=(pair,))


def test_the_custom_profile_never_gets_the_reviewed_npm_settings(layout: Path) -> None:
    with pytest.raises(ValueError, match="set by the jail"):
        profile_with(name="custom", env=(("npm_config_audit", "false"),))
    text = (
        f'[agent]\nprofile = "custom"\nimage = "{OTHER_IMAGE}"\nentrypoint = ["tini", "--"]\n'
        'env = { npm_config_audit = "false" }\n'
    )
    with pytest.raises(ConfigError, match="npm_config_audit is set by the jail"):
        load(layout, text)


def test_a_reviewed_name_cannot_also_be_the_fake_keys_variable() -> None:
    with pytest.raises(ValueError):
        profile_with(
            env=(("npm_config_audit", "false"),),
            fake_key_env=(("npm_config_audit", "anthropic"),),
        )


# --- the shell mode -----------------------------------------------------------------------------


def test_a_shell_profile_has_shell_commands_and_only_it() -> None:
    shell = ShellCommands(session=("agent",), task=("agent", "-p"), resume="--continue")
    with pytest.raises(ValueError, match='if and only if its mode is "shell"'):
        profile_with(mode="shell")
    with pytest.raises(ValueError, match='if and only if its mode is "shell"'):
        profile_with(shell=shell)
    with pytest.raises(ValueError, match="mode must be one of"):
        profile_with(mode="daemon")
    assert profile_with(mode="shell", shell=shell).shell is shell


@pytest.mark.parametrize(
    "fields",
    [
        {"session": ()},
        {"session": ("-x",)},
        {"task": ("agent\n",)},
        {"resume": "continue"},
        {"resume": "--continue now"},
        {"seed_input": "print(1)"},  # an input without a seed
        {"seed": ("python3",), "seed_input": "x" * (16 * 1024 + 1)},
    ],
)
def test_odd_shell_commands_are_refused(fields: dict[str, object]) -> None:
    base: dict[str, object] = {"session": ("agent",), "task": ("agent",), "resume": "--continue"}
    with pytest.raises(ValueError):
        ShellCommands(**{**base, **fields})  # type: ignore[arg-type]


def test_the_commands_of_claude_code() -> None:
    shell = CLAUDE_CODE.shell
    assert shell is not None
    common = ["--dangerously-skip-permissions", "--settings", "/config/claude.json"]
    assert shell.session_argv() == [CLAUDE, *common]
    assert shell.session_argv(resume=True) == [CLAUDE, *common, "--continue"]
    task = [CLAUDE, "-p", "--output-format", "json", *common]
    assert shell.task_argv("hola") == [*task, "--", "hola"]
    # A prompt that looks like an option is still the prompt: it goes after "--".
    assert shell.task_argv("--version", resume=True) == [*task, "--continue", "--", "--version"]
    assert shell.seed == ("python3", "-I", "-") and shell.seed_input == SEED


@pytest.mark.parametrize("prompt", ["", "   ", "a\0b", "x" * (MAX_PROMPT + 1), None])
def test_a_prompt_that_cannot_be_one_argument_is_refused(prompt: object) -> None:
    with pytest.raises(ValueError):
        check_prompt(prompt)


def test_a_long_prompt_with_newlines_is_one_argument() -> None:
    text = "línea uno\nlínea dos\n" * 10
    assert claude_code.CLAUDE_CODE.shell.task_argv(text)[-1] == text  # type: ignore[union-attr]


# --- the first-run seed (~/.claude.json) --------------------------------------------------------

FAKE = "backtide-fake-anthropic-" + "Q" * 32


def seed(home: Path, *, key: str | None = FAKE) -> subprocess.CompletedProcess[str]:
    """The seed as `backtide entrar` runs it in the container: ``python3 -I -``, as the agent."""
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", "")}
    if key is not None:
        env["ANTHROPIC_API_KEY"] = key
    return subprocess.run(
        [sys.executable, "-I", "-"],
        input=SEED,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def state(home: Path) -> dict[str, object]:
    return json.loads((home / ".claude.json").read_text())


def test_the_seed_writes_the_three_first_run_answers(tmp_path: Path) -> None:
    done = seed(tmp_path)
    assert (done.returncode, done.stdout) == (0, "seeded\n"), done.stderr
    assert state(tmp_path) == {
        "hasCompletedOnboarding": True,
        "projects": {"/workspace/work": {"hasTrustDialogAccepted": True}},
        "customApiKeyResponses": {"approved": [FAKE[-20:]], "rejected": []},
    }
    assert (tmp_path / ".claude.json").stat().st_mode & 0o777 == 0o600
    again = seed(tmp_path)
    assert (again.returncode, again.stdout) == (0, "unchanged\n")


def test_the_seed_keeps_what_claude_code_wrote(tmp_path: Path) -> None:
    (tmp_path / ".claude.json").write_text(
        json.dumps(
            {
                "numStartups": 3,
                "projects": {"/workspace/work": {"allowedTools": []}, "/other": {"x": 1}},
                "customApiKeyResponses": {"approved": ["old"], "rejected": [FAKE[-20:]]},
            }
        )
    )
    assert seed(tmp_path).returncode == 0
    found = state(tmp_path)
    assert found["numStartups"] == 3
    assert found["projects"] == {
        "/workspace/work": {"allowedTools": [], "hasTrustDialogAccepted": True},
        "/other": {"x": 1},
    }
    assert found["customApiKeyResponses"] == {"approved": ["old", FAKE[-20:]], "rejected": []}


def test_without_a_key_the_seed_writes_no_key_answer(tmp_path: Path) -> None:
    assert seed(tmp_path, key=None).returncode == 0
    assert "customApiKeyResponses" not in state(tmp_path)


@pytest.mark.parametrize("text", ["{not json", "[1, 2]"])
def test_a_file_the_seed_cannot_read_is_left_as_it_is(tmp_path: Path, text: str) -> None:
    (tmp_path / ".claude.json").write_text(text)
    done = seed(tmp_path)
    assert done.returncode != 0 and "left as it is" in done.stderr
    assert (tmp_path / ".claude.json").read_text() == text


def test_the_seed_replaces_a_link_and_never_writes_through_it(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("{}")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").symlink_to(elsewhere)
    assert seed(home).returncode == 0
    assert elsewhere.read_text() == "{}"
    assert not (home / ".claude.json").is_symlink()
    assert state(home)["hasCompletedOnboarding"] is True
