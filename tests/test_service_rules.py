"""The risk rules inside the service (T08): where the file lives, how it is read, and what
`build_guardian` does with it. Nothing touches Docker, btrfs or inotify (as in
test_service_runner.py)."""

import os
from pathlib import Path

import pytest

from tests.test_service_runner import TOKEN, StubJail
from vigia.analyzer import AssessedBlackBox, RiskResponder
from vigia.jail import JailError
from vigia.service.config import ConfigError, Secret, ServiceConfig
from vigia.service.runner import build_guardian, load_rules

RULES = """
[[rule]]
id = "only-one"
description = "La única regla"
risk = 3
source = "exec"
target = "wipe*"
"""


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return ServiceConfig(state_dir=state, volume=tmp_path / "vol", gateway_token=Secret(TOKEN))


def write_rules(config: ServiceConfig, text: str, mode: int = 0o600) -> Path:
    config.rules_file.write_text(text, encoding="utf-8")
    config.rules_file.chmod(mode)
    return config.rules_file


def test_the_rules_file_is_in_the_state_folder_which_the_agent_never_sees(
    config: ServiceConfig,
) -> None:
    assert config.rules_file == config.state_dir / "rules.toml"
    assert config.rules_file.is_relative_to(config.state_dir)
    # ServiceConfig refuses a state_dir inside what is mounted into the agent (invariant 1), so
    # the rules can never be inside it either.
    assert not config.rules_file.is_relative_to(config.agent_config_dir)
    assert not config.rules_file.is_relative_to(config.volume)


def test_without_a_file_the_default_rules_apply(config: ServiceConfig) -> None:
    assert config.read_rules() is None
    assert load_rules(config).origin == "reglas por defecto"


def test_a_file_replaces_the_default_rules_entirely(config: ServiceConfig) -> None:
    write_rules(config, RULES)
    rules = load_rules(config)
    assert [r.id for r in rules.rules] == ["only-one"]
    assert rules.origin == str(config.rules_file)


def test_a_wrong_file_is_a_config_error_that_names_the_file_the_rule_and_the_key(
    config: ServiceConfig,
) -> None:
    write_rules(config, RULES.replace("risk = 3", "risk = 9"))
    with pytest.raises(ConfigError) as error:
        load_rules(config)
    message = str(error.value)
    assert str(config.rules_file) in message
    assert "only-one" in message and "risk" in message


def test_a_file_that_is_not_utf8_or_not_toml_is_a_config_error(
    config: ServiceConfig,
) -> None:
    config.rules_file.write_bytes(b"\xff\xfe")
    config.rules_file.chmod(0o600)
    with pytest.raises(ConfigError, match="UTF-8"):
        load_rules(config)
    write_rules(config, "[[rule")
    with pytest.raises(ConfigError, match="TOML"):
        load_rules(config)


def test_a_file_writable_by_others_a_symlink_or_a_giant_is_refused(
    config: ServiceConfig,
    tmp_path: Path,
) -> None:
    write_rules(config, RULES, mode=0o666)
    with pytest.raises(ConfigError, match="writable by group or others"):
        load_rules(config)
    config.rules_file.unlink()
    elsewhere = tmp_path / "elsewhere.toml"
    elsewhere.write_text(RULES)
    elsewhere.chmod(0o600)
    config.rules_file.symlink_to(elsewhere)
    with pytest.raises(ConfigError, match="symlink"):
        load_rules(config)
    config.rules_file.unlink()
    write_rules(config, "# " + "x" * (70 * 1024))
    with pytest.raises(ConfigError, match="too big"):
        load_rules(config)


def test_build_guardian_puts_the_rules_in_front_of_the_black_box_of_both(
    config: ServiceConfig,
) -> None:
    write_rules(config, RULES)
    guardian, alerts, box = build_guardian(config)
    rated = guardian._box  # noqa: SLF001
    assert isinstance(rated, AssessedBlackBox)
    assert guardian._watcher._box is rated  # noqa: SLF001 - the watcher records through it too
    assert [r.id for r in rated.rules.rules] == ["only-one"]
    assert isinstance(guardian._risk, RiskResponder)  # noqa: SLF001
    assert box is not rated  # the third value is still the raw black box the runner closes
    assert alerts is guardian._alerts  # noqa: SLF001


def test_the_responder_is_bound_to_the_guardians_evidence_snapshot(
    config: ServiceConfig,
) -> None:
    guardian, _, _ = build_guardian(config)
    responder = guardian._risk  # noqa: SLF001
    assert responder._snapshot == guardian.take_evidence  # noqa: SLF001


def test_wrong_rules_stop_an_agent_a_killed_service_left_running(
    config: ServiceConfig,
) -> None:
    write_rules(config, "not toml [[")
    jail = StubJail(running=True)
    with pytest.raises(ConfigError):
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert not jail.running
    assert jail.calls == ["kill"]  # nobody watches it: killed, not given 30 s to stop


def test_wrong_rules_with_no_agent_running_touch_nothing(config: ServiceConfig) -> None:
    write_rules(config, "not toml [[")
    jail = StubJail(running=False)
    with pytest.raises(ConfigError):
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert jail.calls == []
    assert not os.path.lexists(config.blackbox_db)  # nothing was created


def test_wrong_rules_and_an_agent_that_will_not_stop_say_it_keeps_running(
    config: ServiceConfig,
) -> None:
    write_rules(config, "not toml [[")
    jail = StubJail(running=True)
    jail.fail_to_stop = True
    with pytest.raises(JailError, match="SIGUE EN MARCHA") as error:
        build_guardian(config, jail=jail)  # type: ignore[arg-type]
    assert "reglas de riesgo" in str(error.value)
    assert isinstance(error.value.__cause__, ConfigError)
