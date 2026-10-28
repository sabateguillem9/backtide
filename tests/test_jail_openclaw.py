"""check_rewindable: docs/20-openclaw-autorizacion-y-rebobinado.md, section 8, rules 1-13.

Each rule has at least one config that passes and one that fails. A failing config must name
the offending path, so the log (English) and the user notice (Spanish) point at the exact key.
"""

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.config import AgentJailConfig, openclaw_config
from backtide.jail.openclaw import (
    RewindProblem,
    UnrewindableConfig,
    check_rewindable,
    problems_in,
)

Config = dict[str, Any]
Edit = Callable[[Config], None]

TOKEN = "u" * 43


@pytest.fixture
def base() -> Config:
    return openclaw_config(
        AgentJailConfig(
            workspace=Path("/w"), config_dir=Path("/c"), ca_dir=Path("/ca"), gateway_token=TOKEN
        )
    )


def telegram(**extra: Any) -> Config:
    """docs/20 section 8, "Configuración mínima segura para Telegram" (the channel part)."""
    return {
        "dmPolicy": "allowlist",
        "allowFrom": ["123456789"],
        "groupPolicy": "disabled",
        "commands": {"native": False},
        **extra,
    }


def with_telegram(config: Config, **extra: Any) -> Config:
    config = copy.deepcopy(config)
    config["channels"] = {"telegram": telegram(**extra)}
    return config


def paths(config: Config) -> list[str]:
    return [problem.path for problem in problems_in(config)]


# The baseline and the minimal safe config


def test_the_baseline_config_passes(base: Config) -> None:
    check_rewindable(base)
    assert problems_in(base) == []


def test_the_minimal_safe_telegram_config_passes(base: Config) -> None:
    check_rewindable(with_telegram(base))


def test_the_baseline_has_the_gateway_and_plugin_defences(base: Config) -> None:
    assert base["gateway"]["nodes"]["pairing"]["sshVerify"] is False
    assert base["plugins"]["entries"]["device-pair"]["enabled"] is False


def test_an_empty_config_is_refused_for_what_it_leaves_to_the_defaults() -> None:
    # No gateway, no cron, no device-pair block: every default is the unsafe one.
    found = paths({})
    for expected in (
        "gateway.bind",
        "gateway.auth.mode",
        "gateway.nodes.pairing.sshVerify",
        "plugins.entries.device-pair.enabled",
        "cron.enabled",
        "tools.deny",
    ):
        assert expected in found


def test_a_config_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(UnrewindableConfig):
        check_rewindable([])  # type: ignore[arg-type]


# Rule 1: only Telegram


def test_rule1_no_channels_passes(base: Config) -> None:
    assert "channels" not in base
    check_rewindable(base)


@pytest.mark.parametrize("channel", ["whatsapp", "signal", "matrix", "discord", "slack", "irc"])
def test_rule1_other_channels_fail(base: Config, channel: str) -> None:
    config = with_telegram(base)
    config["channels"][channel] = {"dmPolicy": "allowlist", "allowFrom": ["1"]}
    assert paths(config) == [f"channels.{channel}"]


def test_rule1_a_disabled_other_channel_still_fails(base: Config) -> None:
    base["channels"] = {"discord": {"enabled": False}}
    assert paths(base) == ["channels.discord"]


def test_rule1_channels_must_be_an_object(base: Config) -> None:
    base["channels"] = ["telegram"]
    assert paths(base) == ["channels"]


# Rule 2: direct-message policy, with the default being "pairing"


@pytest.mark.parametrize("policy", ["allowlist", "disabled"])
def test_rule2_allowlist_and_disabled_pass(base: Config, policy: str) -> None:
    check_rewindable(with_telegram(base, dmPolicy=policy))


def test_rule2_a_missing_dm_policy_fails_because_the_default_is_pairing(base: Config) -> None:
    config = with_telegram(base)
    del config["channels"]["telegram"]["dmPolicy"]
    [problem] = problems_in(config)
    assert problem.path == "channels.telegram.dmPolicy"
    assert "pairing" in problem.why


@pytest.mark.parametrize("policy", ["pairing", "open", "Allowlist", "", None, 3, ["allowlist"]])
def test_rule2_any_other_dm_policy_fails(base: Config, policy: object) -> None:
    config = with_telegram(base, dmPolicy=policy)
    assert paths(config) == ["channels.telegram.dmPolicy"]


def test_rule2_an_account_without_its_own_policy_inherits_the_root(base: Config) -> None:
    check_rewindable(with_telegram(base, accounts={"work": {"allowFrom": ["42"]}}))


def test_rule2_an_account_that_inherits_a_bad_root_is_reported_once(base: Config) -> None:
    config = with_telegram(base, dmPolicy="pairing", accounts={"work": {}})
    assert paths(config) == ["channels.telegram.dmPolicy"]


@pytest.mark.parametrize("policy", ["pairing", "open"])
def test_rule2_an_account_can_not_bring_pairing_back(base: Config, policy: str) -> None:
    config = with_telegram(base, accounts={"work": {"dmPolicy": policy}})
    assert paths(config) == ["channels.telegram.accounts.work.dmPolicy"]


def test_rule2_an_account_can_be_stricter(base: Config) -> None:
    check_rewindable(with_telegram(base, accounts={"work": {"dmPolicy": "disabled"}}))


def test_rule2_a_direct_chat_can_not_bring_pairing_back(base: Config) -> None:
    config = with_telegram(base, direct={"555": {"dmPolicy": "pairing"}})
    assert paths(config) == ["channels.telegram.direct.555.dmPolicy"]


def test_rule2_a_direct_chat_under_an_account_can_not_bring_pairing_back(base: Config) -> None:
    config = with_telegram(base, accounts={"work": {"direct": {"555": {"dmPolicy": "open"}}}})
    assert paths(config) == ["channels.telegram.accounts.work.direct.555.dmPolicy"]


def test_rule2_a_direct_chat_with_allowlist_or_nothing_passes(base: Config) -> None:
    check_rewindable(
        with_telegram(
            base, direct={"555": {"dmPolicy": "allowlist"}, "556": {"dmPolicy": "disabled"}}
        )
    )
    check_rewindable(with_telegram(base, direct={"555": {}}))


def test_rule2_telegram_must_be_an_object(base: Config) -> None:
    base["channels"] = {"telegram": True}
    assert paths(base) == ["channels.telegram"]


# Rule 3: who is allowed


def test_rule3_numeric_ids_pass(base: Config) -> None:
    check_rewindable(with_telegram(base, allowFrom=["123456789", 42, "telegram:99", "tg:7"]))


def test_rule3_an_empty_allow_list_fails_with_allowlist(base: Config) -> None:
    assert paths(with_telegram(base, allowFrom=[])) == ["channels.telegram.allowFrom"]


def test_rule3_a_missing_allow_list_fails_with_allowlist(base: Config) -> None:
    config = with_telegram(base)
    del config["channels"]["telegram"]["allowFrom"]
    assert paths(config) == ["channels.telegram.allowFrom"]


def test_rule3_an_empty_allow_list_is_fine_when_disabled(base: Config) -> None:
    check_rewindable(with_telegram(base, dmPolicy="disabled", allowFrom=[]))
    config = with_telegram(base, dmPolicy="disabled")
    del config["channels"]["telegram"]["allowFrom"]
    check_rewindable(config)


@pytest.mark.parametrize("entry", ["*", " * ", "telegram:*"])
def test_rule3_a_wildcard_fails(base: Config, entry: str) -> None:
    assert paths(with_telegram(base, allowFrom=["1", entry])) == ["channels.telegram.allowFrom[1]"]


@pytest.mark.parametrize(
    "entry",
    [
        "@alice",
        "alice",
        "12a",
        "-100123",
        "1.5",
        "",
        "accessGroup:friends",
        "TELEGRAM:1",
        True,
        1.5,
        None,
        {},
    ],
)
def test_rule3_non_numeric_ids_fail(base: Config, entry: object) -> None:
    assert paths(with_telegram(base, allowFrom=["1", entry])) == ["channels.telegram.allowFrom[1]"]


@pytest.mark.parametrize("value", ["123", 123, {"0": "1"}])
def test_rule3_the_allow_list_must_be_a_list(base: Config, value: object) -> None:
    assert paths(with_telegram(base, allowFrom=value)) == ["channels.telegram.allowFrom"]


def test_rule3_every_bad_entry_is_listed(base: Config) -> None:
    found = paths(with_telegram(base, allowFrom=["*", "@a", "5"]))
    assert found == ["channels.telegram.allowFrom[0]", "channels.telegram.allowFrom[1]"]


def test_rule3_an_account_with_allowlist_needs_a_non_empty_list_of_its_own_or_the_roots(
    base: Config,
) -> None:
    check_rewindable(with_telegram(base, accounts={"a": {"dmPolicy": "allowlist"}}))  # root's
    check_rewindable(with_telegram(base, accounts={"a": {"allowFrom": ["8"]}}))
    config = with_telegram(base, accounts={"a": {"allowFrom": []}})  # replaces the root's
    assert paths(config) == ["channels.telegram.accounts.a.allowFrom"]


def test_rule3_an_account_inheriting_an_empty_root_list_fails_once_per_scope(base: Config) -> None:
    config = with_telegram(base, allowFrom=[], accounts={"a": {}})
    assert paths(config) == ["channels.telegram.allowFrom", "channels.telegram.accounts.a"]


def test_rule3_an_account_with_a_wildcard_fails(base: Config) -> None:
    config = with_telegram(base, accounts={"a": {"allowFrom": ["*"]}})
    assert paths(config) == ["channels.telegram.accounts.a.allowFrom[0]"]


def test_rule3_a_disabled_account_needs_no_list(base: Config) -> None:
    check_rewindable(with_telegram(base, accounts={"a": {"dmPolicy": "disabled", "allowFrom": []}}))


def test_rule3_a_direct_chat_allow_list_replaces_the_accounts(base: Config) -> None:
    check_rewindable(with_telegram(base, direct={"555": {"allowFrom": ["555"]}}))
    config = with_telegram(base, direct={"555": {"allowFrom": ["*"]}})
    assert paths(config) == ["channels.telegram.direct.555.allowFrom[0]"]
    config = with_telegram(base, direct={"555": {"allowFrom": []}})
    assert paths(config) == ["channels.telegram.direct.555.allowFrom"]


def test_rule3_a_direct_chat_inherits_the_allow_list(base: Config) -> None:
    config = with_telegram(
        base, allowFrom=[], dmPolicy="disabled", direct={"1": {"dmPolicy": "allowlist"}}
    )
    assert paths(config) == ["channels.telegram.direct.1"]


# Rule 4: groups


def test_rule4_group_policy_allowlist_or_disabled_passes(base: Config) -> None:
    check_rewindable(with_telegram(base, groupPolicy="allowlist"))
    config = with_telegram(base)
    del config["channels"]["telegram"]["groupPolicy"]  # the default is "allowlist"
    check_rewindable(config)


def test_rule4_open_groups_fail(base: Config) -> None:
    assert paths(with_telegram(base, groupPolicy="open")) == ["channels.telegram.groupPolicy"]


def test_rule4_open_groups_fail_in_accounts_and_per_group(base: Config) -> None:
    config = with_telegram(
        base,
        accounts={"a": {"groupPolicy": "open", "groups": {"-100": {"groupPolicy": "open"}}}},
    )
    assert paths(config) == [
        "channels.telegram.accounts.a.groupPolicy",
        "channels.telegram.accounts.a.groups.-100.groupPolicy",
    ]


def test_rule4_group_senders_must_be_numeric_without_a_wildcard(base: Config) -> None:
    ok = with_telegram(
        base,
        groupAllowFrom=["1", 2],
        groups={"-100": {"allowFrom": ["3"], "topics": {"7": {"allowFrom": ["4"]}}}},
    )
    check_rewindable(ok)
    bad = with_telegram(
        base,
        groupAllowFrom=["*"],
        groups={"-100": {"allowFrom": ["@a"], "topics": {"7": {"allowFrom": ["*"]}}}},
    )
    assert paths(bad) == [
        "channels.telegram.groupAllowFrom[0]",
        "channels.telegram.groups.-100.allowFrom[0]",
        "channels.telegram.groups.-100.topics.7.allowFrom[0]",
    ]


def test_rule4_direct_chat_topics_are_checked_too(base: Config) -> None:
    config = with_telegram(base, direct={"1": {"topics": {"2": {"allowFrom": ["*"]}}}})
    assert paths(config) == ["channels.telegram.direct.1.topics.2.allowFrom[0]"]


# Rule 5: exec modes


@pytest.mark.parametrize("mode", ["full", "deny"])
def test_rule5_full_and_deny_pass(base: Config, mode: str) -> None:
    base["tools"]["exec"] = {"mode": mode}
    base["agents"]["entries"] = {"main": {"tools": {"exec": {"mode": mode}}}}
    check_rewindable(base)


@pytest.mark.parametrize("mode", ["allowlist", "ask", "auto", "whatever", None])
def test_rule5_the_modes_that_use_allow_always_fail(base: Config, mode: object) -> None:
    base["tools"]["exec"] = {"mode": mode}
    assert paths(base) == ["tools.exec.mode"]


def test_rule5_per_agent_modes_fail(base: Config) -> None:
    base["agents"]["entries"] = {"main": {"tools": {"exec": {"mode": "ask"}}}}
    assert paths(base) == ["agents.entries.main.tools.exec.mode"]


def test_rule5_the_defaults_block_is_checked_too(base: Config) -> None:
    base["agents"]["defaults"]["tools"] = {"exec": {"mode": "auto"}}
    assert paths(base) == ["agents.defaults.tools.exec.mode"]


def test_rule5_the_old_security_ask_pair(base: Config) -> None:
    base["tools"]["exec"] = {"security": "full", "ask": "off"}
    check_rewindable(base)
    base["tools"]["exec"] = {"security": "allowlist", "ask": "always"}
    check_rewindable(base)
    base["tools"]["exec"] = {"security": "allowlist", "ask": "on-miss"}
    assert paths(base) == ["tools.exec.security"]
    base["tools"]["exec"] = {"security": "allowlist"}
    assert paths(base) == ["tools.exec.security"]


# Rule 6: OAuth


def test_rule6_api_key_and_token_profiles_pass(base: Config) -> None:
    base["auth"] = {"profiles": {"a": {"mode": "api_key"}, "b": {"mode": "token"}}}
    base["models"]["providers"] = {"x": {"auth": "api-key"}}
    base["mcp"] = {"servers": {"s": {"url": "http://x", "auth": "none"}}}
    check_rewindable(base)


def test_rule6_oauth_in_an_auth_profile_fails(base: Config) -> None:
    base["auth"] = {"profiles": {"openai:main": {"mode": "oauth"}}}
    assert paths(base) == ["auth.profiles.openai:main.mode"]


def test_rule6_oauth_in_a_model_provider_fails(base: Config) -> None:
    base["models"]["providers"] = {"x": {"auth": "oauth"}}
    assert paths(base) == ["models.providers.x.auth"]


def test_rule6_oauth_in_an_mcp_server_fails(base: Config) -> None:
    base["mcp"] = {"servers": {"s": {"auth": "oauth"}}}
    assert paths(base) == ["mcp.servers.s.auth"]


# Rule 7: SecretRef sources


def test_rule7_env_secret_refs_pass(base: Config) -> None:
    base["models"]["providers"] = {
        "x": {"apiKey": {"source": "env", "provider": "default", "id": "X_KEY"}}
    }
    check_rewindable(base)


@pytest.mark.parametrize("source", ["file", "exec", "store", "ENV", None, 1])
def test_rule7_other_secret_ref_sources_fail(base: Config, source: object) -> None:
    base["models"]["providers"] = {"x": {"apiKey": {"source": source, "provider": "p", "id": "i"}}}
    assert paths(base) == ["models.providers.x.apiKey.source"]


def test_rule7_secret_refs_are_found_anywhere_including_lists(base: Config) -> None:
    ref = {"source": "store", "provider": "p", "id": "i"}
    base["channels"] = {"telegram": telegram(botToken=ref)}
    base["plugins"]["entries"]["other"] = {"config": {"keys": [ref]}}
    assert sorted(paths(base)) == [
        "channels.telegram.botToken.source",
        "plugins.entries.other.config.keys[0].source",
    ]


def test_rule7_a_dict_with_only_source_is_not_a_secret_ref(base: Config) -> None:
    base["x"] = {"source": "file"}  # no "provider": not a SecretRef
    check_rewindable(base)


# Rule 8: gateway


def test_rule8_loopback_token_and_password_pass(base: Config) -> None:
    check_rewindable(base)
    base["gateway"]["auth"]["mode"] = "password"
    check_rewindable(base)


@pytest.mark.parametrize("bind", ["lan", "0.0.0.0", "auto", "tailnet", None])  # noqa: S104
def test_rule8_a_bind_other_than_loopback_fails(base: Config, bind: object) -> None:
    base["gateway"]["bind"] = bind
    assert paths(base) == ["gateway.bind"]


def test_rule8_a_missing_bind_fails(base: Config) -> None:
    del base["gateway"]["bind"]
    assert paths(base) == ["gateway.bind"]


@pytest.mark.parametrize("mode", ["none", "trusted-proxy", None])
def test_rule8_unsafe_auth_modes_fail(base: Config, mode: object) -> None:
    base["gateway"]["auth"]["mode"] = mode
    assert paths(base) == ["gateway.auth.mode"]


def test_rule8_ssh_verify_must_be_false(base: Config) -> None:
    base["gateway"]["nodes"]["pairing"]["sshVerify"] = True
    assert paths(base) == ["gateway.nodes.pairing.sshVerify"]
    del base["gateway"]["nodes"]["pairing"]["sshVerify"]  # the default is "on"
    assert paths(base) == ["gateway.nodes.pairing.sshVerify"]


def test_rule8_auto_approve_cidrs_fail(base: Config) -> None:
    base["gateway"]["nodes"]["pairing"]["autoApproveCidrs"] = ["10.0.0.0/8"]
    assert paths(base) == ["gateway.nodes.pairing.autoApproveCidrs"]
    base["gateway"]["nodes"]["pairing"]["autoApproveCidrs"] = []
    check_rewindable(base)


def test_rule8_the_device_pair_plugin_must_be_off(base: Config) -> None:
    base["plugins"]["entries"]["device-pair"]["enabled"] = True
    assert paths(base) == ["plugins.entries.device-pair.enabled"]
    del base["plugins"]["entries"]["device-pair"]["enabled"]  # the default is "on"
    assert paths(base) == ["plugins.entries.device-pair.enabled"]
    del base["plugins"]
    assert paths(base) == ["plugins.entries.device-pair.enabled"]


# Rule 9: automation


def test_rule9_cron_must_be_off_and_automation_denied(base: Config) -> None:
    check_rewindable(base)
    base["cron"]["enabled"] = True
    assert paths(base) == ["cron.enabled"]
    base["cron"] = {}
    assert paths(base) == ["cron.enabled"]


def test_rule9_automation_must_be_in_the_deny_list(base: Config) -> None:
    base["tools"]["deny"] = ["sessions_spawn"]
    assert paths(base) == ["tools.deny"]
    del base["tools"]["deny"]
    assert paths(base) == ["tools.deny"]
    base["tools"]["deny"] = "group:automation"  # a string is not the list
    assert paths(base) == ["tools.deny"]


# Rule 10: plugins


def test_rule10_no_load_paths_and_a_channel_only_allow_list_pass(base: Config) -> None:
    base["plugins"]["allow"] = ["telegram"]
    base["plugins"]["load"] = {"paths": []}
    check_rewindable(base)


def test_rule10_load_paths_fail(base: Config) -> None:
    base["plugins"]["load"] = {"paths": ["/workspace/evil"]}
    assert paths(base) == ["plugins.load.paths"]


def test_rule10_an_allow_list_with_other_plugins_fails(base: Config) -> None:
    base["plugins"]["allow"] = ["telegram", "whatsapp", "my-plugin"]
    assert paths(base) == ["plugins.allow[1]", "plugins.allow[2]"]


def test_rule10_plugins_must_be_an_object(base: Config) -> None:
    base["plugins"] = "none"
    assert "plugins" in paths(base)


# Rule 11: IMAP is refused entirely


def test_rule11_imap_is_refused_whatever_its_settings(base: Config) -> None:
    base["plugins"]["entries"]["imap"] = {
        "enabled": True,
        "config": {"accounts": {"main": {"allowedSenders": ["me@example.com"]}}},
    }
    [problem] = problems_in(base)
    assert problem.path == "plugins.entries.imap"
    assert "IMAP" in problem.why


def test_rule11_imap_without_an_enabled_flag_is_refused_and_a_disabled_one_passes(
    base: Config,
) -> None:
    base["plugins"]["entries"]["imap"] = {"config": {}}
    assert paths(base) == ["plugins.entries.imap"]
    base["plugins"]["entries"]["imap"] = {"enabled": False, "config": {}}
    check_rewindable(base)


# Rule 12: no native command menu (T10-5: setMyCommands is an admin call the gate holds at risk 3)


def test_rule12_native_false_passes(base: Config) -> None:
    config = with_telegram(base)
    assert config["channels"]["telegram"]["commands"] == {"native": False}
    check_rewindable(config)


def test_rule12_the_root_must_write_it(base: Config) -> None:
    config = with_telegram(base)
    del config["channels"]["telegram"]["commands"]
    (problem,) = problems_in(config)
    assert problem.path == "channels.telegram.commands.native"
    assert "setMyCommands" in problem.why  # the message says why, not only what
    config["channels"]["telegram"]["commands"] = {"nativeSkills": False}
    assert paths(config) == ["channels.telegram.commands.native"]


@pytest.mark.parametrize("value", [True, "auto", "false", 0, None])
def test_rule12_only_a_boolean_false_passes(base: Config, value: object) -> None:
    config = with_telegram(base, commands={"native": value})
    assert paths(config) == ["channels.telegram.commands.native"]


def test_rule12_commands_must_be_an_object(base: Config) -> None:
    assert paths(with_telegram(base, commands=False)) == ["channels.telegram.commands"]


def test_rule12_an_account_without_commands_inherits_the_root(base: Config) -> None:
    check_rewindable(with_telegram(base, accounts={"work": {}}))


def test_rule12_an_account_with_its_own_commands_replaces_the_root_ones(base: Config) -> None:
    # OpenClaw merges account and root with a shallow spread: an account `commands` object
    # (even an empty one) replaces the root's, so native falls back to OpenClaw's default (on).
    for commands in ({}, {"nativeSkills": False}):
        config = with_telegram(base, accounts={"work": {"commands": commands}})
        assert paths(config) == ["channels.telegram.accounts.work.commands.native"]


@pytest.mark.parametrize("value", [True, "auto"])
def test_rule12_an_account_may_not_turn_it_on(base: Config, value: object) -> None:
    config = with_telegram(base, accounts={"work": {"commands": {"native": value}}})
    assert paths(config) == ["channels.telegram.accounts.work.commands.native"]


def test_rule12_an_account_may_say_false_itself(base: Config) -> None:
    check_rewindable(with_telegram(base, accounts={"work": {"commands": {"native": False}}}))


def test_rule12_custom_commands_are_registered_even_with_native_off(base: Config) -> None:
    root = with_telegram(base, customCommands=[{"command": "x", "description": "y"}])
    assert paths(root) == ["channels.telegram.customCommands"]
    account = with_telegram(
        base, accounts={"a": {"customCommands": [{"command": "x", "description": "y"}]}}
    )
    assert paths(account) == ["channels.telegram.accounts.a.customCommands"]
    check_rewindable(with_telegram(base, customCommands=[]))


def test_rule12_without_a_telegram_channel_there_is_nothing_to_check(base: Config) -> None:
    assert "channels" not in base
    check_rewindable(base)


# Rule 13: OpenClaw's own browser is off (T21, docs/36 decision 12)


def test_rule13_the_baseline_turns_the_browser_off_and_its_node_routing(base: Config) -> None:
    assert base["browser"] == {"enabled": False}
    assert base["gateway"]["nodes"]["browser"] == {"mode": "off"}
    check_rewindable(base)


def test_rule13_the_browser_must_be_turned_off_in_writing(base: Config) -> None:
    # OpenClaw 2026.9.8 turns its browser on when browser.enabled is absent.
    del base["browser"]
    (problem,) = problems_in(base)
    assert problem.path == "browser.enabled"
    assert "on by default" in problem.why
    base["browser"] = {}
    assert paths(base) == ["browser.enabled"]


@pytest.mark.parametrize("value", [True, "false", 0, None, "off"])
def test_rule13_only_a_boolean_false_turns_it_off(base: Config, value: object) -> None:
    base["browser"]["enabled"] = value
    assert paths(base) == ["browser.enabled"]


def test_rule13_the_browser_must_be_an_object(base: Config) -> None:
    base["browser"] = False
    assert paths(base) == ["browser"]


@pytest.mark.parametrize(
    "profiles",
    [
        {"user": {"driver": "existing-session", "attachOnly": True}},  # the owner's real Chrome
        {"chrome": {"driver": "extension"}},  # the owner's Chrome through the extension relay
        {"openclaw": {"cdpPort": 18800}},  # even OpenClaw's own managed profile
        {},
    ],
)
def test_rule13_no_browser_profile_is_accepted(base: Config, profiles: Config) -> None:
    base["browser"]["profiles"] = profiles
    (problem,) = problems_in(base)
    assert problem.path == "browser.profiles"
    assert "real Chrome" in problem.why


@pytest.mark.parametrize(
    "key, value",
    [
        ("allowSystemProfileImport", True),
        ("allowSystemProfileImport", False),  # off is the default to rely on: nothing to write
        ("defaultProfile", "user"),
        ("cdpUrl", "http://10.0.0.2:9222"),
        ("attachOnly", True),
        ("executablePath", "/workspace/home/chrome"),
        ("extraArgs", ["--proxy-server=direct://"]),
        ("noSandbox", True),
        ("ssrfPolicy", {"dangerouslyAllowPrivateNetwork": True}),
    ],
)
def test_rule13_no_other_browser_setting_is_accepted(base: Config, key: str, value: object) -> None:
    base["browser"][key] = value
    assert paths(base) == [f"browser.{key}"]


def test_rule13_odd_browser_keys_are_named_safely(base: Config) -> None:
    base["browser"]["pro\nfiles"] = {}
    assert paths(base) == ["browser.pro?files"]


def test_rule13_node_routing_must_be_off_in_writing(base: Config) -> None:
    # The tool routes to a paired node's browser before it looks at browser.enabled
    # (extensions/browser/src/browser-tool.routing.ts); the default mode is "auto".
    del base["gateway"]["nodes"]["browser"]
    (problem,) = problems_in(base)
    assert problem.path == "gateway.nodes.browser.mode"
    assert "node" in problem.why
    for mode in ("auto", "manual", None, False):
        base["gateway"]["nodes"]["browser"] = {"mode": mode}
        assert paths(base) == ["gateway.nodes.browser.mode"]
    base["gateway"]["nodes"]["browser"] = "off"
    assert paths(base) == ["gateway.nodes.browser"]


def test_rule13_a_wrong_gateway_is_reported_once(base: Config) -> None:
    base["gateway"]["nodes"] = []
    found = paths(base)
    assert found.count("gateway.nodes") == 1
    assert "gateway.nodes.browser.mode" in found


@pytest.mark.parametrize("key", ["enabled", "allowHostControl"])
def test_rule13_no_sandbox_browser_and_no_host_control(base: Config, key: str) -> None:
    base["agents"]["defaults"]["sandbox"]["browser"] = {key: True}
    assert paths(base) == [f"agents.defaults.sandbox.browser.{key}"]
    base["agents"]["defaults"]["sandbox"]["browser"] = {key: False}
    check_rewindable(base)
    base["agents"]["entries"] = {"main": {"sandbox": {"browser": {key: True}}}}
    assert paths(base) == [f"agents.entries.main.sandbox.browser.{key}"]


def test_rule13_sandbox_settings_must_be_objects(base: Config) -> None:
    base["agents"]["defaults"]["sandbox"]["browser"] = True
    assert paths(base) == ["agents.defaults.sandbox.browser"]
    base["agents"]["defaults"]["sandbox"] = "off"
    assert paths(base) == ["agents.defaults.sandbox"]


def test_rule13_an_empty_config_is_refused_for_the_browser_too() -> None:
    found = paths({})
    assert "browser.enabled" in found
    assert "gateway.nodes.browser.mode" in found


# The error


def test_the_error_lists_every_problem_with_its_path_and_a_spanish_notice(base: Config) -> None:
    config = with_telegram(base, dmPolicy="pairing", groupPolicy="open")
    config["channels"]["discord"] = {}
    config["cron"]["enabled"] = True
    with pytest.raises(UnrewindableConfig) as caught:
        check_rewindable(config)
    error = caught.value
    assert isinstance(error, ValueError)
    assert [p.path for p in error.problems] == [
        "channels.discord",
        "channels.telegram.dmPolicy",
        "channels.telegram.groupPolicy",
        "cron.enabled",
    ]
    text = str(error)
    for problem in error.problems:
        assert problem.path in text
        assert problem.why in text
    notice = error.notice
    assert "\n" not in notice
    assert notice.startswith("La configuración de OpenClaw no se puede rebobinar con seguridad")
    assert "4 problemas" in notice
    assert "channels.discord" in notice and "cron.enabled" in notice


def test_the_notice_says_one_problem_in_the_singular(base: Config) -> None:
    base["cron"]["enabled"] = True
    with pytest.raises(UnrewindableConfig) as caught:
        check_rewindable(base)
    assert "1 problema:" in caught.value.notice
    assert "problemas" not in caught.value.notice


def test_the_error_never_contains_a_secret(base: Config) -> None:
    base["channels"] = {"telegram": telegram(botToken="123456:SECRET-TOKEN", dmPolicy="pairing")}
    base["models"]["providers"] = {"x": {"apiKey": "sk-secret-value", "auth": "oauth"}}
    base["gateway"]["auth"]["token"] = "gateway-secret"  # noqa: S105
    with pytest.raises(UnrewindableConfig) as caught:
        check_rewindable(base)
    shown = str(caught.value) + caught.value.notice + repr(caught.value.problems)
    for secret in ("SECRET-TOKEN", "sk-secret-value", "gateway-secret"):
        assert secret not in shown


def test_bad_entries_are_not_echoed_back(base: Config) -> None:
    # An allow-list entry might be pasted from anywhere: the path is enough.
    config = with_telegram(base, allowFrom=["1", "hunter2-not-a-number"])
    shown = str(UnrewindableConfig(problems_in(config)))
    assert "hunter2" not in shown


def test_check_does_not_modify_the_config(base: Config) -> None:
    config = with_telegram(base, dmPolicy="pairing")
    before = json.dumps(config, sort_keys=True)
    with pytest.raises(UnrewindableConfig):
        check_rewindable(config)
    assert json.dumps(config, sort_keys=True) == before


def test_a_problem_is_a_plain_value() -> None:
    problem = RewindProblem("a.b", "because")
    assert (problem.path, problem.why) == ("a.b", "because")


# --- talking to it from the terminal (D27: `backtide tarea` and `entrar`) ---------------------


def test_the_commands_to_talk_to_openclaw() -> None:
    """A turn of its own CLI through the running Gateway, always in the main session
    (Telegram's too): one conversation, so no resume flag. No terminal session for now: an
    always-on agent could write escape sequences into its terminal UI's tty."""
    from backtide.jail.profiles import OPENCLAW
    from backtide.jail.profiles.openclaw import CLI, NODE

    shell = OPENCLAW.shell
    assert shell is not None and OPENCLAW.mode == "service" and shell.one_conversation
    assert shell.task_argv("-rf todo", seconds=600) == [
        NODE, CLI, "agent", "--agent", "main", "--json", "--timeout=600", "--message=-rf todo",
    ]  # fmt: skip
    assert shell.session == () and shell.default_minutes == 15
    assert "--deliver" not in shell.task
    assert not shell.seed


# What `openclaw agent --json` printed in the VM with 2026.9.8 (tests/integration/
# test_local_profiles.py), cut to what is read.
TURN = {
    "runId": "c208b14f",
    "status": "ok",
    "summary": "completed",
    "result": {
        "payloads": [{"text": "uno", "mediaUrl": None}, {"text": "  "}, {"text": "dos"}],
        "meta": {"durationMs": 1783},
    },
}


@pytest.mark.parametrize(
    ("printed", "text", "outcome"),
    [
        (TURN, "uno\n\ndos", "ok"),
        ({**TURN, "status": "timeout", "result": {"payloads": []}}, "", "timed_out"),
        ({**TURN, "status": "error", "result": {}}, "", "failed"),
        ({"runId": "x", "status": "in_flight"}, "", "busy"),
        ({**TURN, "status": "whatever"}, "uno\n\ndos", "failed"),
        (
            {"ok": False, "error": {"type": "cli_error", "message": "no gateway"}},
            "no gateway",
            "failed",
        ),
        ({"ok": False}, "", "failed"),
    ],
)
def test_the_answer_of_a_turn(printed: object, text: str, outcome: str) -> None:
    from backtide.jail.profiles.openclaw import task_answer

    answer = task_answer(json.dumps(printed))
    assert answer is not None and (answer.text, answer.outcome) == (text, outcome)


@pytest.mark.parametrize(
    "printed", ["not json", "[]", '{"status": 3}', '{"status": "ok", "result": {"payloads": 1}}']
)
def test_what_is_not_an_answer(printed: str) -> None:
    from backtide.jail.profiles.openclaw import task_answer

    assert task_answer(printed) is None
