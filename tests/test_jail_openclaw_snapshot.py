"""OpenClaw's jail, byte for byte as it was before the agent profile (T17a-2, docs/34 section 11).

tests/fixtures/openclaw_jail_snapshot.json was generated from the code BEFORE the profile
existed (the jail's constants and OpenClaw's lived in jail/config.py). It holds, for two configs
(the defaults, and one with every option and two model providers): the ``docker create`` argv,
the environment the docker CLI gets, the network's argv, the container's environment,
openclaw.json, a container that verify.py accepts, and every problem verify.py reports for an
empty ``docker inspect`` (which names each value it expects). Nothing of it may change for
OpenClaw; regenerate it only on purpose, when the jail changes for every agent.

Changed on purpose three times since, each time with a script that proved nothing else moved:
T17a-3 (``BASH_ENV`` and ``CLAUDE_ENV_FILE`` at /dev/null), the security review of the profiles
(``--no-healthcheck``, and the profile's own variables by name in the argv, their values in the
docker CLI's environment: ``create_cli_env`` is create_env now) and rule 13 of check_rewindable
(openclaw.json only: ``browser.enabled`` false and ``gateway.nodes.browser.mode`` "off"), and
T13-4 (a ``--label backtide.role=...`` after ``--name`` in the create argv and after the driver in
the network's, so the uninstaller only removes what is backtide's; nothing else moved).
"""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from backtide.jail.config import (
    AgentJailConfig,
    Protected,
    container_env,
    create_env,
    docker_create_argv,
    network_create_argv,
    token_env,
)
from backtide.jail.profiles.openclaw import OPENCLAW, ModelProvider
from backtide.jail.verify import container_problems

# The default seccomp profile lives in the checkout, so its path is stored as {REPO}.
REPO = str(Path(__file__).resolve().parent.parent)
SNAPSHOT = json.loads(
    (Path(__file__).parent / "fixtures" / "openclaw_jail_snapshot.json")
    .read_text()
    .replace("{REPO}", REPO)
)
SECCOMP = SNAPSHOT["seccomp_profile"]
IMAGE_ENV = SNAPSHOT["image_env"]
TOKEN = "t" * 43
ROOT = Path("/srv/bt")
STATE = ROOT / "state"


def _configs() -> dict[str, AgentJailConfig]:
    """The same two configs the snapshot was generated from."""
    plain = AgentJailConfig(
        workspace=ROOT / "volume" / "workspace",
        config_dir=STATE / "openclaw",
        ca_dir=STATE / "agent-ca",
        gateway_token=TOKEN,
    )
    full = AgentJailConfig(
        workspace=ROOT / "volume" / "workspace",
        config_dir=STATE / "openclaw",
        ca_dir=STATE / "agent-ca",
        gateway_token="A-b_9" * 8,
        model_providers=(
            ModelProvider(
                name="anthropic",
                kind="anthropic",
                host="api.anthropic.com",
                fake_key="backtide-fake-anthropic-" + "a" * 32,
            ),
            ModelProvider(
                name="local",
                kind="openai",
                host="llm.example.com",
                fake_key="backtide-fake-local-" + "b" * 32,
                models=("qwen-2.5", "llama/3"),
            ),
        ),
        name="backtide-test-agent-0123abcd",
        network="backtide-test-net-0123abcd",
        hostname="agente",
        uid=501,
        gid=1000,
        memory="1536m",
        pids_limit=256,
        cpus="1.5",
        tmp_size="64m",
        seccomp_profile=Path("/opt/backtide/deploy/seccomp/agent.json"),
        stop_timeout=12,
        ready_timeout=30.0,
        protected=(
            Protected(
                "backtide's state folder",
                STATE,
                allowed_inside=(STATE / "openclaw", STATE / "agent-ca"),
            ),
            Protected("the black box", STATE / "blackbox.db"),
        ),
    )
    return {"plain": plain, "full": full}


CONFIGS = _configs()
LABELS = sorted(SNAPSHOT["configs"])


def test_the_snapshot_covers_both_configs() -> None:
    assert LABELS == sorted(CONFIGS) == ["full", "plain"]


@pytest.mark.parametrize("label", LABELS)
def test_the_default_profile_is_openclaw(label: str) -> None:
    assert CONFIGS[label].profile is OPENCLAW


@pytest.mark.parametrize("label", LABELS)
def test_docker_create_is_byte_for_byte_the_same(label: str) -> None:
    expected = SNAPSHOT["configs"][label]
    config = CONFIGS[label]
    assert docker_create_argv(config) == expected["create_argv"]
    assert create_env(config) == expected["create_cli_env"]
    assert token_env(config) == {"OPENCLAW_GATEWAY_TOKEN": config.gateway_token}
    assert network_create_argv(config) == expected["network_argv"]
    assert [list(pair) for pair in container_env(config)] == expected["container_env"]


@pytest.mark.parametrize("label", LABELS)
def test_openclaw_json_is_byte_for_byte_the_same(label: str) -> None:
    config = CONFIGS[label]
    assert dict(config.profile.render_config(config)) == SNAPSHOT["configs"][label]["config_files"]


def _problems(config: AgentJailConfig, info: dict[str, Any]) -> list[str]:
    return container_problems(config, info, seccomp_profile=SECCOMP, image_env=IMAGE_ENV)


@pytest.mark.parametrize("label", LABELS)
def test_verify_expects_exactly_the_same(label: str) -> None:
    expected = SNAPSHOT["configs"][label]
    config = CONFIGS[label]
    assert _problems(config, expected["good_info"]) == []
    # Each expected value, named in the problem verify reports when it is missing.
    assert _problems(config, {}) == expected["problems_of_empty_info"]


@pytest.mark.parametrize("label", LABELS)
def test_verify_checks_every_variable_of_the_snapshot(label: str) -> None:
    """Not only the names: a change to any one value is a problem, naming that variable."""
    good = SNAPSHOT["configs"][label]["good_info"]
    for index, entry in enumerate(good["Config"]["Env"]):
        name = entry.split("=", 1)[0]
        info = copy.deepcopy(good)
        info["Config"]["Env"][index] = f"{entry}-changed"
        assert _problems(CONFIGS[label], info) == [f"its environment differs in [{name!r}]"]
