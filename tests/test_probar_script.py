"""The logic of scripts/demo/probar.py that does not need the VM (`make probar`, docs/probar.md):
the config it writes, starting without the Anthropic key (backtide itself waits for it: no
placeholder anywhere), the message it hands the agent and the lines of its live view. Every key
here is made up."""

import base64
import os
import secrets
import stat
import tomllib
from pathlib import Path

import pytest

from backtide.blackbox import Event, Source
from backtide.gate.providers import is_fake_key
from backtide.jail.config import openclaw_config
from backtide.jail.openclaw import check_rewindable
from backtide.service import config as service_config
from backtide.service.config import ServiceConfig
from scripts.demo import demo, probar

MADE_UP_KEY = "sk-ant-test-made-up-" + "Q" * 24


@pytest.fixture
def paths(tmp_path: Path) -> demo.Paths:
    paths = demo.Paths(tmp_path / "probar")
    paths.state.mkdir(parents=True, mode=0o700)
    paths.volume.mkdir(parents=True)
    token = paths.state / "gateway.token"
    token.write_text(secrets.token_urlsafe(32) + "\n")
    token.chmod(0o600)
    return paths


def write_config(
    paths: demo.Paths, model: str = probar.DEFAULT_MODEL, *, offline: bool = False
) -> None:
    paths.config.write_text(probar.render_config(paths, 1000, 1000, model=model, offline=offline))
    paths.config.chmod(0o600)


def test_the_config_has_claude_the_gate_and_more_memory(paths: demo.Paths) -> None:
    write_config(paths)
    config = ServiceConfig.from_file(paths.config)

    (provider,) = config.proxy_settings().providers
    assert (provider.name, provider.kind, provider.host) == (
        "anthropic",
        "anthropic",
        "api.anthropic.com",
    )
    assert provider.models == ("claude-sonnet-5-5", probar.UTILITY_MODEL)  # the agent's first
    assert config.proxy_settings().allow_provider_tools == ("param:fallbacks",)
    gate = config.gate_settings(owner_chat=4242)
    assert gate.unknown_hosts == "hold"
    assert [t.recipient for t in gate.trusted] == ["4242"]  # the owner's chat, trusted
    assert config.jail_config().memory == "3g"
    assert config.workspace_limit == 192 * 1024**2
    claw = openclaw_config(config.jail_config())
    assert claw["agents"]["defaults"]["model"] == {"primary": "anthropic/claude-sonnet-5-5"}
    check_rewindable(claw)
    text = paths.config.read_text()
    assert "allow_shared_ids" not in text and "key =" not in text  # never in the file
    assert tomllib.loads(text)["agent"]["name"] == demo.CONTAINER  # the demo's names
    assert config.budget_settings().auto_prices is True  # the founder's run: real prices


def test_the_fake_internets_run_never_fetches_the_prices(paths: demo.Paths) -> None:
    """`make probar FALSO=1` stays inside the VM: not even Anthropic's pricing page."""
    write_config(paths, offline=True)
    config = ServiceConfig.from_file(paths.config)
    assert config.budget_settings().auto_prices is False
    assert tomllib.loads(paths.config.read_text())["budget"] == {"auto_prices": False}
    assert "[budget]" not in probar.render_config(paths, 1, 1)


def test_the_model_can_be_chosen_and_an_odd_one_is_refused(paths: demo.Paths) -> None:
    text = probar.render_config(paths, 1, 1, model="claude-haiku-5-5")
    assert '"claude-haiku-5-5", "claude-haiku-4-5"' in text
    once = probar.render_config(paths, 1, 1, model=probar.UTILITY_MODEL)
    assert f'models = ["{probar.UTILITY_MODEL}"]' in once  # not twice
    with pytest.raises(demo.DemoError, match="modelo"):
        probar.render_config(paths, 1, 1, model='x"\n[gate]')
    paths.config.write_text(text)
    assert probar.model_of(paths) == "claude-haiku-5-5"


def test_it_starts_without_the_real_key_and_the_provider_waits_for_it(
    paths: demo.Paths,
) -> None:
    write_config(paths)
    config = ServiceConfig.from_file(paths.config)

    keys = paths.state / "keys"
    assert stat.S_IMODE(keys.stat().st_mode) == 0o700
    assert sorted(p.name for p in keys.iterdir()) == ["anthropic.fake"]  # no .key written
    key = config.provider_keys["anthropic"]
    assert is_fake_key(key.fake, "anthropic")
    assert key.real is None and key.problem == "missing"
    assert config.model_providers().waiting() == ("anthropic",)
    assert config.jail_config().model_providers[0].fake_key == key.fake  # the agent's is fake
    assert not probar.has_real_key(paths)
    assert not hasattr(probar, "keys_or_placeholder") and not hasattr(probar, "PLACEHOLDER_PREFIX")
    # Nothing replaces backtide's own reading of the keys any more.
    assert service_config.read_provider_keys.__module__ == "backtide.service.config"


def test_once_the_settings_page_saved_the_key_it_is_the_real_one(paths: demo.Paths) -> None:
    write_config(paths)
    fake = ServiceConfig.from_file(paths.config).provider_keys["anthropic"].fake
    real_file = paths.state / "keys" / "anthropic.key"
    real_file.write_text(MADE_UP_KEY + "\n")  # what the Settings page writes
    real_file.chmod(0o600)

    key = ServiceConfig.from_file(paths.config).provider_keys["anthropic"]

    assert key.real is not None and key.real.reveal() == MADE_UP_KEY
    assert key.fake == fake  # the agent keeps the same fake key
    assert probar.has_real_key(paths)


def test_a_bad_key_file_is_never_used(paths: demo.Paths) -> None:
    write_config(paths)
    ServiceConfig.from_file(paths.config)
    real_file = paths.state / "keys" / "anthropic.key"
    real_file.write_text(MADE_UP_KEY + "\n")
    real_file.chmod(0o644)
    config = ServiceConfig.from_file(paths.config)
    key = config.provider_keys["anthropic"]
    assert key.real is None and key.problem == "unusable"  # fail closed: it waits
    assert key.why is not None and "600" in key.why and MADE_UP_KEY not in key.why
    providers = config.model_providers()
    anthropic = providers.by_name("anthropic")
    assert anthropic is not None and anthropic.real_key is None  # never swapped in...
    assert MADE_UP_KEY in providers.strike_only  # ...but struck (review of T09b, finding 2)


def encoded(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_the_message_arrives_whole_and_goes_as_one_argument() -> None:
    message = "Escribe 'hola'; rm -rf / $(date) `id` \"x\""
    assert probar.decode_message(encoded(message)) == message
    argv = probar.agent_turn_argv(message)
    assert argv[-2:] == ["--message", message]  # never through a shell
    assert argv[:4] == ["node", "openclaw.mjs", "agent", "--agent"]


@pytest.mark.parametrize("bad", ["", "   ", "%%%", base64.b64encode(b"\xff\xfe").decode()])
def test_an_empty_or_broken_message_is_refused(bad: str) -> None:
    with pytest.raises(demo.DemoError):
        probar.decode_message(bad if bad.strip() != "" else encoded(bad))


def test_a_huge_message_is_refused() -> None:
    with pytest.raises(demo.DemoError, match="largo"):
        probar.decode_message(encoded("a" * (probar.MAX_MESSAGE_BYTES + 1)))


def _event(source: Source, action: str, target: str, risk: int = 0, **details: object) -> Event:
    return Event(
        seq=1,
        ts="2026-10-20T17:00:00.000000Z",
        source=source,
        action=action,
        target=target,
        details=dict(details),
        risk=risk,
        snapshot_id=None,
        prev_hash="0" * 64,
        hash="1" * 64,
    )


def test_the_live_view_shows_the_model_the_gate_and_the_files() -> None:
    held = probar.describe(
        _event(Source.GATE, "held", "https://httpbin.org/post", risk=2, method="POST")
    )
    assert held is not None and "PUERTA" in held and "riesgo 2" in held and "POST" in held
    response = probar.describe(
        _event(Source.LLM, "response", "x", model="claude-sonnet-5-5", usage={"input": 3})
    )
    assert response is not None and "claude-sonnet-5-5" in response and "entran 3" in response
    model_call = _event(Source.NET, "request", "https://api.anthropic.com/v1/messages")
    model_call.details["host"] = "api.anthropic.com"
    assert probar.describe(model_call) is None  # the llm lines say it
    note = probar.describe(_event(Source.FILE, "create", "work/nota.txt"))
    assert note is not None and note.endswith("work/nota.txt")
    assert probar.describe(_event(Source.FILE, "modify", "state/openclaw.sqlite")) is None


def test_text_of_the_agent_shows_its_invisible_characters() -> None:
    line = probar.describe(_event(Source.FILE, "create", "work/a‮exe.txt\x1b[2J"))
    assert line is not None
    assert "‮" not in line and "\x1b" not in line
    assert "U+202E" in line and "U+001B" in line


def test_the_fake_internets_read_only_folders_are_removed(tmp_path: Path) -> None:
    paths = demo.Paths(tmp_path / "run")
    paths.base.mkdir()
    paths.mark.write_text("mark\n")
    folder = paths.base / demo.FAKE_INTERNET_FOLDER / "t06"
    folder.mkdir(parents=True)
    (folder / "fake_internet.py").write_text("x")
    folder.chmod(0o555)
    folder.parent.chmod(0o555)

    demo._make_writable(paths.base / demo.FAKE_INTERNET_FOLDER)

    assert os.access(folder, os.W_OK) and os.access(folder.parent, os.W_OK)


# --- with Claude Code (T17a-4: make probar PERFIL=claude-code) ----------------------------------


def test_the_config_with_claude_code(paths: demo.Paths) -> None:
    paths.config.write_text(probar.render_config(paths, 1000, 1000, profile=probar.CLAUDE_CODE))
    paths.config.chmod(0o600)
    config = ServiceConfig.from_file(paths.config)
    assert config.agent_profile.name == "claude-code"
    (provider,) = config.proxy_settings().providers
    assert (provider.name, provider.host, provider.models) == ("anthropic", "api.anthropic.com", ())
    allowed = config.proxy_settings().allow_provider_tools
    assert "param:diagnostics" in allowed and "param:fallbacks" in allowed
    assert config.jail_config().memory == "3g" and config.workspace_limit == 192 * 1024**2
    assert config.gate_settings(owner_chat=4242).unknown_hosts == "hold"


def test_an_unknown_profile_is_refused(paths: demo.Paths) -> None:
    with pytest.raises(demo.DemoError, match="perfil"):
        probar.render_config(paths, 1000, 1000, profile="codex")
    with pytest.raises(SystemExit):
        probar.build_parser().parse_args(["up", "--perfil", "codex"])


def mounted(paths: demo.Paths, monkeypatch: pytest.MonkeyPatch, profile: str) -> list[tuple]:
    paths.config.write_text(probar.render_config(paths, 1000, 1000, profile=profile))
    paths.config.chmod(0o600)
    monkeypatch.setattr(demo, "PATHS", paths)
    monkeypatch.setattr(demo, "require_demo_mount", lambda p: None)
    ran: list[tuple] = []
    monkeypatch.setattr(probar, "run_backtide", lambda *argv, **kw: ran.append(argv) or 0)
    return ran


def test_the_claude_code_commands_go_to_backtides_own(
    paths: demo.Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran = mounted(paths, monkeypatch, probar.CLAUDE_CODE)
    config = ("--config", str(paths.config))
    assert probar.main(["entrar", "--continue"]) == 0
    assert probar.main(["tarea", encoded("-haz esto"), "--continue"]) == 0
    assert probar.main(["importar", "/home/me/repo", "--reemplazar"]) == 0
    assert probar.main(["exportar", "/home/me/salida"]) == 0
    assert ran == [
        ("entrar", *config, "--continue"),
        ("tarea", *config, "--continue", "--", "-haz esto"),  # a task that looks like an option
        ("importar", *config, "--reemplazar", "/home/me/repo"),
        ("exportar", *config, "/home/me/salida"),
    ]
    assert probar.main(["pedir", encoded("hola")]) == 1  # that one is OpenClaw's


def test_with_openclaw_the_claude_code_commands_say_how_to_start_it(
    paths: demo.Paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ran = mounted(paths, monkeypatch, probar.OPENCLAW)
    assert probar.main(["entrar"]) == 1
    assert "PERFIL=claude-code" in capsys.readouterr().err and ran == []
