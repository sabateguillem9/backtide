"""T12e: the Settings page's commands on the control socket (``secrets``, ``set_secret``,
``clear_secret``): what the server serves and refuses, and that a value never comes back, never
reaches a log line and never reaches a refusal.

A real server over a real Unix socket in a short folder, with ``SO_PEERCRED`` played by a fake
``peer`` (as in tests/test_service_control.py), and the real ``Settings`` on a real black box."""

import json
import logging
import os
import secrets
import shutil
import socket
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.service.control import (
    ControlError,
    ControlServer,
    ask_clear_secret,
    ask_secrets,
    ask_set_secret,
)
from backtide.service.settings import Applied, Settings, SettingsOutcome
from tests.test_service_control import FakeGuardian, me, somebody_else

KEY = bytes(range(32))


def anthropic_key() -> str:
    return "sk-ant-api03-TEST" + secrets.token_urlsafe(48).replace("=", "")


def pieces(value: str) -> set[str]:
    return {value[i : i + 8] for i in range(len(value) - 7)} | {value}


@pytest.fixture
def folder() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="vs"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def box(folder: Path) -> BlackBox:
    return BlackBox(folder / "blackbox.db", KEY, checkpoint_path=folder / "blackbox.ckpt")


@pytest.fixture
def settings(folder: Path, box: BlackBox) -> Settings:
    return Settings(folder, record=box.append, reload_keys=lambda: Applied.NOW,
                    in_use=["anthropic"])  # fmt: skip


@pytest.fixture
def make_server(folder: Path, settings: Settings) -> Iterator[Callable[..., ControlServer]]:
    servers: list[ControlServer] = []

    def make(**options: Any) -> ControlServer:
        options.setdefault("peer", me)
        options.setdefault("settings", settings)
        server = ControlServer(FakeGuardian(), folder / "control.sock", **options)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def talk(server: ControlServer, request: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(server.path))
        sock.sendall(json.dumps(request).encode() + b"\n")
        sock.shutdown(socket.SHUT_WR)
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
    return raw, json.loads(raw)


def test_a_key_is_set_through_the_socket_and_recorded_as_the_web(
    make_server: Callable[..., ControlServer], folder: Path, box: BlackBox,
    caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    caplog.set_level(logging.DEBUG)
    server = make_server()
    key = anthropic_key()
    reply = ask_set_secret(server.path, "anthropic", key, via="web", peer=me)
    assert reply == {
        "ok": True,
        "outcome": "saved",
        "message": "Guardada. El proxy ya la usa: el agente sigue con su clave falsa.",
        "applied": "now",
    }
    assert (folder / "keys" / "anthropic.key").read_text() == key + "\n"
    [event] = box.events()
    assert event.details == {
        "kind": "anthropic",
        "requested_by": f"web (uid {os.geteuid()}, pid 4242)",
    }
    shown = ask_secrets(server.path, peer=me)
    assert shown["anthropic"]["tail"] == key[-4:]
    removed = ask_clear_secret(server.path, "anthropic", via="web", peer=me)
    assert (removed["ok"], removed["outcome"]) == (True, "cleared")
    logs = " ".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    said = json.dumps([reply, removed, [e.details for e in box.events()]]) + logs
    assert not any(piece in said for piece in pieces(key))


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "set_secret", "kind": "anthropic"},  # no value
        {"cmd": "set_secret", "kind": "gemini", "value": "x"},
        {"cmd": "set_secret", "kind": "anthropic", "value": 7},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x" * 300},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x", "chat_id": "1"},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x", "via": "telegram"},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x", "via": "evil"},
        {"cmd": "set_secret", "kind": "anthropic", "value": "x", "extra": 1},
        {"cmd": "clear_secret", "kind": "anthropic", "value": "x"},
        {"cmd": "clear_secret"},
        {"cmd": "secrets", "value": "x"},
        {"cmd": "secrets", "kind": "anthropic"},
    ],
)
def test_a_malformed_settings_request_is_refused_and_never_echoed(
    make_server: Callable[..., ControlServer], box: BlackBox, request_: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    caplog.set_level(logging.DEBUG)
    secret = anthropic_key()
    if isinstance(request_.get("value"), str):
        request_ = {**request_, "value": secret + request_["value"][:200]}
    raw, reply = talk(make_server(), request_)
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert box.events() == []
    logs = " ".join(r.getMessage() for r in caplog.records)
    assert not any(piece.encode() in raw for piece in pieces(secret))
    assert not any(piece in logs for piece in pieces(secret))


def test_a_value_of_the_wrong_shape_is_refused_by_the_service_without_quoting_it(
    make_server: Callable[..., ControlServer], box: BlackBox
) -> None:
    secret = "sk-proj-" + secrets.token_urlsafe(40)
    raw, reply = talk(make_server(), {"cmd": "set_secret", "kind": "anthropic", "value": secret})
    assert (reply["ok"], reply["outcome"]) == (False, "invalid")
    assert not any(piece.encode() in raw for piece in pieces(secret))
    assert box.events() == []


def test_another_user_cannot_set_or_read_a_key(
    make_server: Callable[..., ControlServer], folder: Path, box: BlackBox
) -> None:
    server = make_server(peer=somebody_else)
    _, reply = talk(server, {"cmd": "set_secret", "kind": "anthropic", "value": anthropic_key()})
    assert reply["outcome"] == "refused"
    _, listed = talk(server, {"cmd": "secrets"})
    assert listed["outcome"] == "refused" and "secrets" not in listed
    assert not (folder / "keys").exists() and box.events() == []


def test_a_service_without_settings_refuses_them(
    make_server: Callable[..., ControlServer],
) -> None:
    server = make_server(settings=None)
    _, reply = talk(server, {"cmd": "secrets"})
    assert reply["outcome"] == "refused"
    with pytest.raises(ControlError):
        ask_secrets(server.path, peer=me)


def test_a_settings_call_that_raises_is_not_logged_with_its_text(
    make_server: Callable[..., ControlServer], caplog: pytest.LogCaptureFixture
) -> None:
    secret = anthropic_key()

    class Exploding:
        def status(self) -> dict[str, dict[str, Any]]:
            raise RuntimeError(f"oops {secret}")

        def set_secret(self, kind: str, value: str, *, chat_id: str = "",
                       requested_by: str) -> SettingsOutcome:  # fmt: skip
            raise RuntimeError(f"oops {value}")

        def clear_secret(self, kind: str, *, requested_by: str) -> SettingsOutcome:
            raise RuntimeError(f"oops {secret}")

    caplog.set_level(logging.DEBUG)
    server = make_server(settings=Exploding())
    raw, reply = talk(server, {"cmd": "set_secret", "kind": "anthropic", "value": secret})
    assert (reply["ok"], reply["outcome"]) == (False, "failed")
    raw2, listed = talk(server, {"cmd": "secrets"})
    assert listed["ok"] is False
    logs = " ".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    for blob in (raw.decode(), raw2.decode(), logs):
        assert not any(piece in blob for piece in pieces(secret))
    assert "RuntimeError" in logs, "the failure is logged (by its type), not silenced"


def test_the_client_checks_what_it_sends() -> None:
    with pytest.raises(ValueError):
        ask_set_secret(Path("/nowhere"), "gemini", "x")
    with pytest.raises(ValueError):
        ask_set_secret(Path("/nowhere"), "anthropic", "x", via="telegram")
    with pytest.raises(ValueError):
        ask_clear_secret(Path("/nowhere"), "anthropic", via="telegram")
