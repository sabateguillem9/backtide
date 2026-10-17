"""The control socket takes ``via: "telegram"`` only from the service's own process (T09): the
bot lives there, so another process of the same user cannot make the black box say that a
rewind came from Telegram. Uses the fixtures of test_service_control.py."""

# ruff: noqa: F811

import json
import os
import socket
from collections.abc import Callable

from test_service_control import (  # noqa: F401 - fixtures, used by name
    SNAPSHOT,
    FakeGuardian,
    folder,
    guardian,
    make_server,
    talk,
)

from vigia.service.control import ControlServer

REQUEST = json.dumps({"cmd": "rewind", "snapshot_id": SNAPSHOT, "via": "telegram"}).encode()


def ours(sock: socket.socket) -> tuple[int, int, int]:
    return os.getpid(), os.geteuid(), os.getegid()


def test_another_process_cannot_ask_as_telegram(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    reply = talk(make_server(), REQUEST + b"\n")  # the fake peer is pid 4242
    assert reply["outcome"] == "refused" and reply["ok"] is False
    assert guardian.calls == []


def test_the_service_itself_asks_as_telegram(
    make_server: Callable[..., ControlServer], guardian: FakeGuardian
) -> None:
    reply = talk(make_server(peer=ours), REQUEST + b"\n")
    assert reply["outcome"] == "done"
    assert guardian.calls == [(SNAPSHOT, f"telegram (uid {os.geteuid()}, pid {os.getpid()})")]
