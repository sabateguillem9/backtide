"""uvicorn's private part that ``backtide web`` relies on (review of T10-3, L10)."""

import logging
import signal

import pytest
import uvicorn

from backtide.web import server as server_module


def make() -> uvicorn.Server:
    return server_module.make_server(lambda scope, receive, send: None)


def test_uvicorn_still_keeps_the_signals_it_caught_where_we_clear_them() -> None:
    """``_Server.handle_exit`` clears uvicorn's ``_captured_signals`` (0.54.0): if an upgrade
    renames or retypes it, this fails here instead of `backtide web` dying by its signal."""
    made = make()
    assert isinstance(made._captured_signals, list)  # noqa: SLF001 - the private part under test
    made._captured_signals.append(signal.SIGINT)  # noqa: SLF001
    made.handle_exit(signal.SIGINT, None)
    assert made._captured_signals == []  # noqa: SLF001
    assert made.should_exit


def test_without_it_the_stop_still_works_and_says_so(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A future uvicorn that keeps its caught signals elsewhere: no crash, and a warning."""

    def handle_exit(self: uvicorn.Server, sig: int, frame: object) -> None:
        self.should_exit = True

    monkeypatch.setattr(uvicorn.Server, "handle_exit", handle_exit)
    made = make()
    del made._captured_signals  # noqa: SLF001 - an uvicorn without it
    with caplog.at_level(logging.WARNING, logger="backtide.web.server"):
        made.handle_exit(signal.SIGTERM, None)
    assert made.should_exit
    assert "uvicorn changed" in caplog.text
