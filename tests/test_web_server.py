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


# -- T26-3b-2: the web holds [::1] too, on the same port ------------------------------------------


def test_the_web_holds_both_loopbacks_on_one_port() -> None:
    import socket

    from backtide.web.server import bind_both

    socks = bind_both(0)
    try:
        assert [s.family for s in socks][0] == socket.AF_INET
        if len(socks) == 2:  # a machine with IPv6
            assert socks[1].family == socket.AF_INET6
            assert socks[1].getsockname()[0] == "::1"
            assert socks[0].getsockname()[1] == socks[1].getsockname()[1]
    finally:
        for sock in socks:
            sock.close()


def test_a_foreign_program_on_the_ipv6_loopback_stops_the_web() -> None:
    """Review of T26-3b-2: whoever held [::1]:port would get backtide.localhost's requests."""
    import socket

    from backtide.web.server import bind, bind_both

    probe = bind(0)
    port = probe.getsockname()[1]
    probe.close()
    try:
        squatter = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        squatter.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        squatter.bind(("::1", port))
        squatter.listen(1)
    except OSError:
        pytest.skip("no IPv6 loopback here")
    try:
        with pytest.raises(OSError):
            bind_both(port)
        # ...and IPv4 is left free again: nothing half-open stays behind.
        again = bind(port)
        again.close()
    finally:
        squatter.close()
