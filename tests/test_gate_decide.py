"""The gate's table without translators (backtide/gate/decide.py, docs/32 section 5)."""

from dataclasses import replace

import pytest

from backtide.gate.decide import MAX_READ_URL, Decision, Facts, Verdict, decide

READ = Facts(method="GET", exact_read=True, has_body=False, url_bytes=40, url_struck=False,
             allowed=True)  # fmt: skip
WRITE = Facts(method="POST", exact_read=False, has_body=True, url_bytes=40, url_struck=False,
              allowed=True)  # fmt: skip


def verdict(facts: Facts, **options: str) -> tuple[Verdict, str, int]:
    decision = decide(facts, **options)
    return decision.verdict, decision.reason, decision.risk


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_a_read_without_a_body_passes_without_asking(method: str) -> None:
    assert verdict(replace(READ, method=method)) == (Verdict.PASS, "read", 0)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "PROPFIND", "MKCOL", "BREW", "TRACE"])
def test_every_other_method_is_held_with_risk_2(method: str) -> None:
    assert verdict(replace(WRITE, method=method)) == (Verdict.HOLD, "write", 2)


def test_a_delete_is_held_with_risk_3() -> None:
    assert verdict(replace(WRITE, method="DELETE", has_body=False)) == (Verdict.HOLD, "delete", 3)
    decision = decide(replace(WRITE, method="DELETE"))
    assert decision.held and decision == Decision(Verdict.HOLD, "delete", 3)


def test_a_get_with_a_body_is_not_a_read() -> None:
    assert verdict(replace(READ, has_body=True)) == (Verdict.HOLD, "write", 2)


def test_a_method_not_sent_exactly_as_a_read_is_a_write() -> None:
    """``get`` is recorded as GET, but a server may read it otherwise: an unknown method."""
    assert verdict(replace(READ, exact_read=False)) == (Verdict.HOLD, "write", 2)


def test_a_read_whose_url_carried_a_secret_is_held_with_risk_3() -> None:
    assert verdict(replace(READ, url_struck=True)) == (Verdict.HOLD, "url_secret", 3)


def test_a_read_with_a_long_url_is_held_with_risk_2() -> None:
    assert verdict(replace(READ, url_bytes=MAX_READ_URL)) == (Verdict.PASS, "read", 0)
    assert verdict(replace(READ, url_bytes=MAX_READ_URL + 1)) == (Verdict.HOLD, "url_long", 2)
    # A secret outweighs the length.
    assert verdict(replace(READ, url_bytes=9000, url_struck=True))[2] == 3


def test_a_model_provider_is_never_held() -> None:
    assert verdict(replace(WRITE, provider=True, method="DELETE")) == (Verdict.PASS, "provider", 0)


def test_a_websocket_only_to_the_allowed_list() -> None:
    socket = replace(READ, websocket=True)
    assert verdict(socket) == (Verdict.PASS, "websocket", 0)
    assert verdict(replace(socket, allowed=False)) == (Verdict.REJECT, "not_allowed", 0)
    # Never held, never preapproved: an open WebSocket is a blank cheque.
    assert verdict(replace(socket, allowed=False, preapproved=True))[0] is Verdict.REJECT


def test_a_preapproved_fingerprint_passes_and_a_rejected_one_is_refused() -> None:
    assert verdict(replace(WRITE, preapproved=True)) == (Verdict.PASS, "preapproved", 0)
    assert verdict(replace(WRITE, rejected=True)) == (Verdict.REJECT, "gate_rejected", 0)
    # Rejected reads too: a read that was held (its URL carried a secret) and rejected.
    assert verdict(replace(READ, url_struck=True, rejected=True))[1] == "gate_rejected"


def test_unknown_hosts_are_gated_by_default() -> None:
    off_list = replace(READ, allowed=False)
    assert verdict(off_list) == (Verdict.PASS, "read", 0)
    assert verdict(replace(WRITE, allowed=False)) == (Verdict.HOLD, "write", 2)


def test_the_strict_mode_refuses_whatever_is_off_the_list() -> None:
    for facts in (READ, WRITE, replace(WRITE, preapproved=True)):
        assert verdict(replace(facts, allowed=False), unknown_hosts="deny") == (
            Verdict.REJECT,
            "not_allowed",
            0,
        )
    # What is on the list is gated as usual.
    assert verdict(READ, unknown_hosts="deny") == (Verdict.PASS, "read", 0)
    assert verdict(replace(WRITE, method="DELETE"), unknown_hosts="deny")[0] is Verdict.HOLD


def test_an_unknown_mode_is_an_error() -> None:
    with pytest.raises(ValueError):
        decide(READ, unknown_hosts="allow")
