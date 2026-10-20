"""The gate's table (backtide/gate/decide.py, docs/32 section 5), with and without a translator."""

from dataclasses import replace

import pytest

from backtide.gate.decide import (
    MAX_READ_CREDENTIALS,
    MAX_READ_HEADERS,
    MAX_READ_URL,
    Decision,
    Facts,
    ReadingFacts,
    Verdict,
    decide,
)
from backtide.gate.translate.base import Effect

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


def test_a_read_whose_headers_carried_a_secret_is_held_with_risk_3() -> None:
    """Decision 1's guard looks at the headers too (security review of T10-2, M3): a GET with
    ``X-Data: AKIA...`` would carry the secret out as surely as its URL."""
    assert verdict(replace(READ, headers_struck=True)) == (Verdict.HOLD, "header_secret", 3)


def test_a_read_with_long_headers_is_held_with_risk_2() -> None:
    assert verdict(replace(READ, header_bytes=MAX_READ_HEADERS)) == (Verdict.PASS, "read", 0)
    assert verdict(replace(READ, header_bytes=MAX_READ_HEADERS + 1)) == (
        Verdict.HOLD, "headers_long", 2
    )  # fmt: skip
    assert MAX_READ_HEADERS == 2048
    assert verdict(replace(READ, header_bytes=9000, headers_struck=True))[2] == 3
    # Once a write, the method decides: the guard is for what would pass unasked.
    assert verdict(replace(WRITE, headers_struck=True)) == (Verdict.HOLD, "write", 2)


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


# --- rule 5: a translator's reading (T10-3) ------------------------------------------------------

TG_SEND = Facts(method="GET", exact_read=True, has_body=False, url_bytes=80, url_struck=False,
                reading=ReadingFacts(Effect.SEND, 2))  # fmt: skip


def test_on_a_host_with_a_translator_rule_6_never_applies() -> None:
    """``GET api.telegram.org/bot…/sendMessage?chat_id=…`` is a send: held, not a read."""
    assert verdict(TG_SEND) == (Verdict.HOLD, "send", 2)
    # Off the allowed list too: unknown hosts are gated, not refused.
    assert verdict(replace(TG_SEND, allowed=False)) == (Verdict.HOLD, "send", 2)


def test_a_translated_read_passes_whatever_its_method() -> None:
    poll = replace(TG_SEND, method="POST", exact_read=False, has_body=True,
                   reading=ReadingFacts(Effect.READ, 0))  # fmt: skip
    assert verdict(poll) == (Verdict.PASS, "translator_read", 0)
    assert verdict(replace(poll, url_bytes=MAX_READ_URL + 1)) == (Verdict.HOLD, "url_long", 2)
    assert verdict(replace(poll, header_bytes=MAX_READ_HEADERS + 1))[1] == "headers_long"
    # A secret struck from its URL or headers: held, risk 3.
    assert verdict(replace(poll, url_struck=True)) == (Verdict.HOLD, "url_secret", 3)
    assert verdict(replace(poll, headers_struck=True)) == (Verdict.HOLD, "header_secret", 3)


@pytest.mark.parametrize("effect", [Effect.SEND, Effect.CHANGE])
def test_a_send_or_a_change_to_trusted_recipients_passes(effect: Effect) -> None:
    trusted = replace(TG_SEND, reading=ReadingFacts(effect, 2, trusted=True))
    assert verdict(trusted) == (Verdict.PASS, "trusted", 0)
    # Never with a secret in its URL (the reading's own secret makes ``trusted`` False).
    assert verdict(replace(trusted, url_struck=True)) == (Verdict.HOLD, str(effect), 3)


@pytest.mark.parametrize(
    ("effect", "risk"),
    [(Effect.FORWARD, 2), (Effect.DELETE, 3), (Effect.ADMIN, 3), (Effect.UNKNOWN, 2)],
)
def test_forwards_deletions_administration_and_the_unknown_are_always_held(
    effect: Effect, risk: int
) -> None:
    facts = replace(TG_SEND, reading=ReadingFacts(effect, risk, trusted=True))
    assert verdict(facts) == (Verdict.HOLD, str(effect), risk)


def test_the_risk_of_a_translated_hold_is_the_readings() -> None:
    secret = replace(TG_SEND, reading=ReadingFacts(Effect.SEND, 3))
    assert verdict(secret) == (Verdict.HOLD, "send", 3)


def test_the_bot_token_in_the_path_alone_never_raises_the_risk() -> None:
    """The proxy leaves ``path_credential`` out of ``url_struck``: a send to an untrusted chat
    is risk 2, not 3, though the black box strikes its token from the path."""
    assert verdict(TG_SEND)[2] == 2


def test_a_draft_change_while_its_sending_is_held_is_held() -> None:
    change = replace(TG_SEND, method="PUT", exact_read=False, has_body=True,
                     reading=ReadingFacts(Effect.READ, 0, draft_open=True))  # fmt: skip
    assert verdict(change) == (Verdict.HOLD, "draft_open", 2)
    trusted = replace(change, reading=ReadingFacts(Effect.CHANGE, 2, trusted=True,
                                                   draft_open=True))  # fmt: skip
    assert verdict(trusted) == (Verdict.HOLD, "draft_open", 2)
    assert verdict(replace(change, reading=ReadingFacts(Effect.READ, 0)))[0] is Verdict.PASS


def test_preapprovals_rejections_and_the_strict_mode_come_before_a_reading() -> None:
    assert verdict(replace(TG_SEND, preapproved=True)) == (Verdict.PASS, "preapproved", 0)
    assert verdict(replace(TG_SEND, rejected=True))[1] == "gate_rejected"
    assert verdict(replace(TG_SEND, allowed=False), unknown_hosts="deny")[1] == "not_allowed"


def test_a_plain_read_caps_its_credential_headers() -> None:
    """T10-3: reads to unknown hosts pass, so the credential headers (whose values are not
    searched) are no free channel out: over 4 KiB together, held with risk 2."""
    assert verdict(replace(READ, credential_bytes=MAX_READ_CREDENTIALS)) == (
        Verdict.PASS, "read", 0
    )  # fmt: skip
    assert verdict(replace(READ, credential_bytes=MAX_READ_CREDENTIALS + 1)) == (
        Verdict.HOLD, "credentials_long", 2
    )  # fmt: skip


def test_a_write_whose_url_or_body_carried_a_secret_is_risk_3() -> None:
    """docs/32, section 5: any request whose URL or body carried a secret that the redaction
    struck is held with risk 3."""
    assert verdict(replace(WRITE, body_struck=True)) == (Verdict.HOLD, "write", 3)
    assert verdict(replace(WRITE, url_struck=True)) == (Verdict.HOLD, "write", 3)
    assert verdict(replace(WRITE, headers_struck=True)) == (Verdict.HOLD, "write", 2)
