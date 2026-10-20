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


# --- security review of T10-3 ----------------------------------------------------------------

UNKNOWN_READ = replace(READ, allowed=False)


def test_a_credential_header_to_an_unknown_host_is_held() -> None:
    """Review of T10-3, H1: a read to a host off ``[proxy] allow_hosts`` (and not a provider)
    with any credential header is held with risk 2 (``credential_unknown_host``): using an
    authenticated API means listing its host. To a listed host it still passes."""
    with_token = replace(UNKNOWN_READ, credential_bytes=60)
    assert verdict(with_token) == (Verdict.HOLD, "credential_unknown_host", 2)
    assert verdict(replace(with_token, allowed=True)) == (Verdict.PASS, "read", 0)
    assert verdict(replace(with_token, provider=True)) == (Verdict.PASS, "provider", 0)
    assert verdict(UNKNOWN_READ) == (Verdict.PASS, "read", 0)


def test_a_recognisable_secret_in_a_credential_header_to_an_unknown_host_is_risk_3() -> None:
    struck = replace(UNKNOWN_READ, credential_bytes=60, credentials_struck=True)
    assert verdict(struck) == (Verdict.HOLD, "credential_secret", 3)
    # To a listed host the agent's own token is no leak: within the cap, it passes.
    assert verdict(replace(struck, allowed=True)) == (Verdict.PASS, "read", 0)


def test_a_translated_read_caps_its_credential_headers_too() -> None:
    """Review of T10-3, L9: MAX_READ_CREDENTIALS holds for a translator's reads as well."""
    read = replace(TG_SEND, reading=ReadingFacts(Effect.READ, 0))
    assert verdict(replace(read, credential_bytes=MAX_READ_CREDENTIALS))[0] is Verdict.PASS
    assert verdict(replace(read, credential_bytes=MAX_READ_CREDENTIALS + 1)) == (
        Verdict.HOLD, "credentials_long", 2
    )  # fmt: skip


# --- batches (T10-4, docs/32 section 10) -----------------------------------------------------


@pytest.mark.parametrize("effect", [Effect.SEND, Effect.CHANGE])
def test_a_send_or_a_change_a_batch_covers_passes(effect: Effect) -> None:
    covered = replace(TG_SEND, reading=ReadingFacts(effect, 2, batch="b-0123abcd"))
    assert verdict(covered) == (Verdict.PASS, "batch", 0)


@pytest.mark.parametrize(
    ("effect", "risk"),
    [(Effect.FORWARD, 2), (Effect.DELETE, 3), (Effect.ADMIN, 3), (Effect.UNKNOWN, 2),
     (Effect.SEND, 3)],
)  # fmt: skip
def test_a_batch_never_lets_a_forward_a_deletion_the_unknown_or_risk_3_pass(
    effect: Effect, risk: int
) -> None:
    """Decision 8: even if the book said a rule covers it (it never does), these are held."""
    facts = replace(TG_SEND, reading=ReadingFacts(effect, risk, batch="b-0123abcd"))
    assert verdict(facts)[0] is Verdict.HOLD


def test_a_batch_never_covers_a_secret_struck_from_the_url_or_a_header() -> None:
    covered = replace(TG_SEND, reading=ReadingFacts(Effect.SEND, 2, batch="b-0123abcd"))
    assert verdict(replace(covered, url_struck=True)) == (Verdict.HOLD, "send", 3)
    assert verdict(replace(covered, headers_struck=True)) == (Verdict.HOLD, "send", 3)


def test_a_batch_comes_after_a_rejection_and_before_holding() -> None:
    covered = replace(TG_SEND, reading=ReadingFacts(Effect.SEND, 2, batch="b-0123abcd"))
    assert verdict(replace(covered, rejected=True)) == (Verdict.REJECT, "gate_rejected", 0)
    draft = replace(covered, reading=ReadingFacts(Effect.CHANGE, 2, draft_open=True,
                                                  batch="b-0123abcd"))  # fmt: skip
    assert verdict(draft)[1] == "draft_open"


def test_a_plain_write_a_batch_covers_passes_but_never_a_delete_or_a_secret() -> None:
    assert verdict(replace(WRITE, batch="b-0123abcd")) == (Verdict.PASS, "batch", 0)
    for changes in ({"method": "DELETE"}, {"body_struck": True}, {"url_struck": True},
                    {"headers_struck": True}):  # fmt: skip
        assert verdict(replace(WRITE, batch="b-0123abcd", **changes))[0] is Verdict.HOLD


def test_a_plain_read_ignores_a_batch() -> None:
    """A batch is for writes: a guarded read stays held."""
    assert verdict(replace(READ, url_bytes=MAX_READ_URL + 1, batch="b-0123abcd"))[0] is (
        Verdict.HOLD
    )


# --- the security review of T10-4 ----------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "GET", "PATCH"])
def test_an_override_that_says_delete_is_a_delete_and_never_rides_a_batch(method: str) -> None:
    """A1: ``POST`` with ``X-HTTP-Method-Override: DELETE`` is a DELETE to many servers."""
    disguised = replace(WRITE, method=method, override="DELETE", batch="b-0123abcd")
    assert verdict(disguised) == (Verdict.HOLD, "delete", 3)


@pytest.mark.parametrize(
    ("override", "risk"), [("?", 3), ("PURGE", 3), ("MOVE", 3), ("PUT", 2), ("POST", 2)]
)
def test_any_other_override_is_held_and_never_rides_a_batch(override: str, risk: int) -> None:
    """A1: a path, an unreadable value or another verb than the plain writes is risk 3."""
    assert verdict(replace(WRITE, override=override, batch="b-0123abcd")) == (
        Verdict.HOLD, "override", risk
    )  # fmt: skip
    assert verdict(replace(WRITE, override=override, body_struck=True))[2] == 3


def test_trailers_never_ride_a_batch() -> None:
    assert verdict(replace(WRITE, trailers=True, batch="b-0123abcd")) == (Verdict.HOLD, "write", 2)


def test_a_recognisable_token_rides_a_batch_only_toward_a_listed_api() -> None:
    """M1: the redaction strikes every ``Bearer …``; toward a listed API it is the agent's own
    token (T10-3, H1, and the batch is bound to it); toward any other host, never batched."""
    stray = replace(WRITE, credentials_struck=True, batch="b-0123abcd", allowed=False)
    assert verdict(stray) == (Verdict.HOLD, "write", 2)
    own = replace(WRITE, credentials_struck=True, batch="b-0123abcd", allowed=True)
    assert verdict(own) == (Verdict.PASS, "batch", 0)


def test_a_translated_request_with_an_override_or_trailers_never_passes() -> None:
    """A1: the translators read them as UNKNOWN; even a reading that said otherwise is held,
    with risk 3 when the override says DELETE or cannot be read."""
    covered = replace(TG_SEND, reading=ReadingFacts(Effect.SEND, 2, trusted=True,
                                                    batch="b-0123abcd"))  # fmt: skip
    assert verdict(replace(covered, override="DELETE")) == (Verdict.HOLD, "send", 3)
    assert verdict(replace(covered, override="?")) == (Verdict.HOLD, "send", 3)
    assert verdict(replace(covered, override="POST")) == (Verdict.HOLD, "send", 2)
    assert verdict(replace(covered, trailers=True)) == (Verdict.HOLD, "send", 2)
    read = replace(TG_SEND, reading=ReadingFacts(Effect.READ, 0))
    assert verdict(replace(read, override="DELETE")) == (Verdict.HOLD, "read", 3)
