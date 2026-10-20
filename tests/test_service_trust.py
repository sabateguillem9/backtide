"""T10-5: "aprobar y confiar en este destinatario" (docs/32, decision 9) and the shorter
"pending" of Telegram (section 16).

- ``TrustStore``: the list lives in backtide's state folder, 0600, written atomically; a file that
  cannot be used gives no trust and is never overwritten.
- ``trust_target``: only a send or a change of risk 2 to exactly one recipient, read from strict
  fields, and never what is never trusted (an inline message, a URL the platform fetches, a
  Slack channel by name, a cut reading, a secret seen, a deletion, a forward...).
- ``ProxyChannel.trust``: records ``gate/trust_added`` (no secret), approves the hold, and from
  then on a send to that recipient alone passes (``all_trusted``) without editing the TOML.
"""

import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from backtide.blackbox import BlackBox
from backtide.gate import protocol
from backtide.service.holds import (
    TRUST_RECIPIENT_CHARS,
    Hold,
    HoldTimings,
    Scope,
    TrustStatus,
    trust_target,
)
from backtide.service.trust import STATE_TRUST, TrustError, TrustStore
from tests.test_service_proxy_channel import (  # noqa: F401 - box is a fixture
    OTHER_BOT,
    OWNER,
    Gated,
    box,
    delete_event,
    policy,
    telegram_call,
    write_facts,
)

# -- the store -------------------------------------------------------------------------------------


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return state


def test_an_entry_is_normalized_saved_0600_and_read_back(folder: Path) -> None:
    store = TrustStore(folder)
    entry, new = store.add("gmail", "Ana@Ejemplo.COM", by="web", hold_id="h-0123456789ab")
    assert new and entry.recipient == "ana@ejemplo.com" and entry.trust_id.startswith("t-")
    again, new_again = store.add("gmail", "ana@ejemplo.com", by="web")
    assert again == entry and not new_again, "the same recipient once"
    path = folder / STATE_TRUST
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())[0]["recipient"] == "ana@ejemplo.com"
    later = TrustStore(folder)
    later.load()
    assert [(t.translator, t.recipient) for t in later.entries()] == [("gmail", "ana@ejemplo.com")]
    assert later.remove(entry.trust_id) == entry and later.entries() == ()
    assert json.loads(path.read_text()) == []
    assert later.remove(entry.trust_id) is None


@pytest.mark.parametrize(
    ("translator", "recipient"),
    [("slack", "#general"), ("telegram", "inline:abc"), ("gmail", "no es un correo"),
     ("webhook", "x"), ("read_post", "x")],
)  # fmt: skip
def test_what_could_never_match_is_refused(folder: Path, translator: str, recipient: str) -> None:
    with pytest.raises(ValueError):
        TrustStore(folder).add(translator, recipient, by="web")
    assert not (folder / STATE_TRUST).exists()


def test_the_list_has_a_cap(folder: Path) -> None:
    store = TrustStore(folder, limit=2)
    store.add("telegram", "556", by="web")
    store.add("telegram", "557", by="web")
    with pytest.raises(TrustError):
        store.add("telegram", "558", by="web")
    assert len(store.entries()) == 2


@pytest.mark.parametrize(
    "content",
    [
        "no es json",
        json.dumps([{"trust_id": "t-0a1b2c3d", "translator": "slack", "recipient": "#general",
                     "added_at": "x", "by": "web"}]),
        json.dumps([{"trust_id": "t-0a1b2c3d", "translator": "gmail", "recipient": "Ana@x.com",
                     "added_at": "x", "by": "web"}]),  # not normalized: never trusted as is
        json.dumps([{"trust_id": "../x", "translator": "gmail", "recipient": "ana@x.com",
                     "added_at": "x", "by": "web"}]),
    ],
)  # fmt: skip
def test_a_file_that_cannot_be_used_gives_no_trust_and_is_kept(folder: Path, content: str) -> None:
    path = folder / STATE_TRUST
    path.write_text(content)
    path.chmod(0o600)
    store = TrustStore(folder)
    store.load()
    assert store.entries() == ()
    with pytest.raises(TrustError):
        store.add("telegram", "556", by="web")
    assert path.read_text() == content, "never overwritten: a person looks at it first"


def test_a_file_open_to_others_is_not_used(folder: Path) -> None:
    path = folder / STATE_TRUST
    path.write_text(json.dumps([{"trust_id": "t-0a1b2c3d", "translator": "telegram",
                                 "recipient": "556", "added_at": "x", "by": "web"}]))  # fmt: skip
    path.chmod(0o644)
    store = TrustStore(folder)
    store.load()
    assert store.entries() == ()


def test_a_list_that_cannot_be_written_changes_nothing(folder: Path) -> None:
    store = TrustStore(folder)
    folder.chmod(0o500)
    try:
        if os.access(folder, os.W_OK):
            pytest.skip("this user can write anywhere")
        with pytest.raises(TrustError):
            store.add("telegram", "556", by="web")
    finally:
        folder.chmod(0o700)
    assert store.entries() == ()


# -- what may be trusted ---------------------------------------------------------------------------


def hold_with(reading: dict[str, Any] | None, *, risk: int = 2, batchable: bool = True) -> Hold:
    hold = Hold("h-0123456789ab", "f" * 64, risk, "send", {}, 0.0, 300.0, "2026-10-20T10:05:00Z")
    hold.reading = reading
    hold.scope = Scope(translator="telegram", batchable=batchable)
    return hold


def reading(**changes: Any) -> dict[str, Any]:
    base = {"translator": "telegram", "effect": "send", "recipients": ["556"], "reply_to": [],
            "secret_seen": False, "cut": False, "draft": None, "notes": []}  # fmt: skip
    return base | changes


def test_a_send_to_one_recipient_may_be_trusted() -> None:
    assert trust_target(hold_with(reading())) == ("telegram", "556")
    assert trust_target(hold_with(reading(effect="change"))) == ("telegram", "556")
    # A group (negative id) or a supergroup or channel (-100...): trustable, and the web says
    # in our words that everyone in it reads it (final review of T10, finding 9).
    assert trust_target(hold_with(reading(recipients=["-1001234567890"]))) == (
        "telegram", "-1001234567890"
    )  # fmt: skip
    slack = reading(translator="slack", recipients=["C0123ABCD9"])
    assert trust_target(hold_with(slack)) == ("slack", "C0123ABCD9")
    longest = reading(translator="discord", recipients=["1" * TRUST_RECIPIENT_CHARS])
    assert trust_target(hold_with(longest)) == ("discord", "1" * TRUST_RECIPIENT_CHARS)


@pytest.mark.parametrize(
    "hold",
    [
        hold_with(None),  # no translator read it
        hold_with(reading(), risk=3),
        hold_with(reading(), batchable=False),  # an override header or trailers
        hold_with(reading(effect="forward")),
        hold_with(reading(effect="delete")),
        hold_with(reading(effect="admin")),
        hold_with(reading(effect="unknown")),
        hold_with(reading(recipients=["556", "557"])),
        hold_with(reading(recipients=[])),
        hold_with(reading(notes=["fetches_url"])),
        hold_with(reading(notes=["inline_message"], recipients=["inline:abc"])),
        hold_with(reading(notes=["webhook"])),
        hold_with(reading(secret_seen=True)),
        hold_with(reading(cut=True)),
        hold_with(reading(draft="d" * 32)),
        hold_with(reading(translator="slack", recipients=["#general"])),
        hold_with(reading(translator="gmail", recipients=["ana@x.com"], reply_to=["malo@x.com"])),
        hold_with(reading(translator="read_post")),
        # Final review of T10: no mail recipient until the owner's accounts exist (finding 2),
        # nothing too long to read whole (finding 4), no Telegram @name (finding 9).
        hold_with(reading(translator="gmail", recipients=["ana@x.com"], reply_to=["ana@x.com"])),
        hold_with(reading(translator="graph_mail", recipients=["ana@x.com"])),
        hold_with(reading(translator="discord", recipients=["1" * (TRUST_RECIPIENT_CHARS + 1)])),
        hold_with(reading(recipients=["@canal_publico"])),
    ],
)
def test_what_is_never_trusted(hold: Hold) -> None:
    assert trust_target(hold) is None


# -- the channel -----------------------------------------------------------------------------------


@pytest.fixture
def trusting(box: BlackBox, folder: Path) -> Iterator[tuple[Gated, TrustStore]]:  # noqa: F811
    from backtide.gate.translate.base import normalize_trusted

    store = TrustStore(folder)
    made = Gated(
        box,
        trust=store,
        policy=policy(unknown_hosts="hold", trusted=(normalize_trusted("telegram", OWNER),)),
    )
    try:
        yield made, store
    finally:
        made.channel.close()


def trust(gated: Gated, hold_id: str, **options: Any) -> Any:
    return gated.channel.trust(hold_id, by="web", requested_by="web (uid 1, pid 2)", **options)


def test_aprobar_y_confiar_records_approves_and_trusts_from_then_on(
    trusting: tuple[Gated, TrustStore],
) -> None:
    gated, store = trusting
    hold_id = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    [pending] = gated.channel.pending()
    assert pending["trustable"] is True and pending["view"]["recipients"] == ["556"]
    outcome = trust(gated, hold_id)
    assert outcome.status is TrustStatus.TRUSTED and str(outcome.hold) == "released"
    [added] = gated.gate_events("trust_added")
    [approved] = gated.gate_events("approved")
    assert added.seq < approved.seq and added.risk == 2
    assert {k: added.details[k] for k in ("hold_id", "translator", "recipient", "by")} == {
        "hold_id": hold_id, "translator": "telegram", "recipient": "556", "by": "web"
    }  # fmt: skip
    assert added.details["trust_id"] == outcome.trust_id
    assert gated.proxy.receive_type("decision")["verdict"] == "allow"
    assert [(t.translator, t.recipient) for t in store.entries()] == [("telegram", "556")]
    # From now on a send to 556 alone passes, as one to [gate] trusted, with any text.
    ack = gated.ask(*telegram_call("556", "dos", n=2))
    assert ack["verdict"] == "allow"
    assert gated.requests()[-1].details["gate"]["decision"] == "trusted"
    # Anything else still asks: another chat, or a forward to it.
    assert gated.ask(*telegram_call("557", "tres", n=3))["verdict"] == "hold"
    forward = telegram_call("556", "x", n=4, method="forwardMessage",
                            extra="&from_chat_id=1&message_id=2")  # fmt: skip
    assert gated.ask(*forward)["verdict"] == "hold"


def test_a_trust_that_may_not_be_given_changes_nothing(
    trusting: tuple[Gated, TrustStore],
) -> None:
    gated, store = trusting
    deleted = gated.ask(delete_event(), write_facts())["hold_id"]
    assert trust(gated, deleted).status is TrustStatus.NOT_TRUSTABLE
    photo = telegram_call("556", "x", n=2, method="sendPhoto",
                          extra="&photo=https://malo.example/a.jpg")  # fmt: skip
    fetches = gated.ask(*photo)["hold_id"]
    assert trust(gated, fetches).status is TrustStatus.NOT_TRUSTABLE
    sent = gated.ask(*telegram_call("556", "y", n=3))["hold_id"]
    assert trust(gated, sent, frozen=lambda: True).status is TrustStatus.PAUSED
    assert trust(gated, "h-000000000000").status is TrustStatus.UNKNOWN
    assert store.entries() == () and gated.gate_events("trust_added") == []
    assert {h["hold_id"] for h in gated.channel.pending()} == {deleted, fetches, sent}
    with pytest.raises(ValueError):
        gated.channel.trust(sent, by="agent", requested_by="x")


def test_a_trust_that_cannot_be_saved_approves_nothing(
    trusting: tuple[Gated, TrustStore], folder: Path
) -> None:
    gated, store = trusting
    hold_id = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    (folder / STATE_TRUST).write_text("roto")
    store.load()  # unreadable now: no trust is added until a person looks
    outcome = trust(gated, hold_id)
    assert outcome.status is TrustStatus.FAILED and outcome.hold is None
    assert gated.gate_events("approved") == [] and gated.gate_events("trust_added") == []
    assert [h["hold_id"] for h in gated.channel.pending()] == [hold_id]


def test_a_trust_is_recorded_before_it_is_saved_and_used(
    trusting: tuple[Gated, TrustStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final review of T10, finding 6: two phases. ``gate/trust_added`` comes first; if saving
    then fails, ``gate/trust_failed`` says so, nothing is trusted and the hold stays open."""
    gated, store = trusting
    hold_id = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    seen: list[list[str]] = []

    def cannot_write(*_args: Any, **_kwargs: Any) -> None:
        seen.append([e.action for e in gated.gate_events()])
        raise OSError("disk full")

    monkeypatch.setattr("backtide.service.trust.write_private", cannot_write)
    outcome = trust(gated, hold_id)
    assert outcome.status is TrustStatus.FAILED and outcome.hold is None
    assert seen == [["held", "trust_added"]], "recorded before the file is written"
    [added] = gated.gate_events("trust_added")
    [failed] = gated.gate_events("trust_failed")
    assert failed.details["trust_id"] == added.details["trust_id"] and added.seq < failed.seq
    assert failed.details["why"] == "not_saved" and failed.details["by"] == "web"
    assert store.entries() == () and gated.gate_events("approved") == []
    assert [h["hold_id"] for h in gated.channel.pending()] == [hold_id]
    assert gated.ask(*telegram_call("556", "dos", n=2))["verdict"] == "hold", "never used"
    monkeypatch.undo()
    assert trust(gated, hold_id).status is TrustStatus.TRUSTED
    assert [(t.translator, t.recipient) for t in store.entries()] == [("telegram", "556")]


def test_a_trust_that_cannot_be_recorded_is_never_saved(box: BlackBox, folder: Path) -> None:  # noqa: F811
    from backtide.gate.translate.base import normalize_trusted
    from tests.test_service_proxy_channel import Failing

    store = TrustStore(folder)
    owner = (normalize_trusted("telegram", OWNER),)
    gated = Gated(box, trust=store, record=Failing(box, "trust_added"),
                  policy=policy(unknown_hosts="hold", trusted=owner))  # fmt: skip
    try:
        hold_id = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
        assert trust(gated, hold_id).status is TrustStatus.FAILED
        assert gated.gate_events("approved") == []
        assert store.entries() == () and not (folder / STATE_TRUST).exists()
    finally:
        gated.channel.close()


def test_other_holds_to_a_newly_trusted_recipient_are_decided_on_their_own(
    trusting: tuple[Gated, TrustStore],
) -> None:
    """Final review of T10, finding 1: two messages to 556 are held; "aprobar y confiar" on the
    first. The second one's retry (same fingerprint) joins its own hold instead of passing as
    trusted: it goes out only if that hold is approved, and never twice. A new message to 556
    passes."""
    gated, _store = trusting
    first = gated.ask(*telegram_call("556", "uno", n=1))["hold_id"]
    second = gated.ask(*telegram_call("556", "dos", n=2))
    gated.proxy.send(protocol.hold_left(second["hold_id"], "waited"))  # its client gave up
    gated.until(lambda: len([h for h in gated.channel.pending() if not h["waiting"]]) == 1)
    assert trust(gated, first).status is TrustStatus.TRUSTED
    gated.proxy.receive_type("decision")
    retry = gated.ask(*telegram_call("556", "dos", n=2))
    assert retry["verdict"] == "hold" and retry["hold_id"] == second["hold_id"]
    assert len(gated.gate_events("held")) == 2, "it joined: no new hold"
    sent = [e.details["path"] for e in gated.requests()]
    assert not any("text=dos" in path for path in sent), "nothing of the second went out"
    assert [h["hold_id"] for h in gated.channel.pending()] == [second["hold_id"]]
    new = gated.ask(*telegram_call("556", "tres", n=3))
    assert new["verdict"] == "allow"
    assert gated.requests()[-1].details["gate"]["decision"] == "trusted"
    # The second one is decided apart: approved, it goes out once.
    assert gated.decide(second["hold_id"]) == "released"
    gated.proxy.receive_type("decision")
    assert sum("text=dos" in e.details["path"] for e in gated.requests()) == 1


def test_trust_is_per_api_and_survives_another_bot(trusting: tuple[Gated, TrustStore]) -> None:
    """A trusted chat is trusted with any bot, like the owner's (docs/32, section 9)."""
    gated, store = trusting
    trust(gated, gated.ask(*telegram_call("556", "uno", n=1))["hold_id"])
    gated.proxy.receive_type("decision")
    assert gated.ask(*telegram_call("556", "dos", n=2, bot=OTHER_BOT))["verdict"] == "allow"
    store.remove(store.listing()[0]["trust_id"])
    assert gated.ask(*telegram_call("556", "tres", n=3))["verdict"] == "hold"


# -- Telegram's "pending" (section 16) -------------------------------------------------------------


def test_telegrams_pending_asks_for_a_short_wait_and_the_rest_for_30_s(
    trusting: tuple[Gated, TrustStore],
) -> None:
    """OpenClaw's Telegram channel stops the whole bot for retry_after s after a 429 (measured
    in T10-5: the owner's reply waited 29.8 s with 30 and 2.0 s with 2)."""
    gated, _store = trusting
    assert gated.ask(*telegram_call("556", "uno", n=1))["retry_after"] == 2
    assert gated.ask(delete_event(), write_facts())["retry_after"] == 30
    assert HoldTimings().telegram_retry_after == 2 <= HoldTimings().retry_after
