"""The notice of a refusal of risk 2 toward a local model (T20-5, docs/35 decision 9): the first
of each reason at once, then at most one every 10 minutes per reason, and what was counted in
between is never lost. Risk 3 is not this notice's: the RiskResponder already tells it."""

from typing import Any

import pytest

from backtide.blackbox import Event
from backtide.blackbox.model import Source
from backtide.notify import AlertLevel
from backtide.notify.local_refusals import EVERY, LocalRefusals


class Told:
    """The alert door (the Guardian's ``_alert``): what it was asked to say."""

    def __init__(self) -> None:
        self.alerts: list[tuple[AlertLevel, str, str, Event | None]] = []

    def __call__(self, level: AlertLevel, title: str, body: str, event: Event | None) -> None:
        self.alerts.append((level, title, body, event))

    @property
    def bodies(self) -> list[str]:
        return [body for _, _, body, _ in self.alerts]


def blocked(
    seq: int, reason: str = "provider_endpoint", path: str = "/api/tags", risk: int = 2, **more: Any
) -> Event:
    details = {"reason": reason, "method": "GET", "host": "ollama.backtide.internal",
               "path": path, "local": True} | more  # fmt: skip
    target = f"https://ollama.backtide.internal{path}"
    return Event(seq, "2026-10-23T10:00:00.000000Z", Source.NET, "blocked", target, details, risk,
                 None, "p", "h")  # fmt: skip


@pytest.fixture
def clock() -> list[float]:
    return [1000.0]


@pytest.fixture
def told() -> Told:
    return Told()


@pytest.fixture
def notices(told: Told, clock: list[float]) -> LocalRefusals:
    return LocalRefusals(told, clock=lambda: clock[0])


def test_the_first_refusal_of_a_reason_is_told_at_once(notices: LocalRefusals, told: Told) -> None:
    event = blocked(7)
    notices.note(event, "ollama")
    [(level, title, body, cited)] = told.alerts
    assert level is AlertLevel.WARNING
    assert "ollama" in title
    assert "provider_endpoint" in body and "GET ∕api/tags" in body
    assert "No ha llegado a esa máquina" in body
    assert cited is event  # the alert cites the refusal it is about


def test_then_at_most_one_every_ten_minutes_per_reason_with_how_many(
    notices: LocalRefusals, told: Told, clock: list[float]
) -> None:
    notices.note(blocked(1), "ollama")
    for seq in (2, 3, 4):
        clock[0] += 60
        notices.note(blocked(seq, path=f"/api/ps{seq}"), "ollama")
    notices.send_due()
    assert len(told.alerts) == 1  # the three within the 10 min are held, counted
    clock[0] = 1000.0 + EVERY
    notices.send_due()
    assert len(told.alerts) == 2
    _, _, body, cited = told.alerts[-1]
    assert "Son 3 así" in body and "∕api/ps4" in body
    assert cited is not None and cited.seq == 2  # the first of those held back
    notices.send_due()
    assert len(told.alerts) == 2  # nothing left


def test_each_reason_has_its_own_ten_minutes(notices: LocalRefusals, told: Told) -> None:
    notices.note(blocked(1), "ollama")
    notices.note(blocked(2, "provider_side_tool", "/v1/chat/completions", tools=["param:options"]),
                 "ollama")  # fmt: skip
    notices.note(blocked(3, "foreign_credential"), "ollama")
    notices.note(blocked(4, "provider_endpoint"), "ollama")
    reasons = told.bodies
    assert len(reasons) == 3
    assert "param:options" in reasons[1]


def test_a_refusal_after_its_ten_minutes_goes_out_with_those_held(
    notices: LocalRefusals, told: Told, clock: list[float]
) -> None:
    """Without a tick in between (the channel was down): the next one carries the count."""
    notices.note(blocked(1), "ollama")
    notices.note(blocked(2), "ollama")
    clock[0] += EVERY + 1
    notices.note(blocked(3), "ollama")
    assert len(told.alerts) == 2
    assert "Son 2 así" in told.alerts[-1][2]


def test_flush_sends_what_is_held_at_once(notices: LocalRefusals, told: Told) -> None:
    """The service stops: nothing counted is lost (one decoy cannot buy ten quiet minutes)."""
    notices.note(blocked(1), "ollama")
    notices.note(blocked(2, path="/api/generate"), "ollama")
    notices.flush()
    assert len(told.alerts) == 2 and "∕api/generate" in told.alerts[-1][2]
    notices.flush()
    assert len(told.alerts) == 2


def test_only_risk_2_refusals_are_its_own(notices: LocalRefusals, told: Told) -> None:
    admin = blocked(1, path="/api/pull", risk=3)  # the RiskResponder tells it, with evidence
    notices.note(admin, "ollama")
    other = Event(2, "2026-10-23T10:00:00.000000Z", Source.NET, "request", "x", {}, 2, None,
                  "p", "h")  # fmt: skip
    notices.note(other, "ollama")
    assert told.alerts == []


def test_what_the_agent_chose_is_escaped_and_cut(notices: LocalRefusals, told: Told) -> None:
    path = "/api/‮evil\x1b[31m" + "x" * 500
    notices.note(blocked(1, path=path, method="G\nET"), "ollama")
    [(_, _, body, _)] = told.alerts
    assert "‮" not in body and "\x1b" not in body and "\n" not in body
    assert len(body) < 700


def test_a_broken_alert_door_never_raises(clock: list[float]) -> None:
    def broken(*args: Any) -> None:
        raise RuntimeError("the queue broke")

    notices = LocalRefusals(broken, clock=lambda: clock[0])
    notices.note(blocked(1), "ollama")  # logged, never raised into the channel's reader
    notices.note(blocked(2), "ollama")
    notices.flush()


def test_so_many_reasons_fold_into_one_line(notices: LocalRefusals, told: Told) -> None:
    for n in range(200):
        notices.note(blocked(n, reason=f"made_up_{n}"), "ollama")
    assert 0 < len(told.alerts) <= 65


def test_what_the_agent_chose_cannot_become_a_link(notices: LocalRefusals, told: Told) -> None:
    """B2 of the review of T20-5: like the hold notice (T10-4 B2), a domain, a mail address, a
    mention or a phone number the agent put in the path or the tools is made untappable."""
    notices.note(
        blocked(1, "provider_side_tool", "/t.me/x?to=a@b.c&tel=+34600000000",
                tools=["t.me/y", "(x)"]),
        "ollama",
    )  # fmt: skip
    [(_, _, body, _)] = told.alerts
    for tappable in ("t.me", "a@b.c", "@", "+34600000000"):
        assert tappable not in body, tappable
    assert "(x)" not in body  # the notice's own markers cannot be drawn by the agent


def test_two_local_providers_are_counted_apart(
    notices: LocalRefusals, told: Told, clock: list[float]
) -> None:
    """B3: the count is by provider and reason, so a folded notice names the right one."""
    notices.note(blocked(1), "ollama")
    notices.note(blocked(2), "torre")
    assert [title for _, title, _, _ in told.alerts] == [
        "Rechazado hacia el modelo local ollama",
        "Rechazado hacia el modelo local torre",
    ]
    notices.note(blocked(3), "torre")
    notices.note(blocked(4), "torre")
    notices.flush()
    [(_, title, body, _)] = told.alerts[2:]
    assert title.endswith("torre") and "Son 2 así" in body


def test_a_redirection_did_reach_the_local_model(notices: LocalRefusals, told: Told) -> None:
    """B4: a local_redirect is the model's answer, cut: the request did reach that machine."""
    notices.note(blocked(1, "local_redirect", "/v1/chat/completions", side="response"), "ollama")
    [(_, _, body, _)] = told.alerts
    assert "No ha llegado a esa máquina" not in body
    assert "Llegó al modelo local, pero su respuesta" in body
    assert "no ha llegado al agente" in body
