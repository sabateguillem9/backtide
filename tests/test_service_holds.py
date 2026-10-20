"""The book of held requests (backtide/service/holds.py, docs/32 sections 6 and 7), on a fake
clock: hold, wait, "pending", join, approve with the request connected (``released``) and
without it (preapproval), the preapproval spent once and gone after 10 min, the hold gone after
5 min, the rejection remembered, the caps and the flood, and a restart that closes everything.
"""

import re
from datetime import UTC, datetime, timedelta

import pytest

from backtide.service.holds import HoldBook, HoldTimings, State, stale_holds

FP, OTHER = "a" * 64, "b" * 64
EVENT = {"source": "net", "action": "request", "target": "https://api.fake.test/x", "risk": 0,
         "details": {"method": "DELETE", "host": "api.fake.test", "path": "/x"}}  # fmt: skip
START = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def wall(self) -> datetime:
        return START + timedelta(seconds=self.now - 1000.0)


def make(**timings: float) -> tuple[HoldBook, Clock]:
    clock = Clock()
    book = HoldBook(HoldTimings(**timings), clock=clock, wall=clock.wall)  # type: ignore[arg-type]
    return book, clock


def held(book: HoldBook, fp: str = FP, risk: int = 3, seq: int = 10):
    hold = book.open(fp, risk=risk, reason="delete", event=EVENT)
    assert hold is not None
    book.recorded(hold, seq)
    return hold


def test_a_new_hold_has_an_id_a_life_and_one_request_waiting() -> None:
    book, _ = make()
    hold = held(book)
    assert re.fullmatch(r"h-[0-9a-f]{12}", hold.hold_id)
    assert (hold.state, hold.connected, hold.seq, hold.risk) == (State.OPEN, 1, 10, 3)
    assert hold.expires_at == "2026-10-20T12:05:00Z"
    assert book.live(FP) is hold and book.get(hold.hold_id) is hold
    assert book.pending() == [hold]
    assert book.wait_ms(hold) == 90_000


def test_the_wait_is_the_shortest_of_90_s_the_clients_and_what_is_left() -> None:
    book, clock = make()
    hold = held(book)
    assert book.wait_ms(hold, 50) == 50_000  # a translator's hint (T10-3)
    clock.now += 280
    assert book.wait_ms(hold) == 22_000  # 20 s of its 5 min are left, and the tick's margin
    clock.now += 30
    assert book.wait_ms(hold) == 2_000


def test_a_hold_whose_gate_held_was_not_recorded_is_gone() -> None:
    book, _ = make()
    hold = book.open(FP, risk=2, reason="write", event=EVENT)
    assert hold is not None
    book.discard(hold)
    assert book.live(FP) is None and book.get(hold.hold_id) is None and book.pending() == []


def test_a_retry_with_the_same_fingerprint_joins_the_hold() -> None:
    book, _ = make()
    hold = held(book)
    assert book.left(hold.hold_id) is hold  # it waited 90 s: "pending"
    assert hold.connected == 0 and hold.state is State.OPEN
    retry = EVENT | {"details": EVENT["details"] | {"flow_id": "f2"}}
    book.join(hold, retry)
    assert hold.connected == 1 and hold.event == retry
    assert book.pending() == [hold]


def test_a_twin_that_joins_while_one_waits_keeps_the_waiting_ones_event() -> None:
    """Security review of T10-2, M2: what is recorded when the yes lets it out is the request in
    the proxy's slot (the one waiting), never the latest retry's, which got no slot."""
    book, _ = make()
    hold = held(book)
    twin = EVENT | {"details": EVENT["details"] | {"flow_id": "f2"}}
    book.join(hold, twin)
    assert hold.connected == 2 and hold.event == EVENT
    book.left(hold.hold_id)  # the twin: "pending" at once
    assert hold.connected == 1 and hold.event == EVENT


def test_approved_with_the_request_connected_it_is_spent_when_released() -> None:
    book, _ = make()
    hold = held(book)
    assert book.approve(hold.hold_id) is hold
    book.release(hold)
    assert hold.state is State.RELEASING
    assert book.live(FP) is hold  # a retry meanwhile joins: never a second copy
    assert book.released(hold.hold_id) is hold
    assert book.get(hold.hold_id) is None and book.live(FP) is None
    assert not book.preapproved(FP)  # spent: the same request asks again
    assert book.released(hold.hold_id) is None


def test_approved_while_the_proxy_lets_the_request_go_it_becomes_a_preapproval() -> None:
    """The yes crossed a hold_left (the client gave up, or the wait ended): the yes is not lost
    and not spent twice. The next identical request passes once."""
    book, clock = make()
    hold = held(book)
    book.approve(hold.hold_id)
    book.release(hold)
    assert book.left(hold.hold_id) is hold
    assert hold.state is State.PREAPPROVED and book.preapproved(FP)
    assert book.released(hold.hold_id) is None  # too late: it is a preapproval now
    assert book.spend(FP) is hold
    assert book.spend(FP) is None and not book.preapproved(FP)
    clock.now += 1
    assert book.due() == []


def test_a_retry_that_joined_while_releasing_keeps_it_releasing() -> None:
    book, _ = make()
    hold = held(book)
    book.approve(hold.hold_id)
    book.release(hold)
    book.join(hold, EVENT)  # a second identical request, meanwhile
    book.left(hold.hold_id)  # the first one's client left: the second may still go
    assert hold.state is State.RELEASING and hold.connected == 1
    assert book.released(hold.hold_id) is hold


def test_approved_with_nobody_waiting_it_is_a_preapproval_of_one_use_for_10_min() -> None:
    book, clock = make()
    hold = held(book)
    book.left(hold.hold_id)
    assert book.approve(hold.hold_id) is hold
    book.preapprove(hold)
    assert book.preapproved(FP) and book.pending() == [] and book.live(FP) is None
    clock.now += 599
    assert book.preapproved(FP)
    clock.now += 2
    assert not book.preapproved(FP) and book.spend(FP) is None
    assert book.due() == []  # a preapproval that lapses says nothing: it only gave leave


def test_only_an_open_hold_is_approved() -> None:
    book, _ = make()
    hold = held(book)
    assert book.approve("h-000000000000") is None
    book.approve(hold.hold_id)
    book.release(hold)
    assert book.approve(hold.hold_id) is None  # already approved
    assert book.reject(hold.hold_id) is None  # and too late to take back


def test_a_rejection_is_remembered_for_10_min() -> None:
    book, clock = make()
    hold = held(book)
    assert book.reject(hold.hold_id) is hold
    assert book.get(hold.hold_id) is None and book.rejected(FP) and not book.rejected(OTHER)
    clock.now += 599
    assert book.rejected(FP)
    clock.now += 2
    assert not book.rejected(FP)


def test_a_preapproval_can_be_rejected_before_it_is_used() -> None:
    book, _ = make()
    hold = held(book)
    book.left(hold.hold_id)
    book.approve(hold.hold_id)
    book.preapprove(hold)
    assert book.reject(hold.hold_id) is hold
    assert not book.preapproved(FP) and book.rejected(FP)


def test_a_hold_with_no_answer_expires_after_5_min_and_is_remembered() -> None:
    book, clock = make()
    hold = held(book)
    clock.now += 299
    assert book.due() == []
    clock.now += 2
    assert book.due() == [hold]
    assert book.get(hold.hold_id) is None and book.rejected(FP)
    assert book.approve(hold.hold_id) is None  # a yes after the end does nothing
    assert book.due() == []


def test_the_life_starts_at_the_first_gate_held_and_a_join_does_not_extend_it() -> None:
    book, clock = make()
    hold = held(book)
    clock.now += 200
    book.join(hold, EVENT)
    clock.now += 101
    assert book.due() == [hold]


def test_at_most_20_open_holds_and_the_rest_counted_in_a_flood() -> None:
    book, clock = make()
    for n in range(20):
        held(book, fp=f"{n:064x}")
    assert book.open(OTHER, risk=2, reason="write", event=EVENT) is None
    assert book.open("c" * 64, risk=2, reason="write", event=EVENT) is None
    assert book.flood() == (2, 1)
    assert book.flood() is None  # one gate/flood every 10 s at most
    assert book.open("d" * 64, risk=2, reason="write", event=EVENT) is None
    clock.now += 5
    assert book.flood() is None
    clock.now += 5
    assert book.flood() == (1, 10)
    # A join never counts against the cap.
    first = book.live(f"{0:064x}")
    assert first is not None
    book.join(first, EVENT)


def test_a_preapproval_does_not_count_as_an_open_hold() -> None:
    book, _ = make(max_open=1)
    hold = held(book)
    book.left(hold.hold_id)
    book.approve(hold.hold_id)
    book.preapprove(hold)
    assert book.open(OTHER, risk=2, reason="write", event=EVENT) is not None


def test_closing_the_book_ends_every_hold_and_forgets_every_leave() -> None:
    """The channel was lost or backtide stops: what was open is ended (gate/expired), and the
    preapprovals and the memory of rejections go with the fingerprint key."""
    book, _ = make()
    open_one = held(book)
    releasing = held(book, fp=OTHER)
    book.approve(releasing.hold_id)
    book.release(releasing)
    leave = held(book, fp="c" * 64)
    book.left(leave.hold_id)
    book.approve(leave.hold_id)
    book.preapprove(leave)
    rejected = held(book, fp="d" * 64)
    book.reject(rejected.hold_id)
    assert book.close_all() == [open_one, releasing]
    assert not book.preapproved("c" * 64) and not book.rejected("d" * 64)
    assert book.pending() == [] and book.close_all() == []


def test_a_pause_or_a_rewind_rejects_the_open_holds() -> None:
    book, _ = make()
    first = held(book)
    second = held(book, fp=OTHER)
    book.left(second.hold_id)
    leave = held(book, fp="c" * 64)
    book.left(leave.hold_id)
    book.approve(leave.hold_id)
    book.preapprove(leave)
    assert book.reject_open() == [first, second]
    assert book.rejected(FP) and book.rejected(OTHER)
    assert not book.preapproved("c" * 64)  # a leave given before the pause does not survive it


def test_a_yes_being_released_when_the_agent_is_paused_never_becomes_a_preapproval() -> None:
    """Security review of T10-2, B2: the proxy may say hold_left after the pause (its client
    left as the agent froze). That yes must not wait for the agent's next identical request."""
    book, _ = make()
    hold = held(book)
    book.approve(hold.hold_id)
    book.release(hold)
    assert book.reject_open() == []  # too late to reject: the decision went
    assert book.left(hold.hold_id) is hold
    assert not book.preapproved(FP) and book.get(hold.hold_id) is None
    assert book.live(FP) is None  # the next identical request asks again


def test_a_yes_being_released_when_paused_may_still_be_spent_by_the_proxy() -> None:
    book, _ = make()
    hold = held(book)
    book.approve(hold.hold_id)
    book.release(hold)
    book.reject_open()
    assert book.released(hold.hold_id) is hold and book.get(hold.hold_id) is None


def test_ids_are_never_reused() -> None:
    book, _ = make()
    ids = {held(book, fp=f"{n:064x}").hold_id for n in range(20)}
    assert len(ids) == 20


# --- after a restart -----------------------------------------------------------------------------


def gate(action: str, hold_id: str, minutes_ago: float) -> tuple[str, str, datetime]:
    return action, hold_id, START - timedelta(minutes=minutes_ago)


def test_a_restart_closes_the_holds_left_open_in_the_last_15_min() -> None:
    events = [
        gate("held", "h-000000000001", 3),  # open: closed now
        gate("held", "h-000000000002", 4),
        gate("approved", "h-000000000002", 3),  # approved: closed already
        gate("held", "h-000000000003", 5),
        gate("rejected", "h-000000000003", 4),
        gate("held", "h-000000000004", 6),
        gate("expired", "h-000000000004", 1),
        gate("held", "h-000000000005", 14),  # open, an older one
        gate("held", "h-000000000006", 20),  # past the window: not looked at
        gate("flood", "", 2),
    ]
    assert stale_holds(events, now=START) == ["h-000000000005", "h-000000000001"]


@pytest.mark.parametrize("bad", ["", "nope", "h-XYZ"])
def test_a_restart_ignores_what_is_not_a_hold_id(bad: str) -> None:
    assert stale_holds([gate("held", bad, 1)], now=START) == []


DRAFT = ("gmail", "0123456789abcdef", "r-42")


def test_a_draft_is_open_while_its_sending_is_held_approved_or_preapproved() -> None:
    """T10-3 (decision 12): while the send of a saved draft is held, being released or
    preapproved, a change to that draft must be held too."""
    book, clock = make()
    assert not book.draft_open(DRAFT)
    hold = book.open(FP, risk=2, reason="unknown", event=EVENT, draft=DRAFT)
    assert hold is not None
    book.recorded(hold, 10)
    assert book.draft_open(DRAFT)
    assert not book.draft_open(("gmail", "0123456789abcdef", "r-43"))
    assert not book.draft_open(("graph_mail", "0123456789abcdef", "r-42"))
    book.preapprove(hold)  # nobody waited: preapproved
    assert book.draft_open(DRAFT)
    clock.now += 601  # the preapproval lapsed
    assert not book.draft_open(DRAFT)


def test_a_rejected_or_spent_draft_hold_no_longer_counts() -> None:
    book, _ = make()
    hold = book.open(FP, risk=2, reason="unknown", event=EVENT, draft=DRAFT)
    assert hold is not None
    book.recorded(hold, 10)
    book.reject(hold.hold_id)
    assert not book.draft_open(DRAFT)
    again = book.open(OTHER, risk=2, reason="unknown", event=EVENT, draft=DRAFT)
    assert again is not None
    book.recorded(again, 11)
    book.preapprove(again)
    assert book.spend(OTHER) is again and not book.draft_open(DRAFT)
