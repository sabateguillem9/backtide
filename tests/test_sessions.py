"""The web's sign-in (T26-3a, docs/47 section 5.2): a one-time link exchanged for a session that
dies after an hour unused or twelve in all, kept by the service, never by the web."""

import threading

import pytest

from backtide.service.sessions import (
    IDLE_SECONDS,
    LIFETIME_SECONDS,
    LINK_SECONDS,
    MAX_SESSIONS,
    MIN_SECONDS,
    TOUCH_SECONDS,
    Sessions,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def sessions(clock: Clock) -> Sessions:
    return Sessions(clock=clock)


def test_the_defaults_are_the_designs() -> None:
    assert (IDLE_SECONDS, LIFETIME_SECONDS, LINK_SECONDS) == (3600, 12 * 3600, 15 * 60)


def test_a_link_opens_one_session_once(sessions: Sessions) -> None:
    token = sessions.new_link()
    session = sessions.open(token)
    assert session is not None and len(session.id) >= 43 and len(session.csrf) >= 43
    assert session.id not in (token, session.csrf)
    assert sessions.open(token) is None  # dead after one use
    assert sessions.check(session.id) == session


def test_a_new_link_kills_the_unspent_one(sessions: Sessions) -> None:
    first = sessions.new_link()
    second = sessions.new_link()
    assert sessions.open(first) is None
    assert sessions.open(second) is not None


def test_a_link_dies_after_fifteen_minutes(sessions: Sessions, clock: Clock) -> None:
    token = sessions.new_link()
    clock.now += LINK_SECONDS
    assert sessions.open(token) is None


@pytest.mark.parametrize("given", [None, "", "x", "a" * 43, "a" * 5000])
def test_a_wrong_token_or_session_opens_nothing(sessions: Sessions, given: str | None) -> None:
    sessions.new_link()
    assert sessions.open(given) is None
    assert sessions.check(given) is None
    assert sessions.end(given) is False


def test_every_entry_is_a_new_session(sessions: Sessions) -> None:
    """Never the id there was before signing in (session fixation)."""
    ids = set()
    for _ in range(5):
        session = sessions.open(sessions.new_link())
        assert session is not None
        ids.add(session.id)
    assert len(ids) == 5


def test_a_session_dies_after_an_hour_unused(sessions: Sessions, clock: Clock) -> None:
    session = sessions.open(sessions.new_link())
    assert session is not None
    clock.now += IDLE_SECONDS - 1
    assert sessions.check(session.id) == session  # a use: the hour starts again
    clock.now += IDLE_SECONDS - 1
    assert sessions.check(session.id) == session
    clock.now += IDLE_SECONDS
    assert sessions.check(session.id) is None
    clock.now -= IDLE_SECONDS  # dead stays dead, even if the clock goes back
    assert sessions.check(session.id) is None


def test_a_session_dies_after_twelve_hours_even_in_use(sessions: Sessions, clock: Clock) -> None:
    session = sessions.open(sessions.new_link())
    assert session is not None
    for _ in range(12 * 4 - 1):
        clock.now += 15 * 60
        assert sessions.check(session.id) == session
    clock.now += 15 * 60
    assert sessions.check(session.id) is None


def test_several_sessions_at_once_and_ending_one(sessions: Sessions) -> None:
    laptop = sessions.open(sessions.new_link())
    phone = sessions.open(sessions.new_link())
    assert laptop is not None and phone is not None and laptop.csrf != phone.csrf
    assert sessions.end(laptop.id) is True
    assert sessions.check(laptop.id) is None
    assert sessions.check(phone.id) == phone
    assert sessions.end(laptop.id) is False


def test_ending_all(sessions: Sessions) -> None:
    opened = [sessions.open(sessions.new_link()) for _ in range(3)]
    unspent = sessions.new_link()
    assert sessions.end_all() == 3
    assert all(s is not None and sessions.check(s.id) is None for s in opened)
    assert sessions.open(unspent) is None  # the link waiting too: "close all" closes all


def test_past_the_cap_the_least_recently_used_goes(sessions: Sessions, clock: Clock) -> None:
    opened = []
    for _ in range(MAX_SESSIONS):
        clock.now += 1
        session = sessions.open(sessions.new_link())
        assert session is not None
        opened.append(session)
    clock.now += 1
    assert sessions.check(opened[0].id) is not None  # the oldest is used again
    newest = sessions.open(sessions.new_link())
    assert newest is not None
    assert sessions.check(opened[1].id) is None  # the least recently used went
    assert sessions.check(opened[0].id) is not None
    assert len(sessions) == MAX_SESSIONS


def test_the_dead_are_forgotten(sessions: Sessions, clock: Clock) -> None:
    for _ in range(3):
        sessions.open(sessions.new_link())
    clock.now += IDLE_SECONDS
    sessions.check("x")
    assert len(sessions) == 0


def test_a_preset_session_for_the_demo_and_the_tests(sessions: Sessions, clock: Clock) -> None:
    session = sessions.preset("s" * 43)
    assert sessions.check("s" * 43) == session
    clock.now += IDLE_SECONDS
    assert sessions.check("s" * 43) is None


def test_the_secrets_are_not_kept(sessions: Sessions) -> None:
    """Only a digest of each: a dump of the service's memory structures shows no live id."""
    token = sessions.new_link()
    session = sessions.open(sessions.new_link())
    assert session is not None
    kept = repr(vars(sessions))
    assert token not in kept and session.id not in kept


@pytest.mark.parametrize(
    "options",
    [
        {"idle": MIN_SECONDS - 1},
        {"idle": IDLE_SECONDS + 1},
        {"lifetime": LIFETIME_SECONDS + 1},
        {"idle": 600, "lifetime": 300},
        {"link_seconds": LINK_SECONDS + 1},
        {"link_seconds": 0},
        {"max_sessions": 0},
    ],
)
def test_the_limits_can_only_be_shortened(options: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        Sessions(**options)


def test_shortened_limits_for_a_test(clock: Clock) -> None:
    sessions = Sessions(idle=MIN_SECONDS, lifetime=2 * MIN_SECONDS, clock=clock)
    session = sessions.open(sessions.new_link())
    assert session is not None
    clock.now += MIN_SECONDS
    assert sessions.check(session.id) is None


def test_one_link_one_session_whoever_races(sessions: Sessions) -> None:
    token = sessions.new_link()
    won: list[object] = []
    start = threading.Barrier(8)

    def go() -> None:
        start.wait()
        session = sessions.open(token)
        if session is not None:
            won.append(session)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(won) == 1


def test_a_check_without_use_does_not_keep_a_session_alive(
    sessions: Sessions, clock: Clock
) -> None:
    """A page's own stream reconnects by itself: a tab left open is not a use."""
    session = sessions.open(sessions.new_link())
    assert session is not None
    for _ in range(5):
        clock.now += IDLE_SECONDS / 5 - 1
        assert sessions.check(session.id, use=False) == session
    clock.now += 10
    assert sessions.check(session.id, use=False) is None


def test_a_given_link_token_must_look_like_one() -> None:
    with pytest.raises(ValueError):
        Sessions().new_link("é" * 10)


# -- touching the key again (T26-3c) ----------------------------------------------------------


def test_a_session_remembers_its_touch_for_a_while() -> None:
    clock = Clock()
    sessions = Sessions(clock=clock)
    session = sessions.start()
    assert not sessions.recently_touched(session.id)
    assert sessions.touch(session.id)
    clock.now += TOUCH_SECONDS - 1
    assert sessions.recently_touched(session.id)
    clock.now += 1
    assert not sessions.recently_touched(session.id)


def test_entering_with_a_key_counts_as_a_touch_and_the_others_do_not() -> None:
    sessions = Sessions()
    assert sessions.recently_touched(sessions.start(touched=True).id)
    assert not sessions.recently_touched(sessions.start().id)
    assert not sessions.recently_touched(sessions.open(sessions.new_link()).id)


def test_a_touch_is_of_one_session_and_of_a_live_one() -> None:
    clock = Clock()
    sessions = Sessions(clock=clock)
    one, other = sessions.start(), sessions.start()
    sessions.touch(one.id)
    assert not sessions.recently_touched(other.id)
    assert not sessions.touch("x" * 43) and not sessions.recently_touched("x" * 43)
    sessions.end(one.id)
    assert not sessions.recently_touched(one.id) and not sessions.touch(one.id)


def test_recently_opened_is_for_the_first_key() -> None:
    clock = Clock()
    sessions = Sessions(clock=clock)
    session = sessions.start()
    assert sessions.recently_opened(session.id)
    clock.now += TOUCH_SECONDS
    assert not sessions.recently_opened(session.id)
    assert not sessions.recently_opened("x" * 43)
