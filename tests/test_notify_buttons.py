"""The server-side book of the bot's buttons and the rate limit (T09)."""

from backtide.notify.buttons import Action, Button, ButtonBook, RateLimit, Refused


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_a_bound_button_acts_on_its_own_message_only() -> None:
    book = ButtonBook()
    token = book.issue(Action.NOTICE, snapshot_id="s1")
    assert book.take(token, 7) is Refused.WRONG_MESSAGE  # not bound yet
    book.bind([token], 7)
    assert book.take(token, 8) is Refused.WRONG_MESSAGE  # copied onto another message
    button = book.take(token, 7)
    assert isinstance(button, Button)
    assert (button.action, button.snapshot_id) == (Action.NOTICE, "s1")
    assert isinstance(book.take(token, 7), Button)  # not single use: shows the notice again


def test_forged_data_is_an_unknown_button() -> None:
    book = ButtonBook()
    book.bind([book.issue(Action.PAUSE)], 1)
    for forged in ("confirm:20261016T120000.000000Z-manual", "", None, 3, "x" * 64):
        assert book.take(forged, 1) is Refused.UNKNOWN
    assert book.take(book.issue(Action.PAUSE), "1") is Refused.UNKNOWN  # not an int id


def test_a_confirmation_is_single_use_together_with_its_cancel() -> None:
    book = ButtonBook()
    cancel = book.issue(Action.CANCEL, single_use=True)
    confirm = book.issue(Action.CONFIRM, snapshot_id="s1", single_use=True, group=cancel)
    book.bind([confirm, cancel], 5)
    assert isinstance(book.take(confirm, 5), Button)
    assert book.take(confirm, 5) is Refused.USED  # a replay
    assert book.take(cancel, 5) is Refused.USED  # and its sibling with it


def test_buttons_expire() -> None:
    clock = Clock()
    book = ButtonBook(clock=clock)
    token = book.issue(Action.CONFIRM, snapshot_id="s1", ttl=120.0, single_use=True)
    book.bind([token], 1)
    clock.now += 120.0
    assert book.take(token, 1) is Refused.EXPIRED


def test_tokens_are_random_and_short_enough_for_telegram() -> None:
    book = ButtonBook()
    tokens = {book.issue(Action.PAUSE) for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(token.encode()) <= 64 for token in tokens)  # callback_data's limit


def test_the_book_is_bounded_and_drops_expired_then_oldest() -> None:
    clock = Clock()
    book = ButtonBook(clock=clock, capacity=3)
    old = book.issue(Action.PAUSE, ttl=1.0)
    keep = [book.issue(Action.PAUSE) for _ in range(2)]
    clock.now += 2.0
    new = book.issue(Action.PAUSE)  # the expired one makes room
    assert len(book) == 3
    for token in [*keep, new]:
        book.bind([token], 1)
    assert book.take(old, 1) is Refused.UNKNOWN
    for _ in range(5):
        book.issue(Action.PAUSE)
    assert len(book) == 3


def test_forget_removes_the_buttons_of_a_message_that_was_not_sent() -> None:
    book = ButtonBook()
    token = book.issue(Action.PAUSE)
    book.forget([token])
    book.bind([token], 1)
    assert book.take(token, 1) is Refused.UNKNOWN


def test_the_rate_limit_allows_a_burst_then_one_per_interval() -> None:
    clock = Clock()
    limit = RateLimit(3, 2.0, clock=clock)
    assert [limit.allow() for _ in range(4)] == [True, True, True, False]
    clock.now += 2.0
    assert limit.allow() and not limit.allow()
    clock.now += 100.0
    assert sum(limit.allow() for _ in range(10)) == 3  # never more than the burst
