"""The buttons of the Telegram bot (T09): what each one means lives HERE, not in Telegram.

A button's ``callback_data`` is only a random token (``secrets.token_urlsafe``, 144 bits). What
it does (pause, show the notice of a rewind to snapshot S, confirm that rewind, cancel) is in
this server-side book, with:

- an expiry: an alert's buttons live a day, the confirmation of a rewind two minutes;
- the message it was sent on: a press must come from that very message, so a button copied,
  forwarded or replayed onto another message does nothing;
- single use for the confirmation: the "Sí, rebobinar" and its "Cancelar" are one group, and
  pressing either uses both;
- a bounded size: the oldest entries go first, so a flood of alerts cannot grow it.

The held requests (T10-4, docs/32 section 11) have their buttons here too: "Aprobar",
"Rechazar", "Ver" and the batches, each bound to its ``hold_id`` and living as long as the hold.
When a hold ends (whoever ended it), ``retire_hold`` uses all of them up with a ``note`` that
says how ("aprobada", "caducada"...), so a late or replayed press answers that; ``peek`` reads a
button without using it. A batch's confirmation is a single-use pair like a rewind's.

The book is in memory: after a restart of the service every old button answers "caducado".
Forged data (anything that is not a token we issued) is just an unknown token. Thread-safe.
"""

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

ALERT_TTL = 24 * 3600.0
CONFIRM_TTL = 120.0
CAPACITY = 1024


class Action(StrEnum):
    PAUSE = "pause"
    NOTICE = "notice"  # show the fixed notice of a rewind and ask for confirmation
    CONFIRM = "confirm"  # rewind
    CANCEL = "cancel"
    # Held requests (T10-4)
    APPROVE = "approve"
    REJECT = "reject"
    VIEW = "view"  # the whole of what the black box keeps of it; never used up by a press
    BATCH = "batch"  # ask to confirm a batch of ``kind``
    BATCH_CONFIRM = "batch_confirm"
    BATCH_CANCEL = "batch_cancel"
    BATCH_END = "batch_end"  # revoke the batch rule ``rule_id`` (/lotes)


HOLD_ACTIONS = frozenset({Action.APPROVE, Action.REJECT, Action.VIEW, Action.BATCH,
                          Action.BATCH_CONFIRM, Action.BATCH_CANCEL, Action.BATCH_END})  # fmt: skip


class Refused(StrEnum):
    UNKNOWN = "unknown_button"  # never issued, or issued before a restart
    EXPIRED = "expired_button"
    USED = "used_button"
    WRONG_MESSAGE = "wrong_message"  # pressed on a message it was not sent on


@dataclass
class Button:
    action: Action
    snapshot_id: str | None
    expires: float
    single_use: bool
    group: str
    message_id: int | None = None
    used: bool = False
    hold_id: str | None = None  # a held request's button (T10-4)
    kind: str | None = None  # a batch's kind
    rule_id: str | None = None  # a batch rule's id (/lotes)
    note: str | None = None  # how its hold ended, once ``retire_hold`` used it up


class ButtonBook:
    def __init__(
        self, *, clock: Callable[[], float] = time.monotonic, capacity: int = CAPACITY
    ) -> None:
        self._clock = clock
        self._capacity = capacity
        self._buttons: OrderedDict[str, Button] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buttons)

    def issue(
        self,
        action: Action,
        *,
        snapshot_id: str | None = None,
        ttl: float = ALERT_TTL,
        single_use: bool = False,
        group: str | None = None,
        hold_id: str | None = None,
        kind: str | None = None,
        rule_id: str | None = None,
    ) -> str:
        """A new token for ``action``. Buttons of one ``group`` are used up together."""
        token = secrets.token_urlsafe(18)
        with self._lock:
            self._make_room()
            self._buttons[token] = Button(
                action, snapshot_id, self._clock() + ttl, single_use, group or token,
                hold_id=hold_id, kind=kind, rule_id=rule_id,
            )  # fmt: skip
        return token

    def peek(self, token: object) -> Button | None:
        """The button behind ``token``, without using it (to say why a press was refused)."""
        if not isinstance(token, str):
            return None
        with self._lock:
            return self._buttons.get(token)

    def retire_hold(self, hold_id: str, note: str) -> None:
        """The hold ``hold_id`` ended: every button of it is used up, saying ``note``."""
        with self._lock:
            for button in self._buttons.values():
                if button.hold_id == hold_id and not button.used:
                    button.used = True
                    button.note = note

    def bind(self, tokens: list[str], message_id: int) -> None:
        """The message the buttons ``tokens`` were sent on: only a press there counts."""
        with self._lock:
            for token in tokens:
                button = self._buttons.get(token)
                if button is not None and button.message_id is None:
                    button.message_id = message_id

    def forget(self, tokens: list[str]) -> None:
        """The message could not be sent: its buttons never existed."""
        with self._lock:
            for token in tokens:
                self._buttons.pop(token, None)

    def take(self, token: object, message_id: object) -> Button | Refused:
        """The button behind ``token`` pressed on ``message_id``, if it may act now. A
        single-use one (and its whole group) is used up by this call."""
        if not isinstance(token, str) or not isinstance(message_id, int):
            return Refused.UNKNOWN
        with self._lock:
            button = self._buttons.get(token)
            if button is None:
                return Refused.UNKNOWN
            if button.message_id is None or button.message_id != message_id:
                return Refused.WRONG_MESSAGE
            if button.used:
                return Refused.USED
            if self._clock() >= button.expires:
                return Refused.EXPIRED
            if button.single_use:
                for other in self._buttons.values():
                    if other.group == button.group:
                        other.used = True
            return button

    def _make_room(self) -> None:
        now = self._clock()
        if len(self._buttons) < self._capacity:
            return
        for token in [t for t, b in self._buttons.items() if now >= b.expires]:
            del self._buttons[token]
        while len(self._buttons) >= self._capacity:
            self._buttons.popitem(last=False)


class RateLimit:
    """A token bucket: ``burst`` at once, then one every ``every`` seconds. Thread-safe."""

    def __init__(
        self, burst: int, every: float, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._burst = float(burst)
        self._every = every
        self._clock = clock
        self._tokens = float(burst)
        self._last = clock()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            self._tokens = min(self._burst, self._tokens + (now - self._last) / self._every)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False
