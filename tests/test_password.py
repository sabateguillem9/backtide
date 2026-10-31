"""The web's password (T26-3b-1, D40): only a scrypt hash is kept, guessing is slow and then
stops, and nothing ever quotes it."""

import os
import stat
from pathlib import Path

import pytest

from backtide.service import password as pw
from backtide.service.password import (
    LOCK_AFTER,
    LOCK_SECONDS,
    Checker,
    PasswordError,
    Verdict,
)

GOOD = "correct horse battery staple"  # noqa: S105 - a test value


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def state(tmp_path: Path) -> Path:
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    return folder


def test_only_a_hash_is_kept_root_only(state: Path) -> None:
    pw.write(state, GOOD)
    path = pw.path_of(state)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    text = path.read_text()
    assert GOOD not in text and "horse" not in text
    assert text.startswith("scrypt$32768$8$1$")
    assert pw.matches(GOOD, text) and not pw.matches(GOOD + "!", text)


def test_two_hashes_of_the_same_password_differ(state: Path) -> None:
    assert pw.hash_password(GOOD) != pw.hash_password(GOOD)  # a salt each


@pytest.mark.parametrize(
    "bad", ["", "short", "x" * 11, "x" * 257, " " * 20, "tab\there-and-more", 12345678901234, None]
)
def test_a_password_that_cannot_be_one_is_refused_unquoted(state: Path, bad: object) -> None:
    assert pw.problem(bad) is not None
    with pytest.raises(PasswordError) as caught:
        pw.write(state, bad)  # type: ignore[arg-type]
    if isinstance(bad, str) and len(bad) > 3:
        assert bad not in str(caught.value)
    assert not pw.path_of(state).exists()


@pytest.mark.parametrize(
    "line",
    [
        "",
        "plain",
        "bcrypt$1$2$3$aa$bb",
        "scrypt$2$1$1$AAAA$AAAA",  # cheap parameters: never accepted from a file
        "scrypt$1048576$8$1$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 44,  # huge ones neither
        "scrypt$32768$8$1$!!!$AAAA",
    ],
)
def test_an_odd_line_matches_nothing(line: str) -> None:
    assert pw.matches(GOOD, line) is False


def test_a_file_that_is_not_ours_is_not_used(state: Path, tmp_path: Path) -> None:
    pw.write(state, GOOD)
    path = pw.path_of(state)
    path.chmod(0o644)
    with pytest.raises(PasswordError, match="no es el archivo"):
        pw.read(state)
    path.unlink()
    elsewhere = tmp_path / "other"
    elsewhere.write_text(pw.hash_password(GOOD))
    path.symlink_to(elsewhere)
    with pytest.raises(PasswordError):
        pw.read(state)


def test_without_a_password_nothing_matches(state: Path) -> None:
    assert pw.read(state) is None
    assert Checker(state).check(GOOD) is Verdict.UNSET


def test_the_checker_says_right_and_wrong(state: Path) -> None:
    pw.write(state, GOOD)
    checker = Checker(state, clock=Clock())
    assert checker.check(GOOD + "x") is Verdict.WRONG
    assert checker.check(GOOD) is Verdict.RIGHT
    assert checker.failures == 0  # a right one starts the count again


def test_guessing_is_slowed_for_the_whole_web(state: Path) -> None:
    pw.write(state, GOOD)
    clock = Clock()
    checker = Checker(state, clock=clock)
    verdicts = [checker.check("wrong-password-" + str(i)) for i in range(6)]
    assert verdicts == [Verdict.WRONG] * 5 + [Verdict.SLOW_DOWN]
    assert checker.check(GOOD) is Verdict.SLOW_DOWN  # not even checked
    clock.now += 12
    assert checker.check(GOOD) is Verdict.RIGHT


def test_after_many_failures_in_a_row_nothing_is_checked_for_a_while(state: Path) -> None:
    pw.write(state, GOOD)
    clock = Clock()
    checker = Checker(state, clock=clock)
    verdicts = []
    for i in range(LOCK_AFTER):
        clock.now += 12
        verdicts.append(checker.check(f"wrong-password-{i}"))
    assert verdicts[-1] is Verdict.LOCKING and set(verdicts[:-1]) == {Verdict.WRONG}
    clock.now += 12
    assert checker.check(GOOD) is Verdict.LOCKED  # the right one too
    clock.now += LOCK_SECONDS
    assert checker.check(GOOD) is Verdict.RIGHT


def test_setting_a_new_password_ends_a_lock(state: Path) -> None:
    pw.write(state, GOOD)
    clock = Clock()
    checker = Checker(state, clock=clock)
    for i in range(LOCK_AFTER):
        clock.now += 12
        checker.check(f"wrong-password-{i}")
    checker.set("another good password")
    clock.now += 12
    assert checker.check("another good password") is Verdict.RIGHT
    assert checker.check(GOOD) is Verdict.WRONG


@pytest.mark.parametrize(
    "bad",
    [
        " correct horse battery",  # spaces at the ends: the CLI strips them, the form does not
        "correct horse battery ",
        "correct horse battery",  # NBSP: the form refuses what is not printable
        "correct horse battery",
        "correct­horse battery",
        "correct\x85horse battery",
        "".join(chr(0x4E00 + i) for i in range(230)),  # too long once encoded for the form
        "aaaaaaaaaaaa",
        "abcabcabcabcabc",
        "123456789012",
        "zyxwvutsrqpo",  # a run backwards
        "qwertyuiopasdf",
        "Password1234",
    ],
)
def test_what_the_form_cannot_send_or_anyone_guesses_is_refused(bad: str) -> None:
    assert pw.problem(bad) is not None


def test_the_same_accent_written_two_ways_is_the_same_password(state: Path) -> None:
    composed, decomposed = "contraseña de montaña", "contraseña de montaña"
    assert composed != decomposed
    pw.write(state, composed)
    assert pw.matches(decomposed, pw.read(state) or "")


def test_tries_hashing_at_once_lock_once(state: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review of T26-3b-1: several tries hashing at once at the limit say the lock once."""
    import threading

    pw.write(state, GOOD)
    clock = Clock()
    checker = Checker(state, clock=clock)
    for i in range(LOCK_AFTER - 1):
        clock.now += 12
        checker.check(f"wrong-password-{i}")
    clock.now += 60  # a full bucket: five tries may hash at once
    started = threading.Barrier(5)
    real = pw.matches

    def slow_matches(password: object, line: str) -> bool:
        started.wait(timeout=10)  # every try is hashing before any finishes
        return real(password, line)

    monkeypatch.setattr(pw, "matches", slow_matches)
    verdicts: list[Verdict] = []
    threads = [
        threading.Thread(target=lambda i=i: verdicts.append(checker.check(f"wrong-try-{i}xx")))
        for i in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(verdicts) == sorted([Verdict.LOCKING] + [Verdict.LOCKED] * 4)


def test_a_right_one_that_finishes_after_the_lock_is_refused(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    pw.write(state, GOOD)
    clock = Clock()
    checker = Checker(state, clock=clock)
    for i in range(LOCK_AFTER - 1):
        clock.now += 12
        checker.check(f"wrong-password-{i}")
    clock.now += 60
    release = threading.Event()
    real = pw.matches

    def held(password: object, line: str) -> bool:
        if password == GOOD:
            release.wait(timeout=10)  # the right one is still hashing...
        return real(password, line)

    monkeypatch.setattr(pw, "matches", held)
    verdicts: list[Verdict] = []
    right = threading.Thread(target=lambda: verdicts.append(checker.check(GOOD)))
    right.start()
    assert checker.check("the one too many here") is Verdict.LOCKING  # ...when this one locks
    release.set()
    right.join()
    assert verdicts == [Verdict.LOCKED]


def test_a_password_folder_that_is_not_ours_is_said(state: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (state / "web-auth").symlink_to(elsewhere)
    with pytest.raises(PasswordError, match="no es una carpeta nuestra"):
        pw.write(state, GOOD)
    assert not (elsewhere / "password").exists()


def test_a_refusal_of_the_private_writer_is_a_password_error(
    state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backtide.service.settings import SettingsError

    def refuse(*args: object, **kwargs: object) -> None:
        raise SettingsError("the folder is open to others")

    monkeypatch.setattr(pw, "write_private", refuse)
    with pytest.raises(PasswordError, match="no se puede guardar"):
        pw.write(state, GOOD)


def test_a_rule_added_later_does_not_lock_out_a_kept_password() -> None:
    """A password the rules of today refuse still matches the hash kept for it before."""
    import base64
    import hashlib

    old = "aaaaaaaaaaaa"
    assert pw.problem(old) is not None
    salt = b"s" * 16
    digest = hashlib.scrypt(old.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=2**27, dklen=32)
    line = f"scrypt$32768$8$1${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"
    assert pw.matches(old, line)
