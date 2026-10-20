"""The process sensor's list of secrets to strike, which Settings can change while it runs.
Every key is made up by the test."""

import pickle
import secrets

import pytest

from backtide.blackbox.redact import REDACTED
from backtide.sensors.scrub import LiveScrub


def key() -> str:
    return "sk-ant-api03-TEST" + secrets.token_urlsafe(40)


def test_it_strikes_what_it_was_given_and_leaves_the_rest() -> None:
    old = key()
    scrub = LiveScrub([old])
    assert old not in scrub.text(f"curl -H 'x-api-key: {old}' https://x.test")
    assert scrub.text("ls -la /work") == "ls -la /work"


def test_replace_adds_the_new_key_and_drops_the_removed_one() -> None:
    old, new, other = key(), key(), key()
    scrub = LiveScrub([old, other])
    assert scrub.text(f"echo {new}") == f"echo {new}", "not known yet"
    scrub.replace([new, other])
    assert new not in scrub.text(f"echo {new}")
    assert old in scrub.text(f"echo {old}"), "the removed key is no longer in the list"
    assert other not in scrub.text(f"echo {other}"), "the one that stayed is still struck"


def test_replace_with_nothing_strikes_nothing() -> None:
    scrub = LiveScrub([key()])
    scrub.replace([])
    assert scrub.text("echo hello") == "echo hello"


def test_a_bad_replace_changes_nothing() -> None:
    old = key()
    scrub = LiveScrub([old])
    with pytest.raises(ValueError, match="known secret"):
        scrub.replace([key(), "short"])
    assert scrub.text(old) == REDACTED


def test_it_cuts_tails_like_the_sensor_needs() -> None:
    """Tetragon cuts long arguments, maybe in the middle of a secret."""
    value = key()
    scrub = LiveScrub([value])
    assert value[:20] not in scrub.text("run " + value[:30])


def test_it_never_says_what_it_holds() -> None:
    value = key()
    scrub = LiveScrub([value])
    assert value not in repr(scrub) and "1 secrets" in repr(scrub)
    with pytest.raises((TypeError, ValueError)) as error:
        scrub.replace(["x" * 3])
    assert "xxx" not in str(error.value)
    with pytest.raises(TypeError):
        pickle.dumps(scrub)
