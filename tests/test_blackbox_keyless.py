"""A reader that never holds the key: the web (T12) shows the black box without the HMAC key, so a
compromised page could never forge or verify anything, and it does not need root to run."""

from pathlib import Path

import pytest

from tests.webkit import KEY, new_box
from vigia.blackbox import BlackBox, BlackBoxError


def test_a_keyless_reader_lists_events_and_the_head(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("file", "create", "a.txt", risk=2)
    box.append("system", "agent_start", "")
    with BlackBox(tmp_path / "blackbox.db", None, readonly=True) as reader:
        assert [e.seq for e in reader.events(min_risk=2)] == [1]
        assert [e.action for e in reader.events(newest_first=True)] == ["agent_start", "create"]
        head = reader.head()
        assert head is not None and head[0] == 2


def test_a_keyless_reader_can_neither_append_nor_verify(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a.txt")
    with BlackBox(tmp_path / "blackbox.db", None, readonly=True) as reader:
        with pytest.raises(BlackBoxError):
            reader.append("file", "create", "b.txt")
        with pytest.raises(BlackBoxError, match="key"):
            reader.verify()


def test_only_a_read_only_box_may_go_without_a_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="key"):
        BlackBox(tmp_path / "blackbox.db", None)


def test_a_keyless_reader_never_touches_the_database(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("file", "create", "a.txt")
    before = (tmp_path / "blackbox.db").stat().st_mtime_ns
    with BlackBox(tmp_path / "blackbox.db", None, readonly=True) as reader:
        reader.events()
    assert (tmp_path / "blackbox.db").stat().st_mtime_ns == before


def test_with_a_key_a_read_only_box_still_verifies(tmp_path: Path) -> None:
    new_box(tmp_path).append("file", "create", "a.txt")
    with BlackBox(
        tmp_path / "blackbox.db",
        KEY,
        checkpoint_path=tmp_path / "blackbox.checkpoint",
        readonly=True,
    ) as reader:
        assert reader.verify().ok
