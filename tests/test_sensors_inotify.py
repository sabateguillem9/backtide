"""The inotify wrapper: the pure parser, the lazy libc and the safe way to open paths.

The real inotify (watches, queue, overflow) is Linux-only and is tested in the VM
(tests/integration/test_file_watcher.py)."""

import errno
import os
import struct
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from vigia.sensors import inotify
from vigia.sensors.inotify import (
    IN_CREATE,
    IN_ISDIR,
    IN_MODIFY,
    IN_Q_OVERFLOW,
    InotifyUnavailable,
    RawEvent,
    parse_events,
)


def pack(wd: int, mask: int, cookie: int = 0, name: bytes = b"", *, padded_to: int = 0) -> bytes:
    """One struct inotify_event as the kernel lays it out: the name is NUL padded."""
    length = max(padded_to, len(name) + 1 if name else 0)
    return struct.pack("=iIII", wd, mask, cookie, length) + name.ljust(length, b"\0")


class TestParseEvents:
    def test_empty_buffer_has_no_events(self) -> None:
        assert parse_events(b"") == []

    def test_several_events_in_one_buffer(self) -> None:
        buf = (
            pack(1, IN_CREATE, 0, b"notes.md")
            + pack(1, IN_MODIFY, 0, b"notes.md")
            + pack(2, IN_CREATE | IN_ISDIR, 7, b"sub")
        )
        assert parse_events(buf) == [
            RawEvent(1, IN_CREATE, 0, b"notes.md"),
            RawEvent(1, IN_MODIFY, 0, b"notes.md"),
            RawEvent(2, IN_CREATE | IN_ISDIR, 7, b"sub"),
        ]

    def test_name_padded_with_nuls_is_cut_at_the_first_one(self) -> None:
        events = parse_events(pack(3, IN_CREATE, 0, b"a", padded_to=16))
        assert events == [RawEvent(3, IN_CREATE, 0, b"a")]

    def test_zero_length_name_is_an_event_about_the_directory_itself(self) -> None:
        assert parse_events(pack(4, IN_MODIFY)) == [RawEvent(4, IN_MODIFY, 0, b"")]

    def test_overflow_has_wd_minus_one(self) -> None:
        assert parse_events(pack(-1, IN_Q_OVERFLOW)) == [RawEvent(-1, IN_Q_OVERFLOW, 0, b"")]

    def test_names_that_are_not_utf8_stay_bytes(self) -> None:
        events = parse_events(pack(1, IN_CREATE, 0, b"bad\xff\xfename"))
        assert events[0].name == b"bad\xff\xfename"

    def test_a_cut_header_is_an_error_not_a_silent_loss(self) -> None:
        with pytest.raises(ValueError, match="truncated"):
            parse_events(pack(1, IN_CREATE, 0, b"x")[:10])

    def test_a_cut_name_is_an_error_not_a_silent_loss(self) -> None:
        with pytest.raises(ValueError, match="truncated"):
            parse_events(pack(1, IN_CREATE, 0, b"long-name")[:-3])

    def test_good_events_before_a_cut_one_are_not_returned_half_way(self) -> None:
        buf = pack(1, IN_CREATE, 0, b"a") + pack(1, IN_CREATE, 0, b"b")[:-2]
        with pytest.raises(ValueError, match="truncated"):
            parse_events(buf)


class TestLazyLibc:
    def test_importing_never_loads_libc(self) -> None:
        # The module is imported by the whole test suite on macOS: that is the proof.
        assert inotify.IN_CREATE == 0x100

    def test_a_clear_error_where_inotify_does_not_exist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        inotify._libc.cache_clear()
        try:
            with pytest.raises(InotifyUnavailable, match="needs Linux"):
                inotify.Inotify()
        finally:
            inotify._libc.cache_clear()

    def test_unavailable_is_an_oserror_with_a_message(self) -> None:
        assert issubclass(InotifyUnavailable, OSError)


class TestMaxUserWatches:
    def test_falls_back_to_the_default_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(inotify, "_MAX_USER_WATCHES_FILE", "/nonexistent/max_user_watches")
        with caplog.at_level("WARNING", logger=inotify.logger.name):
            assert inotify.max_user_watches() == inotify.DEFAULT_MAX_USER_WATCHES
        assert "cannot read" in caplog.text

    def test_reads_the_sysctl(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        sysctl = tmp_path / "max_user_watches"
        sysctl.write_text("65536\n")
        monkeypatch.setattr(inotify, "_MAX_USER_WATCHES_FILE", str(sysctl))
        assert inotify.max_user_watches() == 65536


@pytest.fixture
def root(tmp_path: Path) -> Iterator[int]:
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f.txt").write_text("x")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret").write_text("s")
    base = tmp_path / "base"
    base.mkdir()
    (base / "dir").mkdir()
    (base / "dir" / "file").write_text("y")
    (base / "to_outside").symlink_to(tmp_path / "outside")
    (base / "dir" / "up").symlink_to("../..")
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    yield fd
    os.close(fd)


class TestOpenBeneath:
    """The walking fallback is what runs on macOS; on Linux the VM tests use openat2."""

    flags = os.O_RDONLY

    def test_opens_a_file_below(self, root: int) -> None:
        fd = inotify.open_beneath(root, b"dir/file", self.flags)
        try:
            assert os.read(fd, 10) == b"y"
        finally:
            os.close(fd)

    def test_dot_and_empty_are_the_directory_itself(self, root: int) -> None:
        for rel in (b".", b""):
            fd = inotify.open_beneath(root, rel, self.flags | os.O_DIRECTORY)
            try:
                assert os.fstat(fd).st_ino == os.fstat(root).st_ino
            finally:
                os.close(fd)

    def test_a_symlink_in_the_last_component_is_refused(self, root: int) -> None:
        with pytest.raises(OSError):  # ELOOP (or ENOTDIR with O_DIRECTORY)
            inotify.open_beneath(root, b"to_outside", self.flags | os.O_DIRECTORY)

    def test_a_symlink_in_the_middle_is_refused(self, root: int) -> None:
        with pytest.raises(OSError):
            inotify.open_beneath(root, b"to_outside/secret", self.flags)
        with pytest.raises(OSError):
            inotify.open_beneath(root, b"dir/up/outside/secret", self.flags)

    def test_dotdot_and_absolute_paths_are_refused(self, root: int) -> None:
        for rel in (b"../outside/secret", b"dir/../../outside/secret", b"/etc/passwd"):
            with pytest.raises(OSError) as raised:
                inotify.open_beneath(root, rel, self.flags)
            assert raised.value.errno in (errno.EXDEV, errno.ELOOP)

    def test_a_missing_file_is_file_not_found(self, root: int) -> None:
        with pytest.raises(FileNotFoundError):
            inotify.open_beneath(root, b"dir/nope", self.flags)

    def test_a_nul_byte_is_a_value_error(self, root: int) -> None:
        with pytest.raises(ValueError, match="NUL"):
            inotify.open_beneath(root, b"dir/fi\0le", self.flags)

    def test_no_descriptor_is_leaked_on_failure(self, root: int) -> None:
        before = len(os.listdir("/dev/fd"))
        for _ in range(20):
            with pytest.raises(OSError):
                inotify.open_beneath(root, b"dir/up/outside/secret", self.flags)
        assert len(os.listdir("/dev/fd")) == before


# A mount point under "/" on each system: crossing it must be refused (finding 8).
MOUNT_UNDER_ROOT = b"dev" if sys.platform == "darwin" else b"proc"


class TestOpenBeneathHardening:
    """The security review of T04a: the fallback, the openat2 probe and PATH_MAX."""

    flags = os.O_RDONLY

    def test_the_fallback_never_crosses_into_another_filesystem(self) -> None:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for rel in (MOUNT_UNDER_ROOT, MOUNT_UNDER_ROOT + b"/null"):
                with pytest.raises(OSError) as raised:
                    inotify._open_walking(fd, rel, self.flags | os.O_DIRECTORY)
                assert raised.value.errno == errno.EXDEV, rel
        finally:
            os.close(fd)

    def test_dotdot_is_refused_even_when_it_would_stay_below(self, root: int) -> None:
        with pytest.raises(OSError) as raised:
            inotify.open_beneath(root, b"dir/../dir/file", self.flags)
        assert raised.value.errno == errno.EXDEV

    def test_a_path_is_cut_into_pieces_below_path_max(self) -> None:
        parts = [bytes([65 + i % 26]) * 255 for i in range(40)]
        rel = b"/".join(parts)
        chunks = inotify._chunks(rel)
        assert len(chunks) > 1 and all(len(c) <= inotify.CHUNK_BYTES for c in chunks)
        assert b"/".join(chunks) == rel
        assert inotify._chunks(b"a/b") == [b"a/b"]

    def test_a_blocked_openat2_falls_back_and_warns_only_once(
        self, root: int, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Under a seccomp filter openat2 can fail with EPERM instead of ENOSYS."""

        def blocked(fd: int, rel: bytes, flags: int) -> int:
            raise OSError(errno.EPERM, "Operation not permitted", rel)

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(inotify, "_openat2", blocked)
        inotify._openat2_usable.cache_clear()
        try:
            with caplog.at_level("WARNING", logger=inotify.logger.name):
                for _ in range(3):
                    os.close(inotify.open_beneath(root, b"dir/file", self.flags))
        finally:
            inotify._openat2_usable.cache_clear()
        assert caplog.text.count("openat2") == 1

    def test_eperm_on_a_real_call_is_an_error_not_a_fallback(
        self, root: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def picky(fd: int, rel: bytes, flags: int) -> int:
            if rel == b".":  # the probe works: openat2 exists
                return os.dup(fd)
            raise OSError(errno.EPERM, "Operation not permitted", rel)

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(inotify, "_openat2", picky)
        inotify._openat2_usable.cache_clear()
        try:
            with pytest.raises(PermissionError):
                inotify.open_beneath(root, b"dir/file", self.flags)
        finally:
            inotify._openat2_usable.cache_clear()
