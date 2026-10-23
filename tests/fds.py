"""Counting open descriptors in a test without being fooled by other tests.

A plain count of /dev/fd moves when the garbage collector closes a socket or a database that an
earlier test left behind, halfway through a measurement (it failed CI that way). So: collect
first, and compare sets: a leak is a descriptor that is open after and was not before.
"""

import gc
import os
from pathlib import Path


def open_fds() -> set[int]:
    """The descriptors open right now, after a garbage collection. Listing a directory opens one
    of its own, which is gone by the time the list is returned: drop whatever no longer
    answers."""
    gc.collect()
    found = set()
    for name in os.listdir("/dev/fd"):
        try:
            os.fstat(int(name))
        except OSError:
            continue
        found.add(int(name))
    return found


def open_fds_on(*paths: os.PathLike[str] | str) -> set[int]:
    """The open descriptors that point at one of ``paths``. Another test's thread can open
    descriptors while one is measured (CI saw two appear that way); counting only the files the
    code under test opens cannot be fooled by that."""
    wanted = set()
    for path in paths:
        info = os.stat(path, follow_symlinks=False)
        wanted.add((info.st_dev, info.st_ino))
    found = set()
    for fd in open_fds():
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) in wanted:
            found.add(fd)
    return found


def tree(root: os.PathLike[str] | str) -> list[Path]:
    """``root`` and everything below it, symlinks included and not followed: what the code under
    test can open there, for ``open_fds_on``."""
    found = [Path(root)]
    for folder, dirs, files in os.walk(root):  # never into a symlinked directory
        found += [Path(folder, name) for name in (*dirs, *files)]
    return found


def identity(fd: int) -> tuple[int, int]:
    """What ``fd`` is open on, (st_dev, st_ino): unlike its number, not handed to the next
    thread that opens something."""
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def still_open(fd: int, was: tuple[int, int]) -> bool:
    """Whether ``fd`` is still open on the object whose ``identity`` was ``was``. That the number
    answers proves nothing: another test's thread can get it the moment it is closed (CI saw
    it). A pipe has no path for ``open_fds_on``; this is how to follow one. (macOS reuses a
    closed pipe's identity, so a false "still open" needs that AND the same number taken by
    another pipe; on Linux a pipe's identity is never reused.)"""
    try:
        return identity(fd) == was
    except OSError:
        return False
