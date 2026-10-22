"""Counting open descriptors in a test without being fooled by other tests.

A plain count of /dev/fd moves when the garbage collector closes a socket or a database that an
earlier test left behind, halfway through a measurement (it failed CI that way). So: collect
first, and compare sets: a leak is a descriptor that is open after and was not before.
"""

import gc
import os


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
