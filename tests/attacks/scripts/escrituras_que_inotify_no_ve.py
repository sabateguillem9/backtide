"""Evil agent: writes that the file watcher (inotify) does not see, or sees under the wrong name.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> prepare|attack <dir>.
``prepare`` makes the four target files with known content; ``attack`` changes each in a way
inotify misses or misattributes:
  mmap      a write through a shared mapping of a file that is NEVER closed (a daemon keeps it
            mapped and open): no IN_CLOSE_WRITE, and IN_MODIFY is not guaranteed for a mapping;
  hardlink  a write through a second name in ANOTHER directory: inotify reports it there, under
            that name, and says nothing in the folder of the original;
  fallocate the size of a file grows without a single write();
  xattr     an extended attribute set on a file.
Prints one JSON object on its last line.
"""

import json
import mmap
import os
import sys
import time

mode, base = sys.argv[1], sys.argv[2]
ORIGINAL = b"original" * 512  # 4096 bytes
FILES = {
    "mmap": os.path.join(base, "a", "mm.bin"),
    "hardlink": os.path.join(base, "a", "hl.bin"),
    "fallocate": os.path.join(base, "fa.bin"),
    "xattr": os.path.join(base, "xa.bin"),
}
LINK = os.path.join(base, "b", "hl-link.bin")


def prepare() -> dict:
    os.makedirs(os.path.join(base, "a"), exist_ok=True)
    os.makedirs(os.path.join(base, "b"), exist_ok=True)
    for path in FILES.values():
        with open(path, "wb") as handle:
            handle.write(ORIGINAL)
    return {"prepared": sorted(FILES)}


def hold_a_mapping_open() -> int:
    """Fork a daemon that maps the file, writes through the map and never closes anything."""
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:  # the daemon
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        for stream in (0, 1, 2):
            os.dup2(devnull, stream)
        handle = open(FILES["mmap"], "r+b")  # noqa: SIM115 - deliberately never closed
        mapped = mmap.mmap(handle.fileno(), 4096)
        mapped[0:8] = b"MMAPPED!"
        mapped.flush()  # to the disk, but still mapped and open
        os.write(ready_write, b"1")
        time.sleep(600)
        os._exit(0)
    os.close(ready_write)
    os.read(ready_read, 1)
    return pid


def attack() -> dict:
    done: dict = {}
    errors: dict = {}
    for name in ("mmap", "hardlink", "fallocate", "xattr"):
        try:
            if name == "mmap":
                done["mmap_daemon_pid"] = hold_a_mapping_open()
            elif name == "hardlink":
                try:
                    os.link(FILES["hardlink"], LINK)
                except FileExistsError:
                    pass
                with open(LINK, "r+b") as handle:
                    handle.write(b"HARDLINK")
                done["nlink"] = os.stat(LINK).st_nlink
            elif name == "fallocate":
                descriptor = os.open(FILES["fallocate"], os.O_RDWR)
                try:
                    os.posix_fallocate(descriptor, 0, 65536)
                finally:
                    os.close(descriptor)
            else:
                os.setxattr(FILES["xattr"], "user.backtide-test", b"hidden")
            done[name] = True
        except OSError as error:
            done[name] = False
            errors[name] = f"{type(error).__name__}: {error}"
    return {"done": done, "errors": errors}


print(json.dumps(prepare() if mode == "prepare" else attack()))
