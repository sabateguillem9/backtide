"""Evil agent: read the volume's usage, its caps and the host path of its image from /sys.

Runs INSIDE a container, as its user (python3 -c). Usage: <script> <fsid> <host image path>...
``/sys/fs/btrfs/<fsid>`` shows the usage and the caps of the volume (and when snapshots
appear); a loop device's ``backing_file`` is the host path of the image file. The script
looks for both in every way it can think of, tries to write in what hides them and to take
the hiding away, and prints one JSON object on its last line:

  listed   what it can list in the two folders that backtide hides
  found    paths that gave away the volume: its fsid folder, a ``backing_file`` it could
           read, or any file in /sys that holds the host path of the image
  writes   errno of each attempt to create something in the hidden folders
  umounts  errno of each attempt to remove the hiding (umount2 of the two folders)
"""

import ctypes
import json
import os
import sys

fsid, images = sys.argv[1], [p.encode() for p in sys.argv[2:]]
HIDDEN = ("/sys/fs/btrfs", "/sys/devices/virtual/block")


def listing(path: str) -> list[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


listed = {path: listing(path) for path in HIDDEN}
found: list[str] = []

# 1. The folder of the volume, and what is in it (usage, qgroups, allocation, features).
for path in (f"/sys/fs/btrfs/{fsid}", f"/sys/fs/btrfs/{fsid}/allocation/data/total_bytes"):
    if os.path.exists(path):
        found.append(path)

# 2. Every route to a loop device's backing_file, and every file in /sys that has the image's
#    host path in it (links followed: /sys is full of them).
for base in ("/sys/block", "/sys/class/block", "/sys/dev/block", "/sys/devices/virtual/block"):
    for directory, subdirs, files in os.walk(base, followlinks=True):
        if directory.count("/") - base.count("/") >= 3:
            subdirs.clear()  # backing_file is two levels down: go no deeper than three
        for name in files:
            path = os.path.join(directory, name)
            try:
                with open(path, "rb") as handle:
                    content = handle.read(4096)
            except OSError:
                continue
            if name == "backing_file" or any(image in content for image in images):
                found.append(path)

# 3. Write in the hidden folders (a tmpfs would take a file; a read-only one says EROFS).
writes: dict[str, int] = {}
for path in HIDDEN:
    for kind in ("file", "dir"):
        target = os.path.join(path, "backtide-probe")
        try:
            if kind == "file":
                os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
            else:
                os.mkdir(target)
            writes[f"{kind}:{path}"] = 0
            (os.unlink if kind == "file" else os.rmdir)(target)
        except OSError as error:
            writes[f"{kind}:{path}"] = error.errno or -1

# 4. Take the hiding away: unmount it, to see what is underneath.
libc = ctypes.CDLL(None, use_errno=True)
umounts: dict[str, int] = {}
for path in HIDDEN:
    ctypes.set_errno(0)
    result = libc.umount2(path.encode(), 2)  # MNT_DETACH
    umounts[path] = 0 if result == 0 else ctypes.get_errno()

print(
    json.dumps(
        {
            "listed": listed,
            "found": sorted(set(found)),
            "writes": writes,
            "umounts": umounts,
            "listed_after": {path: listing(path) for path in HIDDEN},
        }
    )
)
