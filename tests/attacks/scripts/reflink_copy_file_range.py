"""Evil agent: get many copies of a big file for the price of one (a reflink).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <directory in the workspace> <MiB> <copies>. Prints one JSON object on its last line.

On Btrfs, copy_file_range, FICLONE and `cp --reflink` share the blocks of the original, so
the copies cost (almost) no space and slip under the workspace cap. The jail must block all of
them (seccomp: EXDEV for copy_file_range, EOPNOTSUPP for the 0x94 ioctls) so that every
copier falls back to really copying, and every copy is charged.
"""

import fcntl
import json
import os
import shutil
import struct
import subprocess
import sys

directory, size, copies = sys.argv[1], int(sys.argv[2]) << 20, int(sys.argv[3])
os.makedirs(directory, exist_ok=True)
FICLONE = 0x40049409  # _IOW(0x94, 9, int)
FICLONERANGE = 0x4020940D  # _IOW(0x94, 13, struct file_clone_range)
source = os.path.join(directory, "original.bin")
with open(source, "wb") as handle:
    for block in range(size >> 20):
        handle.write(bytes([block % 250 + 1]) * (1 << 20))
    handle.flush()
    os.fsync(handle.fileno())


def attempt(call):
    try:
        return call()
    except OSError as error:
        return -error.errno


def copy_file_range():
    with open(source, "rb") as src, open(os.path.join(directory, "cfr.bin"), "wb") as dst:
        return os.copy_file_range(src.fileno(), dst.fileno(), size)


def ficlone(request, argument):
    def call():
        with open(source, "rb") as src, open(os.path.join(directory, "clone.bin"), "wb") as dst:
            fcntl.ioctl(dst.fileno(), request, argument(src.fileno()))
        return 0

    return call


raw = {
    "copy_file_range": attempt(copy_file_range),
    "ficlone": attempt(ficlone(FICLONE, lambda fd: fd)),
    "ficlonerange": attempt(ficlone(FICLONERANGE, lambda fd: struct.pack("=qQQQ", fd, 0, size, 0))),
}
always = subprocess.run(
    ["cp", "--reflink=always", source, os.path.join(directory, "always.bin")],
    capture_output=True,
    text=True,
)

# The "innocent" copiers must still work: they read and write, and every byte is charged.
made = []
for index in range(copies):
    destination = os.path.join(directory, f"copy-{index}.bin")
    if index % 2:
        subprocess.run(["cp", "--reflink=auto", source, destination], check=True)
    else:
        shutil.copyfile(source, destination)
    made.append(destination)
    os.sync()
identical = all(open(path, "rb").read() == open(source, "rb").read() for path in made)
print(
    json.dumps(
        {
            "raw": raw,
            "cp_always_returncode": always.returncode,
            "copies": [os.path.basename(path) for path in made],
            "identical": identical,
        }
    )
)
