"""Evil agent: fill the disk by rewriting files, so that old and new data both stay charged.

Runs INSIDE the jail, as the agent's user (python3 -c). Two modes, one JSON object printed:

  seed <directory> <files> <MiB each>   write the files (the data a snapshot will pin)
  rewrite <directory> <seconds>         overwrite every file in place, once, with new data

A snapshot keeps the old blocks of a file alive, and the rewrite allocates new ones, so the
space charged to the workspace grows while its files do not. The test takes a snapshot between
rounds, as the T04 service does every 2 minutes while there is activity.
"""

import json
import os
import sys
import time

mode, directory = sys.argv[1], sys.argv[2]
MIB = 1 << 20


def stopped(error, call, **extra):
    return {"errno": error.errno, "call": call, **extra}


if mode == "seed":
    count, size = int(sys.argv[3]), int(sys.argv[4])
    os.makedirs(directory, exist_ok=True)
    for index in range(count):
        with open(os.path.join(directory, f"table-{index}.dat"), "wb") as handle:
            for block in range(size):
                handle.write(bytes([(index * 31 + block) % 251]) * MIB)
            handle.flush()
            os.fsync(handle.fileno())
    print(json.dumps({"files": count, "bytes": count * size * MIB}))
    sys.exit(0)

deadline = time.monotonic() + float(sys.argv[3])
written, outcome = 0, {"errno": 0, "call": "done"}
for name in sorted(os.listdir(directory)):
    path = os.path.join(directory, name)
    size = os.path.getsize(path)
    try:
        fd = os.open(path, os.O_WRONLY)  # no O_TRUNC: the same file, new contents
    except OSError as error:
        outcome = stopped(error, "open")
        break
    try:
        for offset in range(0, size, MIB):
            if time.monotonic() > deadline:
                outcome = {"errno": 0, "call": "deadline"}
                break
            written += os.pwrite(fd, bytes([(offset // MIB + 7) % 253 + 1]) * MIB, offset)
        os.fsync(fd)
    except OSError as error:
        outcome = stopped(error, "write")
    finally:
        os.close(fd)
    if outcome["call"] != "done":
        break
print(json.dumps({**outcome, "rewritten": written}))
