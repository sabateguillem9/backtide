"""Evil agent: fill the metadata of the volume with small files.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <directory> <seconds>.
Prints one JSON object on its last line.

Files of 2000 bytes live inside the metadata tree, and a created empty file costs metadata
too. With the metadata full, every rename in the volume fails, so backtide could not rewind.
The workspace cap (a Btrfs simple quota) is what must stop this first.
"""

import json
import os
import sys
import time

directory, seconds = sys.argv[1], float(sys.argv[2])
SMALL = b"x" * 2000
PER_FOLDER = 1000
deadline = time.monotonic() + seconds
started, count, call = time.monotonic(), 0, "create"
outcome = {"errno": 0, "call": "deadline"}
try:
    while True:
        if count % PER_FOLDER == 0:
            if time.monotonic() > deadline:
                break
            call = "mkdir"
            os.makedirs(os.path.join(directory, f"d{count // PER_FOLDER}"), exist_ok=True)
        folder = os.path.join(directory, f"d{count // PER_FOLDER}")
        call = "create"
        fd = os.open(os.path.join(folder, f"f{count}"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            call = "write"
            os.write(fd, SMALL)
        finally:
            os.close(fd)
        count += 1
except OSError as error:
    outcome = {"errno": error.errno, "call": call}
print(json.dumps({**outcome, "files": count, "seconds": round(time.monotonic() - started, 1)}))
