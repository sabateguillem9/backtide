"""Evil agent: make more folders than the file watcher can watch.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <dir>. Reads the same
limit the watcher reads (a quarter of fs.inotify.max_user_watches, at most 8192 watches) and
makes ``cap + 3000`` folders side by side, then a chain of 100 folders one inside the other
(the watcher stops at depth 64). Prints one JSON object on its last line.
"""

import json
import os
import sys

base = sys.argv[1]
with open("/proc/sys/fs/inotify/max_user_watches") as handle:
    cap = min(8192, int(handle.read()) // 4)
wide = cap + 3000
os.makedirs(os.path.join(base, "wide"))
for number in range(wide):
    os.mkdir(os.path.join(base, "wide", f"d{number}"))
os.mkdir(os.path.join(base, "deep"))
descriptor = os.open(os.path.join(base, "deep"), os.O_RDONLY | os.O_DIRECTORY)
for _ in range(100):  # through descriptors: the path would be too long to write
    os.mkdir("l", dir_fd=descriptor)
    child = os.open("l", os.O_RDONLY | os.O_DIRECTORY, dir_fd=descriptor)
    os.close(descriptor)
    descriptor = child
os.close(descriptor)
print(json.dumps({"cap": cap, "wide": wide, "deep": 100}))
