"""Evil agent: swap folders for links to the host's / and /etc while Vigía looks at them.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <dir> <seconds>
<workers>. Forks ``workers`` processes that, in a tight loop, make a folder with files in it
and then change it for a symlink to "/" or "/etc" at every point where the watcher could be
looking: right after the folder is created (before it can be opened), after it is renamed
away, and with the real folder moved beside the link. The files are empty on purpose: if a
record under <dir> ever shows a size, it came from the HOST's /etc (the service runs there).
Prints one JSON object on its last line: how many swaps it made.
"""

import json
import os
import shutil
import sys
import time

base, seconds, workers = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
HOST_NAMES = ("passwd", "hostname", "os-release", "hosts")
os.makedirs(base, exist_ok=True)
start = time.monotonic()
pipes = []
for worker in range(workers):
    read_end, write_end = os.pipe()
    if os.fork() == 0:
        os.close(read_end)
        swaps = 0
        mine = os.path.join(base, f"w{worker}")
        os.makedirs(mine, exist_ok=True)
        while time.monotonic() - start < seconds:
            folder = os.path.join(mine, f"s{swaps % 20}")
            target = ("/", "/etc")[swaps % 2]
            if swaps % 3 == 0:  # swapped before the watcher can open it
                os.mkdir(folder)
                os.rmdir(folder)
                os.symlink(target, folder)
                os.unlink(folder)
            else:  # a folder with content, moved aside and replaced by the link
                os.makedirs(os.path.join(folder, "inner"))
                for name in HOST_NAMES:
                    for where in (folder, os.path.join(folder, "inner")):
                        os.close(os.open(os.path.join(where, name), os.O_CREAT | os.O_WRONLY))
                os.rename(folder, folder + ".old")
                os.symlink(target, folder)
                os.unlink(folder)
                shutil.rmtree(folder + ".old")
            swaps += 1
        os.write(write_end, str(swaps).encode())
        os._exit(0)
    os.close(write_end)
    pipes.append(read_end)
swaps = sum(int(os.read(read_end, 32) or b"0") for read_end in pipes)
while True:
    try:
        os.wait()
    except ChildProcessError:
        break
print(json.dumps({"swaps": swaps}))
