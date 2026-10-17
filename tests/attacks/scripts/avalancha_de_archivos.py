"""Evil agent: create files faster than anyone can write them down.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <dir> <seconds>
<workers> <max files>. Forks ``workers`` processes that each create empty files (a few
thousand per folder) in their own folders under <dir> until the time or the file budget runs
out. Every file is one IN_CREATE and one IN_CLOSE_WRITE for the watcher. Prints one JSON object
on its last line: how many files were really created and how long it took.
"""

import json
import os
import sys
import time

base, seconds, workers, budget = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
PER_FOLDER = 2000
per_worker = budget // workers
os.makedirs(base, exist_ok=True)
start = time.monotonic()
pipes = []
for worker in range(workers):
    read_end, write_end = os.pipe()
    if os.fork() == 0:  # a worker: counts its own files and reports them through the pipe
        os.close(read_end)
        created = 0
        folder = None
        while created < per_worker and time.monotonic() - start < seconds:
            if created % PER_FOLDER == 0:
                folder = os.path.join(base, f"w{worker}-{created // PER_FOLDER}")
                os.mkdir(folder)
            os.close(os.open(os.path.join(folder, f"f{created}"), os.O_CREAT | os.O_WRONLY))
            created += 1
        os.write(write_end, str(created).encode())
        os._exit(0)
    os.close(write_end)
    pipes.append(read_end)
total = 0
for read_end in pipes:
    total += int(os.read(read_end, 32) or b"0")
while True:  # reap the workers
    try:
        os.wait()
    except ChildProcessError:
        break
print(json.dumps({"created": total, "seconds": round(time.monotonic() - start, 2)}))
