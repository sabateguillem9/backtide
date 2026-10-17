"""Evil agent: keep the kernel's event queue full, without a pause.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <dir> <seconds>
<workers>. Forks ``workers`` processes that create and delete empty files in a loop (four
events per round) until the time runs out, so that events arrive faster than the watcher
reads them, whatever it is doing meanwhile (a snapshot, a rewind). Prints one JSON object on
its last line: the rounds made and how many events the kernel's queue can hold.
"""

import json
import os
import sys
import time

base, seconds, workers = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
os.makedirs(base, exist_ok=True)
with open("/proc/sys/fs/inotify/max_queued_events") as handle:
    queue_size = int(handle.read())
start = time.monotonic()
pipes = []
for worker in range(workers):
    read_end, write_end = os.pipe()
    if os.fork() == 0:
        os.close(read_end)
        rounds = 0
        while time.monotonic() - start < seconds:
            path = os.path.join(base, f"w{worker}-{rounds % 5000}")
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY))  # CREATE + CLOSE_WRITE
            os.unlink(path)  # DELETE
            rounds += 1
        os.write(write_end, str(rounds).encode())
        os._exit(0)
    os.close(write_end)
    pipes.append(read_end)
rounds = sum(int(os.read(read_end, 32) or b"0") for read_end in pipes)
while True:
    try:
        os.wait()
    except ChildProcessError:
        break
print(json.dumps({"rounds": rounds, "queue_size": queue_size, "seconds": seconds}))
