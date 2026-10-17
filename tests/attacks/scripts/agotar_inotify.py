"""Evil agent: use up every inotify instance of its user.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> hold. Opens inotify
instances until the kernel says no (EMFILE), then forks a daemon that keeps them all open and
returns. The limit is per user, and in the tests the agent has the same uid as the service
(production gives the agent a uid of its own, docs/13). Prints one JSON object on its last
line: how many instances it got, the error that stopped it and the daemon's pid. Kill the
daemon to give the instances back.
"""

import ctypes
import json
import os
import time

IN_NONBLOCK = 0o4000
libc = ctypes.CDLL(None, use_errno=True)
with open("/proc/sys/fs/inotify/max_user_instances") as handle:
    limit = int(handle.read())
held = []
code = 0
while True:
    descriptor = libc.inotify_init1(IN_NONBLOCK)
    if descriptor < 0:
        code = ctypes.get_errno()
        break
    held.append(descriptor)
ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:  # the daemon: holds the instances and does nothing else
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDWR)
    for stream in (0, 1, 2):
        os.dup2(devnull, stream)
    os.write(ready_write, b"1")
    time.sleep(900)
    os._exit(0)
os.close(ready_write)
os.read(ready_read, 1)
print(json.dumps({"limit": limit, "instances": len(held), "errno": code, "daemon_pid": pid}))
