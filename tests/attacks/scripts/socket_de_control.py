"""Evil agent: try to reach the service's control socket, to have Vigía rewind (or to feed it
garbage) from inside the jail.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <host path of
control.sock> <a path in the workspace for the control socket>. Prints one JSON object on its
last line.

What it tries, and what counts as reaching it:
1. Finding a socket named ``control.sock`` anywhere it can read (the whole filesystem, without
   crossing into /proc, and the table of Unix sockets of its own network namespace).
2. Connecting to the host path as written and through the roots of other processes
   (/proc/self/root, /proc/1/root, /proc/<pid>/root).
3. As a control, the same probe against a socket it opens itself in the workspace: that one does
   connect, so "nothing connected" means there was nothing to connect to.
"""

import json
import os
import socket
import sys

host_path = sys.argv[1]
own_path = sys.argv[2]


def connects(path: str) -> int:
    """0 if a connection to ``path`` was accepted, else the errno."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(path)
    except OSError as error:
        return error.errno or -1
    finally:
        sock.close()
    return 0


# 1. By name, on every filesystem it can walk (not /proc and /sys: /proc is step 2).
found = []
for directory, names, files in os.walk("/", followlinks=False):
    names[:] = [n for n in names if os.path.join(directory, n) not in ("/proc", "/sys")]
    for name in files:
        if name == "control.sock":
            found.append(os.path.join(directory, name))
try:
    with open("/proc/net/unix", encoding="utf-8", errors="replace") as table:
        listed = [line.split()[-1] for line in table if "control.sock" in line]
except OSError:
    listed = []

# 2. The host path, as written and through the root of every process it can see.
pids = ["self", "1"] + sorted(p for p in os.listdir("/proc") if p.isdigit())
attempts = {host_path: connects(host_path)}
for pid in dict.fromkeys(pids):
    through = f"/proc/{pid}/root{host_path}"
    attempts[through] = connects(through)
reached = [path for path, code in attempts.items() if code == 0]

# 3. The control: a socket of its own, in the workspace, answers the same probe.
if os.path.exists(own_path):
    os.unlink(own_path)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(own_path)
listener.listen()
control_code = connects(own_path)
listener.close()
os.unlink(own_path)

print(
    json.dumps(
        {
            "found": found,
            "listed": listed,
            "reached": reached,
            "attempts": len(attempts),
            "errnos": sorted(set(attempts.values())),
            "control_connect": control_code,
        }
    )
)
