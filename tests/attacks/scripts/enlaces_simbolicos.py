"""Evil agent: symlinks that point out of the workspace.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <directory in the workspace> <canary file> <host path>...
The host paths are where Vigía keeps its store and snapshots ON THE HOST, and a canary file
the test planted next to them. They must not exist inside the container at all. Prints one
JSON object on its last line.
"""

import errno
import json
import os
import sys

base, canary_file, host_paths = sys.argv[1], sys.argv[2], sys.argv[3:]
CANARY = "vigia-canary-host-file"
os.makedirs(base, exist_ok=True)

links = {
    "to-root": "/",
    "to-proc-root": "/proc/1/root",
    "to-self-root": "/proc/self/root",
    "to-config": "/config",
    "to-etc": "/etc",
    "to-parent": "../../../../..",
    "loop": "loop",
    "chain-a": "chain-b",
    "chain-b": "chain-a",
}
for index, path in enumerate(host_paths):
    links[f"to-host-{index}"] = path
for name, target in links.items():
    try:
        os.symlink(target, os.path.join(base, name))
    except FileExistsError:
        pass

# 1. Can anything of the host be reached? Straight, and through the links to / and /proc.
routes = ["", base + "/to-root", base + "/to-proc-root", base + "/to-self-root", "/proc/1/root"]
reached, leaked = [], False
for host_path in host_paths + [canary_file]:
    for route in routes:
        candidate = route + host_path
        if os.path.lexists(candidate):
            reached.append(candidate)
        try:
            with open(candidate) as handle:
                leaked = leaked or CANARY in handle.read()
        except OSError:
            pass
for name in links:  # the links that name a host path directly
    if name.startswith("to-host-") and os.path.exists(os.path.join(base, name)):
        reached.append(os.path.join(base, name))

# 2. Can it WRITE through them into the read-only parts (config, root filesystem)?
writes = {}
for name in ("to-config", "to-etc", "to-root/etc", "to-root/usr", "to-proc-root/etc"):
    try:
        with open(os.path.join(base, name, "vigia-escape.txt"), "w") as handle:
            handle.write("escaped")
        writes[name] = 0
    except OSError as error:
        writes[name] = error.errno

# Control: a file that does exist (the container's own) IS readable through the same links, so
# an empty `reached` above means "not there", not "the probe cannot read".
control_read = False
try:
    with open(os.path.join(base, "to-root", "etc", "hostname")) as handle:
        control_read = bool(handle.read().strip())
except OSError:
    pass

# 3. Loops and chains must fail cleanly, never hang the reader.
loops = {}
for name in ("loop", "chain-a"):
    try:
        os.stat(os.path.join(base, name))
        loops[name] = 0
    except OSError as error:
        loops[name] = error.errno

print(
    json.dumps(
        {
            "links": sorted(links),
            "host_paths_reached": reached,
            "canary_read": leaked,
            "control_read": control_read,
            "writes": writes,
            "loops": loops,
            "eloop": errno.ELOOP,
        }
    )
)
