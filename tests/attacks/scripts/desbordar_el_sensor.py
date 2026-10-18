"""Evil agent: overflow Tetragon with connect() from many processes, and run a command inside.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <procs> <per> <marker>.
Prints one JSON object on its last line.

``procs`` children each connect() a UDP socket ``per`` times to TEST-NET addresses (RFC 5737:
nothing routes there, and with UDP connect() sends nothing anyway); the kernel still calls
security_socket_connect for each, so each one is an event for Tetragon. A second after the
flood starts, the parent runs ``/bin/true desbordar-<marker>``: the command the flood is meant
to hide. In the VM a flood like this fills Tetragon's ring buffer and queues, and Tetragon
drops events without a line or a log (the T07 review): the command must be in the black box,
or the loss must be, with its count.
"""

import json
import os
import socket
import subprocess
import sys
import time

procs, per, marker = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
started = time.monotonic()
children = []
for index in range(procs):
    pid = os.fork()
    if pid == 0:
        for i in range(per):
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect((f"192.0.2.{1 + index % 200}", 1024 + i % 60000))
            except OSError:
                pass
            probe.close()
        os._exit(0)
    children.append(pid)
time.sleep(1.0)
done = subprocess.run(["/bin/true", f"desbordar-{marker}"], capture_output=True, timeout=60)
failed = 0
for pid in children:
    _, status = os.waitpid(pid, 0)
    failed += os.waitstatus_to_exitcode(status) != 0
print(
    json.dumps(
        {
            "made": procs * per - failed * per,
            "marker": done.returncode,
            "seconds": round(time.monotonic() - started, 2),
        }
    )
)
