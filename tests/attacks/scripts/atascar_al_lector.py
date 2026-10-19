"""Evil agent: feed the sensor's reader hostile arguments, to make it stall.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <count> <marker>.
Prints one JSON object on its last line.

Each exec carries about 64 KB of a form that used to cost the reader seconds per line (a long
run of ``a.a.`` that the URL-credentials and JWT patterns scanned quadratically). Halfway, a
marked ``/bin/rm`` of a file of its own: the command the stall is meant to hide. The reader
must stay responsive (its patterns are bounded now), so the marked command is recorded, and
backtide stays alive. Nothing here harms the host: the file is in the agent's own workspace.
"""

import json
import os
import subprocess
import sys

count = int(sys.argv[1])
marker = sys.argv[2]
workdir = f"/workspace/work/atascar-{marker}"
os.makedirs(workdir, exist_ok=True)
victim = os.path.join(workdir, "victim")
with open(victim, "w") as handle:
    handle.write("x\n")

# ~64 KB of the quadratic form, after a quote: the reader's tail window reaches back to the last
# quote or line break (at most 64 KiB), so without it only the plain 2.5 KiB window was struck
# and the hostile part never reached the patterns (T07-5).
blob = '"' + ("a.a-a://" * (64 * 1024 // 8))[: 64 * 1024 - 1]
middle = count // 2
rm_code = None
for index in range(count):
    subprocess.run(["/bin/true", f"atascar-{marker}", blob], capture_output=True, timeout=60)
    if index == middle:
        rm_code = subprocess.run(
            ["/bin/rm", "-f", victim], capture_output=True, timeout=30
        ).returncode

print(json.dumps({"count": count, "marker": marker, "rm": rm_code, "left": os.path.exists(victim)}))
