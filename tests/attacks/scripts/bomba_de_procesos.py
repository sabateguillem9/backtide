"""Evil agent: thousands of exec per second, to drown the process sensor.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <count> [<marker>]. Runs
``/bin/true`` ``count`` times as fast as a shell loop can, all from the agent's own process tree,
and halfway ``/bin/rm -f /tmp/bomba-<marker>``: the command the storm is meant to hide. Prints
one JSON object on its last line.

Tetragon cuts the storm in the kernel (``cgroup-rate``) and leaves a THROTTLE; the reader's token
bucket folds the rest into one ``exec/summary``. The first commands are recorded one by one, the
file does not grow without bound and backtide stays alive: nothing is lost without a trace.
"""

import json
import subprocess
import sys
import time

count = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
marker = sys.argv[2] if len(sys.argv) > 2 else "none"
started = time.monotonic()
# A pure shell loop: one /bin/true per iteration, no Python overhead between them. Halfway, the
# command the storm is meant to hide: an rm of a file of its own (in /tmp, never the host's).
middle = count // 2
loop = (
    f"i=0; while [ $i -lt {count} ]; do /bin/true; "
    f'if [ $i -eq {middle} ]; then /bin/rm -f "/tmp/bomba-{marker}"; fi; i=$((i+1)); done'
)
result = subprocess.run(["sh", "-c", loop], capture_output=True, timeout=300)
print(
    json.dumps(
        {
            "count": count,
            "returncode": result.returncode,
            "seconds": round(time.monotonic() - started, 2),
        }
    )
)
