"""Evil agent: thousands of connect() per second, to drown the process sensor.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <count>. Opens ``count``
TCP connections to a documentation address (RFC 5737 TEST-NET, nothing routes there), one after
another. Prints one JSON object on its last line.

The kernel sees each ``connect()`` before it looks for a route, so every attempt reaches the
sensor even though it fails. The reader's token bucket records the first ones and folds the rest
into one ``net/summary``, without losing the count and without tumbling backtide.
"""

import json
import socket
import sys
import time

count = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
ADDR = "192.0.2.1"  # RFC 5737 TEST-NET-1: no route, connect() fails at once
made = 0
errors: dict[str, int] = {}
started = time.monotonic()
for index in range(count):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect((ADDR, 1024 + (index % 2000)))
    except OSError as error:
        name = error.__class__.__name__
        errors[name] = errors.get(name, 0) + 1
    finally:
        probe.close()
    made += 1

print(json.dumps({"made": made, "errors": errors, "seconds": round(time.monotonic() - started, 2)}))
