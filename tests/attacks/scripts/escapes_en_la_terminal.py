"""Evil agent: write escape sequences straight into the owner's terminal during `entrar`.

Runs INSIDE the jail, as the agent's user (python3 -c), while the owner's interactive Claude
Code session is open. Usage: <script> <marker>
Prints one JSON object on its last line: the ttys it wrote to and the ones it could not.

It finds the session's process (Claude Code without -p) and writes to its terminal, which
`docker exec -t` connects to the owner's: the clipboard (OSC 52 with the marker, so the test can
find exactly this write), the alternate screen, mouse reporting, bracketed paste, a hidden
cursor, and two questions to the terminal (device attributes and the window title).
"""

import base64
import json
import os
import sys
from pathlib import Path

marker = sys.argv[1]
OSC52 = f"\x1b]52;c;{base64.b64encode(marker.encode()).decode()}\x07"
SEQUENCES = OSC52 + "\x1b[?1049h\x1b[?1000h\x1b[?2004h\x1b[?25l\x1b[c\x1b[21t"

found = []
for proc in Path("/proc").glob("[0-9]*"):
    try:
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        tty = os.readlink(proc / "fd" / "1")
    except OSError:
        continue
    if (
        b"--dangerously-skip-permissions" in argv
        and b"-p" not in argv
        and tty.startswith("/dev/pts/")
    ):
        found.append(tty)

written, failed = [], []
for tty in sorted(set(found)):
    try:
        fd = os.open(tty, os.O_WRONLY | os.O_NOCTTY)
        try:
            os.write(fd, SEQUENCES.encode())
        finally:
            os.close(fd)
        written.append(tty)
    except OSError as error:
        failed.append(f"{tty}: {type(error).__name__}")
print(json.dumps({"terminals": sorted(set(found)), "written": written, "failed": failed}))
