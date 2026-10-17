"""Evil agent: fill the workspace up to its cap, then go past it by deleting after a snapshot.

Runs INSIDE the jail, as the agent user (python3 -c). Usage: <script> fill|delete <directory>.
Prints one JSON object on its last line.

``fill``: 2000-byte files (inline: metadata only) until the cap answers EDQUOT, which is where
the cap of T03b stops the agent. ``delete``: once backtide has snapshotted them, delete one file in
every leaf: each delete copies a leaf the snapshot shares and is charged with no quota check
(docs/16, A13), so the workspace ends past its cap without a single write being refused.
"""

import errno
import json
import os
import sys

mode, directory = sys.argv[1], sys.argv[2]
SMALL = b"x" * 2000
STRIDE = 7  # about 7 small files share a leaf
LEAVES = 700  # about 11 MiB of copied leaves: past the cap, with room left to rewind
outcome: dict[str, object] = {"mode": mode}
if mode == "fill":
    os.makedirs(directory, exist_ok=True)
    count, code = 0, 0
    while True:
        try:
            fd = os.open(
                os.path.join(directory, f"f{count}"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            try:
                os.write(fd, SMALL)
            finally:
                os.close(fd)
        except OSError as error:
            code = error.errno or 0
            break
        count += 1
    outcome.update(files=count, errno=code, edquot=code == errno.EDQUOT)
else:
    names = sorted(os.listdir(directory), key=lambda name: int(name[1:]))
    deleted = 0
    for name in names[::STRIDE][:LEAVES]:
        os.unlink(os.path.join(directory, name))
        deleted += 1
    outcome.update(deleted=deleted)
print(json.dumps(outcome))
