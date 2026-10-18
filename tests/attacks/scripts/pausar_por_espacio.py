"""Evil agent: fill the workspace to just under its cap, then go past it by deleting after a
snapshot.

Runs INSIDE the jail, as the agent user (python3 -c). Usage: <script> fill <directory> <files> |
delete <directory> <leaves>. Prints one JSON object on its last line.

``fill``: ``files`` more files of 2000 bytes (inline: metadata only) after the ones already there.
The test calls it in batches until the workspace is near its cap: filling up to the EDQUOT of the
cap (T03b) is not deterministic, because the quota counts what the transaction reserved and the
usage then falls by up to 30 MiB, and the writes that get to the cap can trip the space check
(P3) in the middle of the fill and freeze the script itself. ``delete``: once backtide has
snapshotted them, delete one file in each of ``leaves`` leaves: each delete copies a leaf the
snapshot shares and is charged with no quota check (docs/16, A13), so the workspace ends past
its cap without a single write being refused.
"""

import errno
import json
import os
import sys

mode, directory, amount = sys.argv[1], sys.argv[2], int(sys.argv[3])
SMALL = b"x" * 2000
STRIDE = 7  # about 7 small files share a leaf
outcome: dict[str, object] = {"mode": mode}
if mode == "fill":
    os.makedirs(directory, exist_ok=True)
    first = count = len(os.listdir(directory))
    code = 0
    while count < first + amount:
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
    for name in names[::STRIDE][:amount]:
        os.unlink(os.path.join(directory, name))
        deleted += 1
    outcome.update(deleted=deleted)
print(json.dumps(outcome))
