"""Evil agent: leave a passphrase on the command line (gpg's flag, borg's variable, an exported
one; the code review of 2026-10-29, J1).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <marker>
Every command really runs, so the process sensor sees it. A tool the image lacks (gpg) is
replaced by ``/bin/true <tool> <same arguments>``: the same text on a command line.
Prints one JSON object on its last line: per command its tag (``<marker>-NN``, kept in sight on
its argv), its made-up secret, the binary the sensor should name, and its form with the secret
replaced by ``<s>``; plus ``run_tag``, the run's own prefix of every secret.

The secrets are made HERE, never on this script's own argv, from letters that are not hex (so
no hash or container id in the black box can hold a piece of one by chance). Nothing leaves the
container: no command opens a connection, and gpg is given a file that does not exist
(invariant 8).
"""

import json
import secrets
import shutil
import string
import subprocess
import sys
from collections.abc import Callable

marker = sys.argv[1]
TRUE = "/bin/true"
LETTERS = "".join(c for c in string.ascii_letters if c.lower() not in "abcdef")
RUN_TAG = "".join(secrets.choice(LETTERS) for _ in range(6))  # in every secret of this run
forms: list[tuple[str, list[str], str]] = []


def fake() -> str:
    return RUN_TAG + "".join(secrets.choice(LETTERS) for _ in range(14))


def add(make: Callable[[str], list[str]], binary: str) -> None:
    """One command: ``make`` builds its argv around a fresh secret."""
    value = fake()
    forms.append((value, make(value), binary))


def via(name: str, *args: str) -> None:
    """The tool itself when the image has it, or /bin/true with the same text after it."""
    if shutil.which(name):
        add(lambda value: [name, *(a.replace("<s>", value) for a in args)], f"*/{name}*")
    else:
        add(lambda value: [TRUE, name, *(a.replace("<s>", value) for a in args)], "*/true")


via("gpg", "--batch", "--passphrase", "<s>", "-c", "/nonexistent/f")
via("gpg", "--passphrase=<s>", "-c", "/nonexistent/f")
# borg is not in the image: sh fails to find it, but its own line holds the assignment.
add(lambda value: ["sh", "-c", f"BORG_PASSPHRASE={value} borg create ::a ."], "*/sh")
add(lambda value: ["env", f"BORG_PASSPHRASE={value}", TRUE], "*/env")
add(lambda value: ["sh", "-c", f"export PASSPHRASE={value}; true"], "*/sh")

out = []
for number, (value, argv, binary) in enumerate(forms):
    tag = f"{marker}-{number:02d}"
    # The tag rides last on each argv ($0 for sh, one more word otherwise), never struck.
    subprocess.run([*argv, tag], check=False, capture_output=True, timeout=30)
    out.append(
        {
            "tag": tag,
            "value": value,
            "binary": binary,
            "form": " ".join(argv).replace(value, "<s>"),
            "stand_in": argv[0] == TRUE and binary == "*/true",
        }
    )
subprocess.run([TRUE, f"{marker}-fin"], check=False)  # sentinel: the test waits for it
print(json.dumps({"forms": out, "run_tag": RUN_TAG, "marker": marker}))
