"""Evil agent: put secrets in the command line, to see if any reaches the black box.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <marker>. Prints one
JSON object on its last line with the exact secret strings it made up, by barrier, so the test
can look for each one where it must not be.

Every made-up secret is random (``secrets.token_urlsafe``: no run for the reader to fold, so a
leak cannot hide behind padding). Three groups:
- ``both``: forms both barriers know (Tetragon's RE2 rules and backtide's): an Authorization
  header, ``--password``, ``API_KEY=``, a URL with a password, a Telegram bot token, keys
  shaped like ``sk-``, ``ghp_``, ``AKIA``, a JWT, ``AIza``, ``xoxb-``, ``-u user:pass``.
- ``backtide``: forms only backtide strikes (Tetragon's file may keep them: it is root's alone,
  docs/23): ``--pass``, a quoted ``--password "two words"``, ``password = '…'`` in a script.
- The Gateway token, the real one the agent has in its environment: bare, and cut by the edge
  of the reader's windows (2 KiB from each end) at several offsets, with padding that folds.
The commands are harmless (``true``); only their arguments matter.
"""

import json
import os
import secrets as random
import string
import subprocess
import sys

marker = sys.argv[1]
token = os.environ["OPENCLAW_GATEWAY_TOKEN"]
WINDOW = 2048  # backtide/sensors/procs.py, _WINDOW


def word(size: int = 24) -> str:
    """Random letters and digits (no '-' or '_': no rule cuts it short)."""
    return "".join(c for c in random.token_urlsafe(size * 2) if c.isalnum())[:size]


both = {
    "bearer": word(),
    "password": word(),
    "api_key": "sk-" + word(40),
    "url_pass": word(),
    "telegram": "AA" + word(33),
    "github": "ghp_" + word(36),
    "aws": "AKIA"
    + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in "x" * 16),
    "jwt": f"eyJ{word(12)}.eyJ{word(16)}.{word(24)}",
    "aiza": "AIza" + word(35),
    "slack": "xoxb-" + word(24),
    "curl_user": word(),
    "my_secret": word(),
}
backtide_only = {
    "pass_flag": word(),
    "quoted": word(),
    "script": word(),
}
commands = [
    ["true", f"secretos-en-argv-{marker}", "-H", f"Authorization: Bearer {both['bearer']}"],
    ["true", "--password", both["password"]],
    ["sh", "-c", f"API_KEY={both['api_key']} true  # {marker}"],
    ["true", f"https://user:{both['url_pass']}@example.invalid/repo.git"],
    ["true", f"--token=123456789:{both['telegram']}"],
    ["true", both["github"], both["aws"], both["jwt"], both["aiza"], both["slack"]],
    ["true", "-u", f"alice:{both['curl_user']}", f"MY_SECRET={both['my_secret']}"],
    ["true", "--pass", backtide_only["pass_flag"]],
    ["true", "--password", f"two words {backtide_only['quoted']}"],
    ["true", "-c", f"password = '{backtide_only['script']}'\nlogin(password)"],
    ["true", f"gateway-{marker}", token],
]
# The Gateway token across both edges of the windows, at several offsets: a run of padding
# folds to a few characters, so both cuts become visible in the event (the review's case).
# Padding of token characters (A, B, C) and padding of others (" !"), so the drop of the run
# that touches a cut cannot stand in for the scrub of the token itself.
for shift in (-30, -12, -3, 0, 3, 12, 30):
    lead = f"split{shift}-{marker} "
    pad = WINDOW - len(lead) - len(token) // 2 + shift
    commands.append(["true", lead + "A" * pad + token + "B" * 3000 + token + "C" * pad])
    other = " !" * (pad // 2) + "!" * (pad % 2)
    commands.append(["true", lead + other + token + " !" * 1500 + token + other])

ran: dict[int, object] = {}
for index, argv in enumerate(commands):
    try:
        ran[index] = subprocess.run(argv, capture_output=True, timeout=20).returncode
    except (OSError, subprocess.SubprocessError) as error:
        ran[index] = type(error).__name__

print(json.dumps({"marker": marker, "both": both, "backtide_only": backtide_only, "ran": ran}))
