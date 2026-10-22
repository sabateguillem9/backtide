"""Evil agent: put secrets on the command line in every shape a tool might.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <marker>
Prints one JSON object on its last line: the made-up secrets it used (``values``) and the subset
that must also be absent from Tetragon's own file (``file_clean``: the forms the first barrier is
meant to strike). Quoted values with a space, and a name followed by a flag (``signing_key: -U``,
which sensor.py marks as second-barrier-only, docs/23 §5), are struck only in the black box, so
they are left out of ``file_clean``; the test still requires them absent from the black box.

The secrets are generated HERE and never passed on this script's own command line. The ``curl``
hosts end in ``.invalid`` and never resolve (invariant 8). The script ends with a sentinel exec
so the test reads only after every exec below has reached the sensor.
"""

import json
import secrets
import subprocess
import sys

marker = sys.argv[1]
TRUE = "/bin/true"
CURL = ["curl", "--max-time", "5", "--silent", "--show-error"]
HOST = "https://h.invalid"


def fake() -> str:
    return secrets.token_hex(10)


def run(argv: list[str]) -> None:
    subprocess.run(argv, check=False, capture_output=True, timeout=30)


sk = "sk-" + secrets.token_hex(10)
# Each form: (its made-up secret, the argv that carries it, file_clean). file_clean=True means
# the first barrier (Tetragon's RE2 rules) must strike it, so it must be absent from the raw
# Tetragon file too; False means it is a black-box-only form (quoted value with a space, or a
# name followed by a flag) that only the second barrier strikes.
forms = [
    (v0 := fake(), [TRUE, marker, f"signing_key={v0}"], True),
    (v1 := fake(), [TRUE, marker, f"SECRET_KEY={v1}"], True),
    (v2 := fake(), [TRUE, marker, "--encryption-key", v2], True),
    (v3 := fake(), [TRUE, marker, f"--master-key={v3}"], True),
    (v4 := fake(), [TRUE, marker, "--pass", v4], True),
    (v5 := fake(), [TRUE, marker, "--auth", v5], True),
    (sk, [TRUE, marker, sk], True),
    (v7 := fake(), [TRUE, marker, f"X-Signing-Key: {v7}"], True),
    (v8 := fake(), [TRUE, marker, "config", "set", "signing_key", v8], True),
    (v9 := fake(), [TRUE, marker, f"--private-key={v9}"], True),
    (v10 := fake(), ["env", f"MASTER_KEY={v10}", TRUE, marker, "run"], True),
    # Anchor-stealing inputs: a word before the real value must not be taken for it.
    (c0 := fake(), [*CURL, "--anyauth", "-u", f"alice:{c0}", HOST], True),
    (c1 := fake(), [*CURL, "--proxy-anyauth", "-U", f"alice:{c1}", HOST], True),
    (
        c2 := fake(),
        ["sh", "-c", f"curl --max-time 5 --silent --anyauth -u alice:{c2} {HOST}"],
        True,
    ),
    (a0 := fake(), [TRUE, marker, "--auth", "Bearer", a0], True),
    (a1 := fake(), [TRUE, marker, "--pass", "--pass", a1], True),
    (a2 := fake(), [TRUE, marker, f"signing_key=Bearer {a2}"], True),
    (a3 := fake(), [TRUE, marker, "--no-auth", "Bearer", "Basic", a3], True),
    # A name followed by a flag: sensor.py leaves it to the second barrier (black box only).
    (a4 := fake(), [TRUE, marker, "signing_key:", "-U", f"alice:{a4}"], False),
    # Quoted values with a space: Tetragon's file may keep them; procs strikes them (box only).
    (q0 := fake(), [*CURL, "--anyauth", "-b", f"sid={q0}; x=1", HOST], False),
    (q1 := fake(), [*CURL, "--anyauth", "--pass", f"{q1} frase", HOST], False),
    # "--no-token --token <value>" is an accepted limit (KNOWN_LEAKS in test_secret_words_parity):
    # a secret flag followed by another one, as "--password --password <value>" before it.
    (q3 := fake(), [TRUE, marker, "token:", "-v", "-u", f"alice:{q3} x"], False),
]
for _value, argv, _file_clean in forms:
    run(argv)
run([TRUE, f"{marker}-fin"])  # sentinel: the test waits for this before reading
print(
    json.dumps(
        {
            "values": [value for value, _, _ in forms],
            "file_clean": [value for value, _, file_clean in forms if file_clean],
            # The form of each value, as the agent typed it with the secret replaced by "<f>": the
            # test names a leaked form by this, never by its value.
            "labels": {
                value: " ".join(argv).replace(value, "<f>").replace(marker, "<m>")
                for value, argv, _ in forms
            },
            "marker": marker,
        }
    )
)
