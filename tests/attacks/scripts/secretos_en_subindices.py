"""Evil agent: leave secrets on the command line as a value assigned through a subscript and as a
value in brackets (the code review of 2026-10-29, J2 and J3; T27-9a), and hide code between two
strings the strike may join (the review of PR 1).

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <marker> <workdir>
Every command really runs, so the process sensor sees it. A tool the image lacks (ruby, perl) is
replaced by ``/bin/true <tool> <same arguments>``: the same text on a command line.
Prints one JSON object on its last line:
- ``forms``: per command with a secret its tag (``<marker>-NN``, kept in sight on its argv), its
  made-up secret, the binary the sensor should name, its form with the secret replaced by
  ``<s>``, and whether it is an accepted residue of docs/46 (``residue``);
- ``hidden``: per command with code between two strings its tag, its form and the word of code
  the black box must show, or else note the event (``argv_struck_long``);
- ``run_tag``, the run's own prefix of every secret.

The secrets are made HERE, never on this script's own argv, from letters that are not hex (so
no hash or container id in the black box can hold a piece of one by chance). Nothing leaves the
container: no command opens a connection (invariant 8).
"""

import json
import os
import secrets
import shutil
import string
import subprocess
import sys
from collections.abc import Callable

marker, workdir = sys.argv[1], sys.argv[2]
TRUE = "/bin/true"
LETTERS = "".join(c for c in string.ascii_letters if c.lower() not in "abcdef")
RUN_TAG = "".join(secrets.choice(LETTERS) for _ in range(6))  # in every secret of this run
PYTHON = shutil.which("python3") or "python3"


def fake() -> str:
    return RUN_TAG + "".join(secrets.choice(LETTERS) for _ in range(14))


def add(make: Callable[[str], list[str]], binary: str, residue: bool = False) -> None:
    """One command: ``make`` builds its argv around a fresh secret. ``residue``: an accepted
    limit of docs/46 (section 6), recorded but not struck."""
    value = fake()
    forms.append((value, make(value), binary, residue))


def py(code: str, residue: bool = False) -> None:
    """python3 -c <code>: the code really runs (the subscript or the call happens)."""
    add(lambda value: ["python3", "-c", code.replace("<s>", value)], "*/python3*", residue)


def via(name: str, *args: str) -> None:
    """The tool itself when the image has it, or /bin/true with the same text after it."""
    if shutil.which(name):
        add(lambda value: [name, *(a.replace("<s>", value) for a in args)], f"*/{name}*")
    else:
        add(lambda value: [TRUE, name, *(a.replace("<s>", value) for a in args)], "*/true")


STUB = "import types; requests=types.SimpleNamespace(get=lambda *a, **k: 0); "
F = "f=lambda *a, **k: 0; "
forms: list[tuple[str, list[str], str, bool]] = []

# J2: a value assigned through a subscript (Python, Ruby, Perl; quoted or not).
py("import os; os.environ['GITHUB_TOKEN']='<s>'")
py("d={}; d['password']='<s>'")
py('cfg={}; cfg["api_key"] = "<s>"')
via("ruby", "-e", "ENV['API_TOKEN']='<s>'")
via("perl", "-e", '$ENV{API_TOKEN}="<s>"')
via("perl", "-e", "$ENV{'API_TOKEN'}='<s>'")

# J3: a value in brackets (requests' basic auth, a call, a tuple assigned through a subscript).
# The two auth= ones are struck by procs' pass alone (auth is a flag word, not one of redact's).
py(STUB + "requests.get('u', auth=('u', '<s>'))")
py(STUB + 'requests.get("u", auth=("u", "<s>"))')
py(F + "f(token=(str(), '<s>'))")
py("d={}; d['password'] = ('u', '<s>')")
# The accepted residue (docs/46, section 6): a lone literal glued to "=(" reads as
# token=get_token('name') once the older rule took the "(", and a literal with a ; inside is
# not a clean one. Recorded, and the scenario says they are not struck.
py(F + "f(token=('<s>'))", residue=True)
py(F + "f(cookie=('<s>'))", residue=True)
py(F + "f(password=('a;<s>'))", residue=True)

# Code between two strings: the strike from the first quote to the next one may swallow it, so
# the event shows the code or says the strike may hide part of the command (risk 1).
OS_TRUE = "__import__(chr(111)+chr(115)).system(chr(116)+chr(114)+chr(117)+chr(101))"
copy = os.path.join(workdir, "r")  # an interpreter under a name and a path of the agent's own
os.makedirs(workdir, exist_ok=True)
shutil.copy(PYTHON, copy)
hidden_forms: list[tuple[list[str], str]] = [
    # A call between the strings: never struck, so the code stays in sight.
    (["python3", "-c", f"print('d[token]=')or({OS_TRUE})or('')"], "system"),
    (["python3", "-c", f"print('auth=(\"u\",')or({OS_TRUE})or('')"], "system"),
    # Only token characters between the strings: noted because the program runs code, by its
    # own name (the image's python3), by a versioned name in the text (perl5.36.0) or by its
    # path outside the image (the copy). The perl5.36.0 and copy ones also tell procs' pass from
    # the black box's: the box strikes .qx. and or-exit-1or too, but notes nothing.
    (["python3", "-c", "print('x_token='or-exit-1or'')"], "exit"),
    (["python3", "-c", "print('d[token]='or-exit-1or'')"], "exit"),
    ([TRUE, "perl5.36.0", "-e", "print('x_token='.unlink.'')"], "unlink"),
    ([TRUE, "perl5.36.0", "-e", "print('d[token]='.qx.'')"], "qx"),
    ([copy, "-c", "print('x_token='or-exit-1or'')"], "exit"),
    ([copy, "-c", "print('d[token]='or-exit-1or'')"], "exit"),
    # A character no token has (the !): noted whatever the program, here one that names none.
    ([TRUE, "-e", "print('x_token='+exit!+'')"], "exit"),
    ([TRUE, "-e", "print('d[token]='+exit!+'')"], "exit"),
]
if shutil.which("perl"):
    hidden_forms.append((["perl", "-e", "print('d[token]='.qx.'')"], "qx"))

out, hidden = [], []
try:
    for number, (value, argv, binary, residue) in enumerate(forms):
        tag = f"{marker}-{number:02d}"
        # The tag rides last on each argv (sys.argv, $0, @ARGV or one more word), never struck.
        subprocess.run([*argv, tag], check=False, capture_output=True, timeout=30)
        out.append(
            {
                "tag": tag,
                "value": value,
                "binary": binary,
                "form": " ".join(argv).replace(value, "<s>"),
                "stand_in": argv[0] == TRUE and binary == "*/true",
                "residue": residue,
            }
        )
    for number, (argv, word) in enumerate(hidden_forms):
        tag = f"{marker}-h{number:02d}"
        subprocess.run([*argv, tag], check=False, capture_output=True, timeout=30)
        hidden.append({"tag": tag, "form": " ".join(argv), "word": word})
finally:
    os.remove(copy)  # no copied interpreter left behind in the agent's folder
subprocess.run([TRUE, f"{marker}-fin"], check=False)  # sentinel: the test waits for it
print(json.dumps({"forms": out, "hidden": hidden, "run_tag": RUN_TAG, "marker": marker}))
