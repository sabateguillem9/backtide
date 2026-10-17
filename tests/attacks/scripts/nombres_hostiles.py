"""Evil agent: files and folders whose NAMES are the attack.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script> <dir>. Makes, in <dir>,
one entry per hostile name. Each name starts with a tag (H01, H02...) so that the test can find
its record: names that carry a secret (a token, an Authorization header, API keys of several
providers, a JWT, a private key block, even the target of a symlink), names with terminal
escapes, line breaks that imitate a forged log line, bytes that are not UTF-8, a right-to-left
override, carriage returns, shell and format-string characters, and a 240-byte name. Prints one
JSON object on its last line: the tags, and the secrets that must never be written anywhere.
"""

import json
import os
import sys

base = sys.argv[1].encode()
SECRETS = [
    "SUPERSECRETTOKENVALUE0123456789",
    "Bearer abcdefgh12345678ZZZZ",
    "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF",
    "ghp_0123456789abcdefghijABCDEFGHIJ",
    "AKIAABCDEFGHIJKLMNOP",
    "hunter2hunter2",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl",
    "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
    "AAAAB3NzaC1yc2EAAAADAQABAAABgQC",
    "DIRSECRETVALUE0123456789",
    "LINKSECRETVALUE0123456789",
]
NAMES: list[bytes] = [
    b"H01-token=" + SECRETS[0].encode(),
    b"H02-Authorization: " + SECRETS[1].encode(),
    b"H03-" + SECRETS[2].encode(),
    b"H04-" + SECRETS[3].encode(),
    b"H05-" + SECRETS[4].encode(),
    b"H06-password=" + SECRETS[5].encode(),
    b"H07-" + SECRETS[6].encode(),
    b"H08-" + SECRETS[7].encode(),
    b"H09------BEGIN OPENSSH PRIVATE KEY-----"
    + SECRETS[8].encode()
    + b"-----END OPENSSH PRIVATE KEY-----",
    b"H10-esc\x1b[2J\x1b[31mred\x1b]0;pwned\x07",
    b"H11-line one\nH11-forged: file delete precious.txt risk 3\n",
    b"H12-bad\xff\xfe\xc0\xafname",
    "H13-‮gpj.exe".encode(),
    b"H14-" + b"A" * 240,
    b"H15-\r\r\r-carriage",
    b"H16-%s%n%x{0}{{}}`id`$(id);rm -rf",
    b"H19--rf",
]
os.makedirs(base, exist_ok=True)
for name in NAMES:
    with open(os.path.join(base, name), "wb"):
        pass
folder = os.path.join(base, b"H17-dir-token=" + SECRETS[9].encode())
os.mkdir(folder)
with open(os.path.join(folder, b"inside"), "wb"):
    pass
os.symlink(b"token=" + SECRETS[10].encode(), os.path.join(base, b"H18-link"))
tags = [name[:3].decode() for name in NAMES] + ["H17", "H18"]
print(json.dumps({"tags": sorted(tags), "secrets": SECRETS}))
