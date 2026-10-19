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
- T07-5, in ``both``: passwords glued to their flag (``mysql -pS3cr3t``, ``sshpass -p``,
  ``redis-cli -a``, ``mongosh -p``, ``lftp -u user,pass``, ``smbclient -U user%pass``,
  ``curl -uuser:pass``), run as copies of ``true`` named like each tool (the rules go by the
  binary's name), the same tools inside ``sh -c`` with ``MYSQL_PWD=`` and ``SSHPASS=``, and
  values Tetragon wraps in quotes because they have spaces (``"--password=a b"``, ``env
  "DB_PASSWORD=a b"``) or a glued ``-bsessionid=…``.
The commands are harmless (``true``); only their arguments matter. Usage: <script> <marker>
[<workdir>] (the copies of ``true`` go in ``<workdir>``, inside the agent's workspace).
"""

import json
import os
import secrets as random
import shutil
import string
import subprocess
import sys

marker = sys.argv[1]
workdir = sys.argv[2] if len(sys.argv) > 2 else f"/workspace/work/secretos-{marker}"
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
    # T07-5: glued to their flag, by tool; inside scripts; wrapped in quotes by Tetragon.
    "mysql": word(),
    "mariadb_1": word(),
    "mariadb_2": word(),
    "sshpass": word(),
    "sshpass_glued": word(),
    "redis": word(),
    "mongo": word(),
    "lftp": word(),
    "smb": word(),
    "curl_glued": word(),
    "env_1": word(),
    "env_2": word(),
    "quoted_flag_1": word(),
    "quoted_flag_2": word(),
    "cookie_1": word(),
    "cookie_2": word(),
    "sh_mysql": word(),
    "sh_mysql_pwd": word(),
    "sh_sshpass": word(),
    "sh_sshpass_env": word(),
    "sh_redis": word(),
    # The review of T07-5: more tools, and values with spaces after user flags.
    "podman": word(),
    "ldap": word(),
    "zip": word(),
    "keygen": word(),
    "sqlplus": word(),
    "curl_cert": word(),
    "curl_spaced_1": word(),
    "curl_spaced_2": word(),
    "sql_identified": word(),
    "aws_config": word(),
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
# T07-5: each tool is a copy of `true` with the tool's name (the rules go by the binary's name;
# nothing here connects anywhere).
tools = os.path.join(workdir, "tools")
os.makedirs(tools, exist_ok=True)
tool: dict[str, str] = {}
for name in ("mysql", "mariadb-dump", "sshpass", "redis-cli", "mongosh", "lftp", "smbclient",
             "curl", "env", "podman", "ldapsearch", "zip", "ssh-keygen", "sqlplus",
             "aws"):  # fmt: skip
    tool[name] = os.path.join(tools, name)
    shutil.copy(shutil.which("true") or "/bin/true", tool[name])
    os.chmod(tool[name], 0o755)  # noqa: S103 - the agent makes its copy runnable
b = both
commands += [
    [tool["mysql"], f"glued-{marker}", "-uroot", f"-p{b['mysql']}", "shop"],
    [tool["mariadb-dump"], f"-p{b['mariadb_1']} {b['mariadb_2']}", "shop"],
    [tool["sshpass"], "-p", b["sshpass"], "ssh", "host.invalid"],
    [tool["sshpass"], f"-p{b['sshpass_glued']}", "ssh", "host.invalid"],
    [tool["redis-cli"], "-h", "cache.invalid", f"-a{b['redis']}", "ping"],
    [tool["mongosh"], "-u", "admin", "-p", b["mongo"], "--quiet"],
    [tool["lftp"], "-u", f"alice,{b['lftp']}", "sftp://host.invalid"],
    [tool["smbclient"], "//host.invalid/share", "-U", f"alice%{b['smb']}"],
    [tool["curl"], f"-ualice:{b['curl_glued']}", "https://example.invalid/"],
    [tool["env"], f"DB_PASSWORD={b['env_1']} {b['env_2']}", "run"],
    ["true", f"--password=pass phrase {b['quoted_flag_1']} {b['quoted_flag_2']}", "x"],
    ["true", f"-bsessionid={b['cookie_1']};csrftoken={b['cookie_2']}", "https://x.invalid/"],
    [
        "sh", "-c",
        f"true {marker}; mysql -uroot -p{b['sh_mysql']} shop 2>/dev/null; "
        f"MYSQL_PWD={b['sh_mysql_pwd']} true",
    ],
    [
        "sh", "-c",
        f"true {marker}; sshpass -p {b['sh_sshpass']} ssh h.invalid 2>/dev/null; "
        f"SSHPASS={b['sh_sshpass_env']} true; redis-cli -a {b['sh_redis']} ping 2>/dev/null; true",
    ],
    [tool["podman"], "login", "-u", "me", "-p", b["podman"], "registry.invalid"],
    [tool["ldapsearch"], "-x", "-D", "cn=admin", "-w", b["ldap"], "-b", "dc=x"],
    [tool["zip"], "-P", b["zip"], "out.zip", "a.txt"],
    [tool["ssh-keygen"], "-t", "ed25519", "-N", b["keygen"], "-f", "key"],
    [tool["sqlplus"], f"scott/{b['sqlplus']}@orcl", "@run.sql"],
    [tool["curl"], "-E", f"cert.pem:{b['curl_cert']}", "https://example.invalid/"],
    [tool["curl"], "-u", f"alice:{b['curl_spaced_1']} {b['curl_spaced_2']}", "https://x.invalid/"],
    [tool["mysql"], "-e", f"CREATE USER u IDENTIFIED BY '{b['sql_identified']}'"],
    [tool["aws"], "configure", "set", "aws_secret_access_key", b["aws_config"]],
]  # fmt: skip

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
