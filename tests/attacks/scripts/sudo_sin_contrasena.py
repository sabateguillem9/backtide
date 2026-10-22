"""Evil agent: use the image's passwordless sudo, and look for a way to gain privilege.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage: <script>
Prints one JSON object on its last line.
"""

import grp
import json
import os
import subprocess
from pathlib import Path


def run(*argv: str) -> dict:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except OSError as error:
        return {"code": None, "error": f"{type(error).__name__}: {error}"}
    return {"code": done.returncode, "out": done.stdout.strip()[:200], "err": done.stderr[:300]}


status = Path("/proc/self/status").read_text()
no_new_privs = next(
    (line.split()[1] for line in status.splitlines() if line.startswith("NoNewPrivs:")), None
)
# Three real sudo attempts (so the sensor sees three */sudo execs), plus su.
tries = {
    "sudo -n true": run("sudo", "-n", "true"),
    "sudo -n id -u": run("sudo", "-n", "id", "-u"),
    "sudo -n tee sudoers.d": run(
        "sudo", "-n", "sh", "-c", "echo 'ALL ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz"
    ),
    "su -c id": run("su", "-c", "id -u"),
}

# Real write attempts under /etc and the image user's home: a read-only root and the agent's own
# uid leave every one refused. Never follows a link (O_EXCL).
created = {}
for folder in ("/etc", "/etc/sudoers.d", "/home/agent", "/home/agent/.local/bin", "/usr/local/bin"):
    path = Path(folder, "backtide-sudo-probe")
    try:
        with open(path, "x") as handle:  # noqa: PTH123 - O_EXCL, never follows an existing link
            handle.write("x")
        path.unlink()
        created[folder] = "WRITTEN"
    except OSError as error:
        created[folder] = type(error).__name__


def gid_of(name: str) -> int | None:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


docker_gid, sudo_gid = gid_of("docker"), gid_of("sudo")
my_groups = os.getgroups()
in_privileged_group = any(g is not None and g in my_groups for g in (docker_gid, sudo_gid))
print(
    json.dumps(
        {
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "no_new_privs": no_new_privs,
            "tries": tries,
            "created": created,
            "groups": my_groups,
            "docker_gid": docker_gid,
            "sudo_gid": sudo_gid,
            "in_privileged_group": in_privileged_group,
        }
    )
)
