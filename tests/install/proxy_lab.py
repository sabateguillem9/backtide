"""The web behind the real nginx, left running for the founder's own passkey from the Mac (T26-4b).
Inside a backtide-limpia-* VM with the lab's cut only, as root, never on the Mac or vigia-dev.

    python -m tests.install.proxy_lab arrancar   # certificate, nginx, [web] public_origin
    python -m tests.install.proxy_lab parar      # all of it undone, the domain's keys too

It is what `tests/attacks/test_reverse_proxy_attacks.py` starts, the shipped file unchanged, with
nobody driving: `arrancar` prints what to do on the Mac. The name is made up and only the VM
answers it. The CA can sign that one name and its key was never written, and nothing here touches
the Mac: a throwaway Chrome profile believes the certificate and sends the name to an SSH tunnel.
"""

import platform
import shutil
import subprocess
import sys
from pathlib import Path

from backtide.service import passkeys as pk
from backtide.setup import layout
from tests import reverse_proxy_kit as kit
from tests import vm_gates

LAB = Path("/var/lib/backtide-lab/proxy")
SAVED = {
    layout.CONFIG_FILE: LAB / "backtide.toml.antes",
    layout.WEB_CONFIG_FILE: LAB / "web.toml.antes",
}
TUNNEL_PORT = 8443


def require_lab() -> None:
    if not vm_gates.is_clean_vm(platform.node(), sys.platform):
        raise SystemExit("only inside a backtide-limpia-* or backtide-prueba-* VM")
    marked = subprocess.run(vm_gates.lab_mark_argv(sudo=False), capture_output=True, check=False)  # noqa: S603 - fixed argv
    if marked.returncode != 0:
        raise SystemExit("no lab network cut here: run `instalar_lab.sh bloquear` first")


def restart() -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        ["systemctl", "restart", layout.SERVICE_UNIT, layout.WEB_UNIT],  # noqa: S607
        check=True,
        timeout=300,
    )


def arrancar() -> None:
    if LAB.exists():
        raise SystemExit(f"{LAB} is there: `parar` first")
    current = {path: path.read_bytes() for path in SAVED}
    if any(b"[web]" in text for text in current.values()):
        raise SystemExit("the installation already has a [web] table")
    LAB.mkdir(mode=0o700, parents=True)
    proxy = kit.start(LAB)
    table = f'\n[web]\npublic_origin = "{kit.DOMAIN_URL}"\n'.encode()
    for path, saved in SAVED.items():
        saved.write_bytes(current[path])
        path.write_bytes(current[path] + table)
    restart()
    spki = kit.certificate_spki(proxy.certs / kit.CERT_NAME)
    print(f"""nginx in front of the web, as {kit.DOMAIN_URL}. On the Mac, in two terminals:

  ssh -F ~/.lima/{platform.node().removeprefix("lima-")}/ssh.config -N \\
      -L {TUNNEL_PORT}:127.0.0.1:{kit.HTTPS_PORT} {platform.node()}

  open -na "Google Chrome" --args --user-data-dir="$(mktemp -d)" \\
      --host-resolver-rules="MAP {kit.DOMAIN} 127.0.0.1:{TUNNEL_PORT}" \\
      --ignore-certificate-errors-spki-list={spki}

In this VM, `sudo backtide enlace`, and open the link it prints in that Chrome: register a key, sign
out, and sign in with it. If Chrome will not offer a passkey with that flag, the other way is to
trust {proxy.ca} on the Mac, and add the name to its /etc/hosts: it can only sign that name.
Undo it with `python -m tests.install.proxy_lab parar`.""")


def parar() -> None:
    kit.stop()
    pk.path_of(layout.STATE_DIR, kit.DOMAIN).unlink(missing_ok=True)
    for path, saved in SAVED.items():
        if saved.exists():
            path.write_bytes(saved.read_bytes())
    restart()
    shutil.rmtree(LAB, ignore_errors=True)
    print("nginx removed, the configuration as it was, the domain's keys gone")


if __name__ == "__main__":
    commands = {"arrancar": arrancar, "parar": parar}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit(f"usage: python -m tests.install.proxy_lab {'|'.join(commands)}")
    require_lab()
    commands[sys.argv[1]]()
