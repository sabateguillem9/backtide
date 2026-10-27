"""The Mac's VM (T13b; review of T13b): neither the agent nor the VM's forwarding reaches the Mac.

Scenarios of a REAL installation made by install-mac.sh, in a Mac lab VM (backtide-prueba-*,
tests/install/instalar_mac_lab.sh), as root, with backtide running and the web forwarded. On a
Mac, Lima gives the VM the host at 192.168.5.2: from the VM that address is the Mac's own
127.0.0.1. That is used here twice: to see from inside what Lima forwards (a port forwarded to the
Mac's 127.0.0.1 answers at 192.168.5.2), and as the place the agent must not reach.

    sudo env BACKTIDE_LAB_HOST_PORT=<the web's port on the Mac> uv run --locked pytest -m ataques \\
        -p no:cacheprovider tests/attacks/test_mac_vm_attacks.py

They are skipped anywhere else, saying so (a Linux clean VM has no Mac behind it).
"""

import errno
import json
import os
import platform
import socket
import struct
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from attack_kit import Attack, scenario
from test_install_attacks import Installed, open_installed, sh

from backtide.jail import docker as jail_docker
from tests import vm_gates

pytestmark = [
    pytest.mark.instalada,
    pytest.mark.skipif(
        not platform.node().startswith(vm_gates.MAC_TEST_VM_PREFIX) or sys.platform != "linux",
        reason="only in a Mac lab VM (backtide-prueba-*): a Linux VM has no Mac behind it",
    ),
]
MAC = "192.168.5.2"  # Lima's address for the host: the Mac's 127.0.0.1, seen from the VM
WEB_PORT = 8765  # backtide-web.service, on the VM's 127.0.0.1
HOST_PORT = int(os.environ.get("BACKTIDE_LAB_HOST_PORT", str(WEB_PORT)))
POLL = 12.0  # Lima's guest agent reports new listeners within a few seconds
SHARED_TYPES = ("virtiofs", "9p", "fuse.sshfs", "nfs", "nfs4", "cifs", "smb3")


@pytest.fixture(scope="module")
def installed() -> Iterator[Installed]:
    yield from open_installed()


def tcp_to_the_mac(port: int) -> str:
    """Connect from the VM to the Mac's 127.0.0.1:``port``; what happened."""
    try:
        with socket.create_connection((MAC, port), timeout=5) as conn:
            conn.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1:8765\r\n\r\n")
            return conn.recv(64).decode(errors="replace").split("\r\n", 1)[0] or "CONNECTED"
    except OSError as error:
        return errno.errorcode.get(error.errno or 0, type(error).__name__)


@scenario("la-vm-no-reenvia-al-mac")
def test_only_the_web_is_forwarded_to_the_mac(attack: Attack, installed: Installed) -> None:
    # The would-be leak: a program in the VM (the agent's proxy, a debug server, Docker) listens
    # on a port, and Lima opens it on the Mac too. Listeners on every kind of address, TCP and UDP.
    binds = [("127.0.0.1", socket.AF_INET), ("0.0.0.0", socket.AF_INET), ("::", socket.AF_INET6)]  # noqa: S104
    sockets: list[tuple[str, str, int, socket.socket]] = []
    for address, family in binds:
        for kind, name in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
            sock = socket.socket(family, kind)
            sock.bind((address, 0))
            if kind == socket.SOCK_STREAM:
                sock.listen()
            sockets.append((name, address, sock.getsockname()[1], sock))
    received: list[str] = []

    def drain(sock: socket.socket, label: str) -> None:
        sock.settimeout(1.0)
        end = time.monotonic() + POLL + 10
        while time.monotonic() < end:
            try:
                sock.recvfrom(64)
                received.append(label)
            except OSError:
                pass

    threads = [
        threading.Thread(target=drain, args=(s, f"udp {a}:{p}"), daemon=True)
        for kind, a, p, s in sockets if kind == "udp"
    ]  # fmt: skip
    for thread in threads:
        thread.start()
    try:
        time.sleep(POLL)  # give Lima's guest agent its turn to see them
        tcp = {f"{a}:{p}": tcp_to_the_mac(p) for kind, a, p, _ in sockets if kind == "tcp"}
        # UDP: if Lima forwarded it, a datagram to the Mac's port would come back to our listener.
        for kind, _a, p, _ in sockets:
            if kind == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
                    out.sendto(b"backtide-lab", (MAC, p))
        time.sleep(3)
        control = tcp_to_the_mac(HOST_PORT)
    finally:
        for _, _, _, sock in sockets:
            sock.close()
    attack.check(
        "stopped",
        all(v == "ECONNREFUSED" for v in tcp.values())
        and received == []
        and control.startswith("HTTP/1.1 "),
        f"con {len(sockets)} escuchas en la VM (TCP y UDP en 127.0.0.1, 0.0.0.0 y [::]) y "
        f"{POLL:.0f} s para que el agente de Lima las vea, el Mac no tiene ninguna: por TCP, "
        f"{tcp} desde la VM al 127.0.0.1 del Mac ({MAC}); por UDP, de {len(threads)} datagramas "
        f"mandados a esos puertos del Mac no volvió ninguno a la VM ({received or 'nada'}). "
        f"Control: el puerto de la web en el Mac ({HOST_PORT}) sí llega a la web de la VM: "
        f"{control!r}",
    )


@scenario("sin-carpetas-del-mac")
def test_no_mac_folder_in_the_vm_nor_in_the_jail(attack: Attack, installed: Installed) -> None:
    listed = sh("findmnt", "-rn", "-o", "TARGET,FSTYPE", check=False)
    shared_vm = [line for line in listed.stdout.splitlines() if line.split(" ")[-1] in SHARED_TYPES]
    pid = int(
        jail_docker.run(
            [
                "container",
                "inspect",
                "--format",
                "{{.State.Pid}}",
                installed.config.jail_config().name,
            ]
        ).stdout.strip()
    )
    jail_mounts = Path(f"/proc/{pid}/mounts").read_text().splitlines()
    shared_jail = [m for m in jail_mounts if m.split()[2] in SHARED_TYPES or "lima-cidata" in m]
    attack.check(
        "stopped",
        listed.returncode == 0
        and any(line.startswith("/ ") for line in listed.stdout.splitlines())
        and shared_vm == []
        and len(jail_mounts) > 5
        and shared_jail == [],
        f"en la VM, {len(listed.stdout.splitlines())} montajes y ninguno de "
        f"{', '.join(SHARED_TYPES)} ({shared_vm or 'ninguno'}; control: findmnt ve la raíz); en "
        f"la jaula (pid {pid}), {len(jail_mounts)} montajes y ninguno de esos tipos ni el disco "
        f"de configuración de Lima ({shared_jail or 'ninguno'})",
    )


def covers(route: list[str], address: str) -> bool:
    """Does a /proc/net/route line (interface, destination, mask; hex, little-endian) cover it?"""
    dest, mask = (struct.unpack("<I", bytes.fromhex(v))[0] for v in route[1:3])
    target = struct.unpack("<I", socket.inet_aton(address))[0]
    return target & mask == dest


@scenario("la-carcel-no-llega-al-mac")
def test_the_jail_cannot_reach_the_mac(attack: Attack, installed: Installed) -> None:
    proxy = installed.config.proxy_jail_config()
    info = json.loads(jail_docker.run(["container", "inspect", proxy.name]).stdout)[0]
    proxy_ip = info["NetworkSettings"]["Networks"][proxy.agent_network]["IPAddress"]
    # Control: from the VM the Mac is right there, the web's forwarded port answers.
    control = tcp_to_the_mac(HOST_PORT)
    attack.watch_service(installed)
    ports = sorted({22, 53, 80, 443, 11434, WEB_PORT, HOST_PORT})
    outcome = attack.run_script(
        installed.jail, "la_carcel_no_llega_al_mac", ",".join(map(str, ports)), MAC
    )
    web = attack.run_script(
        installed.jail, "web_desde_la_carcel", f"{WEB_PORT},{HOST_PORT}", proxy_ip, MAC
    )
    routes_to_the_mac = [r for r in outcome["routes"] if covers(r, MAC)]
    attack.check(
        "stopped",
        control.startswith("HTTP/1.1 ")
        and routes_to_the_mac == []
        and outcome["attempts"] >= len(ports)
        and outcome["not_unreachable"] == []
        and set(outcome["outcomes"]) <= {"ENETUNREACH", "EHOSTUNREACH"}
        and web["reached"] == []
        and web["answers"] == []
        and web["via_proxy_through"] == [],
        f"la jaula no tiene ruta que cubra {MAC} (sus rutas: {outcome['routes']}); "
        f"{outcome['attempts']} conexiones a los puertos {ports} del Mac ({MAC} y "
        f"host.lima.internal: {outcome['name']}) acaban en {outcome['outcomes']}, sin ruta y en "
        f"el acto; la sonda de la web desde la cárcel (puertos {WEB_PORT} y {HOST_PORT}, también "
        f"pidiéndoselo al proxy) no llega a nada ({web['reached'] or 'nada'}; el proxy deja pasar "
        f"{web['via_proxy_through'] or 'nada'}). Control: desde la VM, el Mac contesta en "
        f"{HOST_PORT}: {control!r}",
    )
    events = attack.recorded_connect(addr=MAC)
    attack.check(
        "recorded",
        bool(events),
        f"el sensor grabó {len(events)} intentos de conexión de la jaula a {MAC} (net/connect)",
    )
