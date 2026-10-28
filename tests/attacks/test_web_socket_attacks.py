"""T12c (invariant 7): the web's narrow socket, against a REAL installation in a clean VM.

The installed service opens ``/var/lib/backtide/web.sock`` (0660, root's, group backtide-web) for
the web. This scenario plays everyone else who could try it: the agent from its jail, a process of
the host with the agent's ids, a process that only has the web's group as a supplementary one
(so the kernel's ``SO_PEERCRED`` gid is not the web's), and the web's own user asking for what is
not on the list or with forged ids. Like tests/attacks/test_install_attacks.py, it never runs in
vigia-dev nor on the Mac (``instalada``). In a clean VM, after `install.sh`, as root:

    sudo uv run --locked pytest -m ataques -p no:cacheprovider \\
        tests/attacks/test_web_socket_attacks.py

It only sends requests the service should refuse or answer without changing anything (a forged
id is an id that does not exist); if the list failed, the export's folder is removed at the end
and the scenario checks the agent still runs. Nothing leaves the VM.
"""

import grp
import json
import os
import pwd
import secrets
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from attack_kit import Attack, scenario
from test_install_attacks import Installed, agent_running, open_installed, sh, wait

from backtide.jail.config import AGENT_GID, AGENT_UID
from backtide.service.config import STATE_SOCKET, STATE_WEB_SOCKET
from backtide.setup import layout
from backtide.snapshots import Snapshot

pytestmark = pytest.mark.instalada
WEB_SOCKET = layout.STATE_DIR / STATE_WEB_SOCKET
CONTROL_SOCKET = layout.STATE_DIR / STATE_SOCKET

# One JSON request per line in argv[2:], each on its own connection; what comes back is either
# the service's reply (outcome and ok only) or the errno of connecting. Plain sockets: nothing of
# backtide runs as the probe.
PROBE = """
import errno, json, socket, sys
path, out = sys.argv[1], []
for line in sys.argv[2:]:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(20)
            sock.connect(path)
            sock.sendall(line.encode() + b"\\n")
            sock.shutdown(socket.SHUT_WR)
            raw = b""
            while chunk := sock.recv(65536):
                raw += chunk
        reply = json.loads(raw)
        out.append({"outcome": reply.get("outcome"), "ok": reply.get("ok"),
                    "n": len(reply.get("snapshots") or [])})
    except OSError as e:
        out.append({"errno": errno.errorcode.get(e.errno, str(e.errno))})
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def installed() -> object:
    yield from open_installed()


def probe_as(uid: int, gid: int, groups: str, path: str, *requests: dict) -> list[dict]:
    """The probe as ``uid``:``gid`` with exactly ``groups`` as supplementary groups."""
    group_args = ["--clear-groups"] if not groups else ["--groups", groups]
    ran = sh(
        "setpriv", "--reuid", str(uid), "--regid", str(gid), *group_args, "--",
        "python3", "-I", "-c", PROBE, path, *(json.dumps(r) for r in requests),
        check=False, timeout=180,
    )  # fmt: skip
    lines = ran.stdout.strip().splitlines()
    return json.loads(lines[-1]) if lines else [{"error": ran.stderr.strip()[-300:]}]


def forged_snapshot(installed: Installed) -> str:
    """A well-formed snapshot id that is not in the volume's list (one from 2001)."""
    candidate = Snapshot(datetime(2001, 1, 1, tzinfo=UTC), "periodic").id
    assert candidate not in {s.id for s in installed.store.snapshots()}
    return candidate


@scenario("socket-estrecho-de-la-web")
def test_only_the_web_uses_its_socket_and_only_for_its_list(
    attack: Attack, installed: Installed
) -> None:
    web = pwd.getpwnam(layout.WEB_USER)
    web_gid = grp.getgrnam(layout.WEB_USER).gr_gid
    nobody = pwd.getpwnam("nobody")
    head = installed.box.head()
    since = head[0] if head is not None else 0
    forged_id = forged_snapshot(installed)
    forged_hold = "h-" + secrets.token_hex(6)
    path = str(WEB_SOCKET)
    # Never written (the list refuses `export`); if it were, it is removed at the end.
    nowhere = Path("/root") / f"t12c-fuera-{secrets.token_hex(4)}"

    # 0. The socket as the service left it: root's, 0660, the web's group.
    info = os.lstat(WEB_SOCKET)
    socket_file = (
        stat.S_ISSOCK(info.st_mode),
        info.st_uid,
        info.st_gid == web_gid,
        oct(stat.S_IMODE(info.st_mode)),
    )
    # 1. The agent: from its jail the socket is not there at all.
    jail = installed.jail.exec(
        ["sh", "-c", f"[ -e {path} ] || [ -L {path} ] && echo visible || echo absent"],
        timeout=30,
    )
    agent_in_jail = jail.stdout.strip()
    # 2. The agent's ids on the host (as if it escaped): the state folder does not let it in.
    agent_on_host = probe_as(AGENT_UID, AGENT_GID, "", path, {"cmd": "holds"})
    # 3. The agent's uid WITH the web's group as its own (it gets through the folder): the
    # service refuses the agent's uid whatever its group.
    agent_with_group = probe_as(AGENT_UID, web_gid, "", path, {"cmd": "holds"})
    # 4. The web's group only as a supplementary group: the file lets it connect, the service
    # refuses it (the kernel's SO_PEERCRED gid is nobody's).
    side_group = probe_as(nobody.pw_uid, nobody.pw_gid, str(web_gid), path, {"cmd": "holds"})
    # 5. Somebody who switched to the web's group (`sg backtide-web`): the right gid, not the
    # web's user.
    switched = probe_as(nobody.pw_uid, web_gid, "", path, {"cmd": "holds"})
    # 6. The web's own user: outside the list, the wrong origin, forged ids; and the control.
    outside = [
        {"cmd": "resume"},
        {"cmd": "shell", "kind": "session", "continue": False},
        {"cmd": "export", "dest": str(nowhere)},
        {
            "cmd": "import",
            "name": "x",
            "source": "/etc",
            "files": 1,
            "bytes": 1,
            "replace": True,
            "secrets_left_out": 0,
            "include_secrets": True,
        },  # fmt: skip
        {"cmd": "config", "path": "/etc/backtide/backtide.toml"},
        {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve", "via": "telegram"},
        # The control socket takes `cli`: only the web's filter refuses these two.
        {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve", "via": "cli"},
        {"cmd": "rewind", "snapshot_id": forged_id, "via": "cli"},
        {"cmd": "rewind", "snapshot_id": "../../etc"},
    ]
    forged = [
        {"cmd": "rewind", "snapshot_id": forged_id},
        {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve"},
    ]
    control = [{"cmd": "snapshots"}, {"cmd": "holds"}]
    try:
        as_web = probe_as(web.pw_uid, web.pw_gid, "", path, *outside, *forged, *control)
    finally:
        exported = nowhere.exists()
        shutil.rmtree(nowhere, ignore_errors=True)
    root_socket = probe_as(web.pw_uid, web.pw_gid, "", str(CONTROL_SOCKET), {"cmd": "holds"})
    still_running = agent_running(installed)

    said_outside, said_forged = as_web[: len(outside)], as_web[len(outside) : -len(control)]
    said_control = as_web[-len(control) :]
    refused = [{"outcome": "refused", "ok": False, "n": 0}]
    ok = (
        socket_file == (True, 0, True, "0o660")
        and agent_in_jail == "absent"
        and agent_on_host == [{"errno": "EACCES"}]
        and agent_with_group == refused
        and side_group == refused
        and switched == refused
        # "invalid" is the control socket's own word for an id that is not a snapshot id.
        and all(r.get("outcome") == "refused" and r.get("ok") is False for r in said_outside[:-1])
        and said_outside[-1].get("outcome") in ("refused", "invalid")
        and said_outside[-1].get("ok") is False
        and said_forged[0].get("outcome") == "invalid"
        and said_forged[1].get("outcome") == "unknown"
        and said_control[0].get("outcome") == "listed"
        and said_control[0].get("n", 0) >= 1
        and said_control[1].get("outcome") == "listed"
        and root_socket == [{"errno": "EACCES"}]
        and not exported
        and still_running
    )
    attack.check(
        "stopped",
        ok,
        f"el socket (es socket, uid, grupo de la web, modo): {socket_file}; desde la jaula, "
        f"{path}: {agent_in_jail}; con los ids del agente en el anfitrión: {agent_on_host}; con "
        f"el uid del agente y el grupo de la web: {agent_with_group}; con backtide-web solo como "
        f"grupo suplementario: {side_group}; con el grupo de la web como propio pero otro "
        f"usuario (sg): {switched}; como backtide-web, fuera de la lista: "
        f"{[r.get('outcome') for r in said_outside]}; con un id de instantánea y uno de "
        f"petición inventados: {said_forged}; control, la lista de instantáneas y las "
        f"retenidas: {said_control}; el socket de control de root: {root_socket}; nada "
        f"exportado ({not exported}) y el agente sigue en marcha ({still_running})",
    )

    # The refusals reach the black box through the log bridge, on its own thread and once a
    # minute per kind of message: while one of the two kinds that matter is not there since
    # the probes began, cause it again (an earlier run in the same minute may hold the slot).
    kinds = {
        "refused a connection from uid": lambda: probe_as(
            nobody.pw_uid, nobody.pw_gid, str(web_gid), path, {"cmd": "holds"}
        ),
        "refused a command outside its list": lambda: probe_as(
            web.pw_uid, web.pw_gid, "", path, {"cmd": "resume"}
        ),
    }

    def recorded_templates() -> set[str]:
        return {
            kind
            for e in installed.box.events(source="system", since_seq=since)
            if e.action == "log" and e.target == "backtide.service.web_control"
            for kind in kinds
            if kind in str(e.details.get("template", ""))
        }

    def both_recorded() -> bool:
        missing = set(kinds) - recorded_templates()
        for kind in missing:
            kinds[kind]()
        return not missing

    wait(both_recorded, 150, interval=5)
    # Nothing of it reached the Guardian as a change, and the refusals are in the black box.
    events = installed.box.events(since_seq=since)
    rewinds = [e for e in events if e.source == "snapshot" and e.action == "rewind_requested"]
    shells = [
        e for e in events if e.action in ("agent_shell", "export_started", "resume_requested")
    ]
    approved = [e for e in events if e.source == "gate" and e.action == "approved"]
    seen = recorded_templates()
    attack.check(
        "recorded",
        seen == set(kinds) and not rewinds and not shells and not approved,
        f"rechazos del socket de la web en la caja negra: {sorted(seen)}; ningún rebobinado "
        f"pedido ({len(rewinds)}), ninguna shell, exportación ni reanudación ({len(shells)}) y "
        f"ninguna aprobación ({len(approved)})",
    )
