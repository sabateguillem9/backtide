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
and the scenario checks the agent still runs. The exception is ``tarea-sin-sesion``, which gives
the agent real tasks to read: it first checks that no provider has a key or that the lab's network
cut is on (`instalar_lab.sh bloquear`), so no turn reaches one (invariant 8). Nothing leaves the VM.
"""

import grp
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from http.client import HTTPException
from pathlib import Path
from typing import Any

import pytest
from attack_kit import Attack, scenario
from test_install_attacks import (
    AGENT_WAIT,
    Installed,
    agent_running,
    open_installed,
    sh,
    wait,
)

from backtide.jail.config import AGENT_GID, AGENT_UID
from backtide.service.config import STATE_SOCKET, STATE_WEB_SOCKET
from backtide.service.control import (
    ask_secrets,
    ask_task_start,
    ask_task_stop,
    ask_web_end_all,
    ask_web_link,
)
from backtide.service.settings import PROVIDERS
from backtide.setup import layout
from backtide.snapshots import Snapshot

pytestmark = pytest.mark.instalada
CHANGES_WAIT = 31  # the narrow socket's changes: 10 at once, then one every 3 s
WEB_SOCKET = layout.STATE_DIR / STATE_WEB_SOCKET
CONTROL_SOCKET = layout.STATE_DIR / STATE_SOCKET

# One JSON request per line in argv[2:], each on its own connection; what comes back is either
# the service's reply (outcome and ok only) or the errno of connecting. Plain sockets: nothing of
# backtide runs as the probe. A session a reply opens (T26-3a) is kept, never printed, and put
# where a later request says "<session>"; one opened by a request with "_as": NAME is kept under
# that name too, for "<session:NAME>". {"_sleep": S} waits S seconds (T26-3a-2: expiry). A
# request with "_attestation", "_credential" and "_origin" gets, as its "answer", a browser's
# answer to the last options a reply carried (T26-3b-2): only its clientDataJSON depends on the
# challenge, and that needs nothing but the standard library. A request with "_see" shows the
# options and the session of its reply: to sign a challenge out here, with the test's own key
# (a signature needs more than the standard library), and go on with that session (T26-3c).
PROBE = """
import base64, errno, json, socket, sys, time
path, out, session, named, options = sys.argv[1], [], None, {}, None
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
for line in sys.argv[2:]:
    request = json.loads(line)
    if "_sleep" in request:
        time.sleep(request["_sleep"])
        out.append({"slept": request["_sleep"]})
        continue
    if "_attestation" in request and options is not None:
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"],
                             "origin": request.pop("_origin"), "crossOrigin": False}).encode()
        credential = request.pop("_credential")
        request["answer"] = json.dumps({"id": credential, "rawId": credential, "type": "public-key",
            "response": {"clientDataJSON": b64url(client),
                         "attestationObject": request.pop("_attestation")}})
    name = request.pop("_as", None)
    why = request.pop("_why", False)
    see = request.pop("_see", False)
    line = json.dumps(request)
    for key, value in named.items():
        line = line.replace(json.dumps("<session:" + key + ">"), json.dumps(value))
    if session is not None:
        line = line.replace('"<session>"', json.dumps(session))
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
        if isinstance(reply.get("options"), str):
            options = json.loads(reply["options"])
        if isinstance(reply.get("session"), str):
            session = reply["session"]
            if name is not None:
                named[name] = session
        said = {"outcome": reply.get("outcome"), "ok": reply.get("ok"),
                "n": len(reply.get("snapshots") or [])}
        if why:
            said["why"] = str(reply.get("message") or "")[:80]
        if see:
            said["options"], said["session"] = reply.get("options"), reply.get("session")
            said["csrf"], said["task"] = reply.get("csrf"), reply.get("task")
        out.append(said)
    except OSError as e:
        out.append({"errno": errno.errorcode.get(e.errno, str(e.errno))})
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def installed() -> object:
    yield from open_installed()


def probe_as(
    uid: int, gid: int, groups: str, path: str, *requests: dict, timeout: float = 180
) -> list[dict]:
    """The probe as ``uid``:``gid`` with exactly ``groups`` as supplementary groups."""
    group_args = ["--clear-groups"] if not groups else ["--groups", groups]
    ran = sh(
        "setpriv", "--reuid", str(uid), "--regid", str(gid), *group_args, "--",
        "python3", "-I", "-c", PROBE, path, *(json.dumps(r) for r in requests),
        check=False, timeout=timeout,
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
    # The forged ids go with a live session (T26-3a), from a link root asked for: what refuses
    # them is the service's check of the id, not the missing session.
    forged = [
        {"cmd": "rewind", "snapshot_id": forged_id, "session": "<session>"},
        {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve", "session": "<session>"},
    ]
    control = [{"cmd": "snapshots"}, {"cmd": "holds"}]
    signed = [{"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET)}]
    try:
        as_web = probe_as(
            web.pw_uid, web.pw_gid, "", path, *outside, *signed, *forged, *control,
            {"cmd": "session_end", "session": "<session>"},
        )  # fmt: skip
    finally:
        exported = nowhere.exists()
        shutil.rmtree(nowhere, ignore_errors=True)
    root_socket = probe_as(web.pw_uid, web.pw_gid, "", str(CONTROL_SOCKET), {"cmd": "holds"})
    still_running = agent_running(installed)

    said_outside = as_web[: len(outside)]
    said_signed = as_web[len(outside)]
    said_forged = as_web[len(outside) + 1 : len(outside) + 1 + len(forged)]
    said_control = as_web[-len(control) - 1 : -1]
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
        and said_signed.get("outcome") == "opened"
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


@scenario("web-tomada-sin-dueno")
def test_a_web_taken_over_changes_nothing_without_a_session(
    attack: Attack, installed: Installed
) -> None:
    """T26-3a: whoever runs code as `backtide-web` (the web taken over) has the narrow socket,
    but not a session: only root mints the one-time link (on its own socket), and every change
    wants a live session."""
    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    listed = [s.id for s in installed.store.snapshots()]
    assert listed, "the installed volume has no snapshot to aim at"
    forged_hold = "h-" + secrets.token_hex(6)
    budget_before = probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "budget"})
    # Each would change something real if it got through: a listed snapshot, a made-up key.
    changes = [
        {"cmd": "rewind", "snapshot_id": listed[-1]},
        {"cmd": "set_secret", "kind": "openai", "value": "sk-proj-" + "x" * 40},
        {"cmd": "clear_secret", "kind": "anthropic"},
        {"cmd": "set_budget", "daily_usd": "1"},
        {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve"},
        {"cmd": "trust", "hold_id": forged_hold},
        {"cmd": "untrust", "trust_id": "t-0a1b2c3d"},
        {"cmd": "end_batch", "rule_id": "b-01234567"},
        {"cmd": "accept_prices", "digest": "0123456789abcdef"},
    ]
    # 1. No session at all; 2. a made-up one; 3. ways to make one without root.
    bare = probe_as(web.pw_uid, web.pw_gid, "", path, *changes)
    made_up = probe_as(
        web.pw_uid, web.pw_gid, "", path, *({**c, "session": "s" * 43} for c in changes)
    )
    no_link = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "session_open", "token": "t" * 43},
        {"cmd": "web_link"},
        {"cmd": "session_end_all", "session": "s" * 43},
    )  # fmt: skip
    root_socket = probe_as(web.pw_uid, web.pw_gid, "", str(CONTROL_SOCKET), {"cmd": "web_link"})
    # 4. A session that ended: refused like none. 5. The control: a live session gets as far
    # as the service's own check of the id (a forged hold is "unknown"), so the refusals above
    # are the session's doing.
    ended = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET)},
        {"cmd": "session_end", "session": "<session>"},
        {**changes[0], "session": "<session>"},
    )  # fmt: skip
    live = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET)},
        {**changes[4], "session": "<session>"},
        {"cmd": "session_end", "session": "<session>"},
    )  # fmt: skip
    budget_after = probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "budget"})
    still_running = agent_running(installed)

    refused = {"outcome": "refused", "ok": False, "n": 0}
    ok = (
        bare == [refused] * len(changes)
        and made_up == [refused] * len(changes)
        and [r.get("outcome") for r in no_link] == ["refused"] * 3
        and root_socket == [{"errno": "EACCES"}]
        and [r.get("outcome") for r in ended] == ["opened", "ended", "refused"]
        and [r.get("outcome") for r in live] == ["opened", "unknown", "ended"]
        and budget_before == budget_after
        and still_running
    )
    attack.check(
        "stopped",
        ok,
        f"como backtide-web, los {len(changes)} cambios (rebobinar a una instantánea de la "
        f"lista, poner y quitar claves, el tope, aprobar, confiar, quitar confianzas y lotes, "
        f"precios) sin sesión: {[r.get('outcome') for r in bare]}; con una inventada: "
        f"{[r.get('outcome') for r in made_up]}; abrir una sin enlace, pedir un enlace por su "
        f"socket y cerrar todas sin sesión: {[r.get('outcome') for r in no_link]}; el socket de "
        f"control de root: {root_socket}; con una sesión ya cerrada: "
        f"{[r.get('outcome') for r in ended]}; control, con una sesión viva una petición "
        f"inventada llega a la comprobación del id: {[r.get('outcome') for r in live]}; el tope "
        f"no cambia ({budget_before == budget_after}) y el agente sigue ({still_running})",
    )

    # The refusals reach the black box through the log bridge (once a minute per kind): while
    # it is not there since the probes began, cause it again.
    kind = "refused a %s without a live session"

    def recorded() -> bool:
        seen = any(
            kind in str(e.details.get("template", ""))
            for e in installed.box.events(source="system", since_seq=since)
            if e.action == "log" and e.target == "backtide.service.web_control"
        )
        if not seen:
            probe_as(web.pw_uid, web.pw_gid, "", path, changes[0])
        return seen

    wait(recorded, 150, interval=5)
    events = installed.box.events(since_seq=since)
    rewinds = [e for e in events if e.source == "snapshot" and e.action == "rewind_requested"]
    settings = [e for e in events if e.action in ("secret_set", "secret_cleared", "budget_set")]
    approved = [e for e in events if e.source == "gate" and e.action in ("approved", "trusted")]
    # Every way in, one by one (review of T26-3a): the two links root gave and the two sessions
    # they opened, with who asked and never a token or a session id.
    links = [e for e in events if e.source == "system" and e.action == "web_link_given"]
    entries = [e for e in events if e.source == "system" and e.action == "web_session_opened"]
    clean = all(
        not {"token", "session"} & set(e.details)
        and not any(isinstance(v, str) and len(v) >= 43 for v in e.details.values())
        for e in links + entries
    )
    # The other half (T26-3c): with a key registered, a live session that has not touched it.
    # The first key from a fresh session, as the owner would; then, without touching it, what
    # lasts is refused for that reason, and the keys and the sessions stay as they were.
    from backtide.service import passkeys as pk

    try:
        _, session = key_for_the_owner(web, path)
        asked = [
            {"cmd": "set_secret", "kind": "openai", "value": "sk-proj-" + "x" * 40},
            {"cmd": "clear_secret", "kind": "anthropic"},
            {"cmd": "trust", "hold_id": forged_hold},
            {"cmd": "session_end_all"},
            {"cmd": "passkey_begin"},
        ]
        time.sleep(CHANGES_WAIT)
        untouched = probe_as(
            web.pw_uid, web.pw_gid, "", path,
            *({**r, "session": session, "_why": True} for r in asked),
            {"cmd": "session_check", "session": session},
        )  # fmt: skip
        words = [r.get("why", "") for r in untouched[:-1]]
        keys_after = [k.id for k in pk.Passkeys(
            layout.STATE_DIR, origins=[pk.origin_for(pk.WEB_PORT)]).keys()]  # fmt: skip
        untouched_recorded = recorded_in_time(
            installed, since, "without the passkey touched",
            lambda: probe_as(web.pw_uid, web.pw_gid, "", path, {**asked[2], "session": session}),
        )  # fmt: skip
    finally:
        pk.path_of(layout.STATE_DIR).unlink(missing_ok=True)
    attack.check(
        "stopped",
        all("tocar tu llave" in word for word in words)
        and untouched[-1].get("outcome") == "live"
        and len(keys_after) == 1
        and untouched_recorded,
        f"con una llave y una sesión viva sin tocarla, poner y quitar claves, confiar, cerrar "
        f"todas y añadir otra llave: {words}; la sesión sigue ({untouched[-1].get('outcome')}), "
        f"la llave sigue siendo una ({len(keys_after)}) y el rechazo está en la caja negra "
        f"({untouched_recorded})",
    )
    attack.check(
        "recorded",
        recorded()
        and not rewinds
        and not settings
        and not approved
        and len(links) >= 2
        and len(entries) >= 2
        and clean,
        f"el rechazo sin sesión está en la caja negra ({recorded()}); ningún rebobinado "
        f"({len(rewinds)}), ningún cambio de claves ni de topes ({len(settings)}) y ninguna "
        f"aprobación ni confianza ({len(approved)}); cada enlace dado ({len(links)}, al menos 2) "
        f"y cada entrada ({len(entries)}, al menos 2) con su evento, sin token ni id ({clean})",
    )


def _lab_network_cut() -> bool:
    """Is the clean lab's cut on? Then what a container sends stops at the VM, and the lab's key,
    which it made up itself, reaches no provider."""
    done = subprocess.run(
        ["nft", "list", "table", "inet", "backtide_lab"], capture_output=True, text=True
    )
    return done.returncode == 0 and "drop" in done.stdout


@scenario("tarea-sin-sesion")
def test_no_task_and_no_answer_without_a_session(attack: Attack, installed: Installed) -> None:
    """T26-5a: who runs code as `backtide-web` can neither give the agent a task nor read an answer
    without a live session. The answers are not in the black box, so they are the one read of this
    socket that takes a session. The task whose answer it asks for is real, given by root, and the
    control is that a live session reads that very task and gives one of its own."""
    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    marker = f"T26-5A-{secrets.token_hex(8)}"
    keys = ask_secrets(CONTROL_SOCKET)
    keyed = [kind for kind in PROVIDERS if keys.get(kind, {}).get("set")]
    assert not keyed or _lab_network_cut(), (
        f"invariant 8: this scenario gives the agent a turn, {keyed} has a key, and this VM does "
        "not have the lab's network cut (tests/install/instalar_lab.sh bloquear)"
    )
    real = ask_task_start(CONTROL_SOCKET, f"{marker}-root di hola", seconds=120)
    assert real["ok"], real
    real_id = real["task"]

    def probe(*requests: dict) -> list[dict]:
        return probe_as(web.pw_uid, web.pw_gid, "", path, *requests)

    start = {"cmd": "task_start", "prompt": f"{marker}-sin-sesion borra todo", "_why": True}
    read = {"cmd": "task_status", "task": real_id, "_why": True}
    stop = {"cmd": "task_stop", "task": real_id, "_why": True}
    time.sleep(CHANGES_WAIT)
    # 1. Without a session, with a made-up one and with one that ended; and what is not on the list.
    bare = probe(start, read)
    made_up = probe({**start, "session": "s" * 43}, {**read, "session": "s" * 43})
    ended = probe(
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET)},
        {"cmd": "session_end", "session": "<session>"},
        {**start, "session": "<session>"},
        {**read, "session": "<session>"},
    )
    # 2. Stopping it (only Ctrl-C in the CLI, on root's socket) is off the list: with a session,
    # and without one, which a read would not refuse for its shape.
    # 3. The control: a live session reads the same task, and gives one as the web.
    live = probe(
        {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET)},
        {**read, "session": "<session>"},
        {"cmd": "task_status", "task": "f" * 32, "session": "<session>"},
        {**stop, "session": "<session>"},
        stop,
        {"cmd": "task_start", "prompt": f"{marker}-con-sesion di hola", "seconds": 120,
         "session": "<session>", "_see": True},
        {"cmd": "session_end", "session": "<session>"},
    )  # fmt: skip
    web_id = live[5].get("task")
    root_socket = probe_as(
        web.pw_uid, web.pw_gid, "", str(CONTROL_SOCKET), {"cmd": "task_status", "task": real_id}
    )
    for task in (real_id, web_id):
        if task:  # no need for them to end by themselves: their end is what is looked at below
            ask_task_stop(CONTROL_SOCKET, task)

    def refused_for(replies: list[dict], word: str) -> bool:
        """Refused for this reason: a full bucket or a wrong shape says refused too."""
        return all(
            r.get("outcome") == "refused" and r.get("ok") is False and word in r.get("why", "")
            for r in replies
        )

    says = [r.get("outcome") for r in live]
    attack.check(
        "stopped",
        len(bare) == 2
        and refused_for(bare, "sesión")
        and len(made_up) == 2
        and refused_for(made_up, "sesión")
        and [r.get("outcome") for r in ended[:2]] == ["opened", "ended"]
        and len(ended) == 4
        and refused_for(ended[2:], "sesión")
        and says[0] == "opened"
        and live[1].get("ok") is True
        and says[1] not in ("refused", "unknown")
        and says[2] == "unknown"
        and refused_for(live[3:5], "no se acepta")
        and says[5] == "started"
        and bool(web_id)
        and root_socket == [{"errno": "EACCES"}],
        f"como backtide-web, dar una tarea y leer la de root sin sesión: {bare}; con una "
        f"inventada: {made_up}; con una ya cerrada: {[r.get('outcome') for r in ended]}; con una "
        f"viva (el control), abrir, leer esa tarea, un id inventado, pararla con y sin ella y "
        f"dar una: {says}, por {[r.get('why') for r in live[3:5]]}; "
        f"el socket de root: {root_socket}",
    )

    def ended_events() -> list[Any]:
        return [e for e in installed.box.events(since_seq=since) if e.action == "agent_task_end"]

    wait(lambda: len(ended_events()) >= 2, 120, interval=2)
    refused_recorded = recorded_in_time(
        installed,
        since,
        "refused a %s without a live session",
        lambda: probe(read),
        saying="task_status",
    )
    events = installed.box.events(since_seq=since)
    shells = [e for e in events if e.action == "agent_shell" and e.target == "task"]
    asked = {str(e.details.get("prompt", "")): e for e in shells}
    who = {prompt.split(" ")[0].removeprefix(f"{marker}-"): e for prompt, e in asked.items()}
    web_event = who.get("con-sesion")
    every = json.dumps([[e.target, e.details] for e in events], ensure_ascii=False, default=str)
    closed = {"task", "outcome", "code", "seconds", "answer_chars", "requested_by"}
    attack.check(
        "recorded",
        refused_recorded
        and "sin-sesion" not in every
        and "root" in who
        and web_event is not None
        and web_event.details.get("task") == web_id
        and str(web_event.details.get("requested_by", "")).startswith(f"web (uid {web.pw_uid},")
        and {e.details.get("task") for e in ended_events()} >= {real_id, web_id}
        and all(set(e.details) == closed for e in ended_events()),
        f"el rechazo está en la caja negra ({refused_recorded}); lo pedido sin sesión no está en "
        f"ningún evento ({'sin-sesion' not in every}); de las tareas de verdad: {sorted(who)}, la "
        f"de la web como web ({web_event.details if web_event else None}); cada final con sus "
        f"campos: {[sorted(e.details) for e in ended_events()]}",
    )


def restart_service(installed: Installed) -> None:
    """The service again, with the agent answering and the web's socket back."""
    sh("systemctl", "restart", layout.SERVICE_UNIT, timeout=300)
    assert wait(lambda: WEB_SOCKET.exists() and agent_running(installed), AGENT_WAIT), (
        "the service did not come back"
    )


@scenario("sesion-caducada")
def test_a_session_dies_unused_after_its_time_and_when_root_closes_them(
    attack: Attack, installed: Installed
) -> None:
    """T26-3a-2: the limits shortened to 60 s unused and 120 s in all ([web] in the service's
    config, which can only shorten them), then restored."""
    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    original = layout.CONFIG_FILE.read_bytes()
    assert b"[web]" not in original, "the installation already has a [web] table"
    forged_hold = "h-" + secrets.token_hex(6)
    results: dict[str, list[dict]] = {}

    def probe(name: str, *requests: dict) -> None:
        results[name] = probe_as(web.pw_uid, web.pw_gid, "", path, *requests, timeout=400)

    def opened(since: int, count: int) -> None:
        """Wait until the probes have spent ``count`` links: only one link lives at a time, so
        the next is given (or all are closed) once the last was used (review of T26-3a-2)."""

        def spent() -> bool:
            events = installed.box.events(since_seq=since)
            return sum(e.action == "web_session_opened" for e in events) >= count

        assert wait(spent, 60, interval=0.5), f"the probes did not open {count} sessions"

    try:
        layout.CONFIG_FILE.write_bytes(
            original + b"\n[web]\nsession_idle_seconds = 60\nsession_lifetime_seconds = 120\n"
        )
        restart_service(installed)
        head = installed.box.head()
        since = head[0] if head is not None else 0
        # 1. Left alone: dead after its minute unused, and then a change with it is refused.
        quiet = threading.Thread(target=probe, args=("quiet",
            {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_as": "q"},
            {"cmd": "session_check", "session": "<session:q>"},
            {"_sleep": 65},
            {"cmd": "session_check", "session": "<session:q>"},
            {"cmd": "decide", "hold_id": forged_hold, "verdict": "approve",
             "session": "<session:q>"},
        ))  # fmt: skip
        quiet.start()
        opened(since, 1)
        # 2. Used every 30 s: alive past the minute, dead at its two minutes all the same.
        busy = threading.Thread(target=probe, args=("busy",
            {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_as": "b"},
            *[r for _ in range(3) for r in ({"_sleep": 30},
                                            {"cmd": "session_check", "session": "<session:b>"})],
            {"_sleep": 32},
            {"cmd": "session_check", "session": "<session:b>"},
        ))  # fmt: skip
        busy.start()
        quiet.join(400)
        busy.join(400)
        # 3. Root closes them all on its own socket, while a session is live.
        closing = threading.Thread(target=probe, args=("closed",
            {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_as": "c"},
            {"cmd": "session_check", "session": "<session:c>"},
            {"_sleep": 10},
            {"cmd": "session_check", "session": "<session:c>"},
        ))  # fmt: skip
        closing.start()
        opened(since, 3)
        # The event is written before the probe has its answer: give it its first check
        # (it then sleeps 10 s) before root closes everything.
        time.sleep(2)
        ended = ask_web_end_all(CONTROL_SOCKET)
        closing.join(60)
        # 4. "Cerrar todas" from the web (what a web taken over could do): over the narrow
        # socket, from a live session, and recorded by the service like root's.
        probe(
            "web",
            {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_as": "w"},
            {"cmd": "session_end_all", "session": "<session:w>"},
            {"cmd": "session_check", "session": "<session:w>"},
        )
        events = installed.box.events(since_seq=since)
    finally:
        layout.CONFIG_FILE.write_bytes(original)
        restart_service(installed)

    def said(name: str) -> list[str | None]:
        return [r.get("outcome") for r in results.get(name, []) if "slept" not in r]

    closed = [e for e in events if e.source == "system" and e.action == "web_sessions_closed"]
    by_root = [e for e in closed if "uid" in e.details]
    by_web = [e for e in closed if "uid" not in e.details]
    ways_in = [
        e
        for e in events
        if e.source == "system"
        and e.action in ("web_link_given", "web_session_opened", "web_sessions_closed")
    ]
    # Invariant 5: who asked and how many, never a token or a session id.
    clean = all(set(e.details) <= {"uid", "pid", "ended", "via"} for e in ways_in)
    ok = (
        said("quiet") == ["opened", "live", "expired", "refused"]
        and said("busy") == ["opened", "live", "live", "live", "expired"]
        and said("closed") == ["opened", "live", "expired"]
        and said("web") == ["opened", "ended", "expired"]
        and ended >= 1
    )
    attack.check(
        "stopped",
        ok,
        f"con 60 s sin uso y 120 en total: una sesión quieta {said('quiet')} (viva, muerta "
        f"al minuto, y un cambio con ella rechazado); otra usada cada 30 s {said('busy')} "
        f"(viva pasado el minuto y muerta a los dos); `--cerrar-todas` por el socket de root "
        f"con una viva {said('closed')} ({ended} cerradas); «Cerrar todas» desde la web "
        f"{said('web')}; la configuración, como estaba",
    )
    attack.check(
        "recorded",
        len(by_root) >= 1
        and len(by_web) >= 1
        and all(e.details.get("ended", 0) >= 1 for e in closed)
        and clean,
        f"el cierre de todas las sesiones está en la caja negra, por root ({len(by_root)}) y "
        f"desde la web ({len(by_web)}), con cuántas; ningún token ni id en los "
        f"{len(ways_in)} eventos de entrada y salida ({clean})",
    )


LAB_PASSWORD = Path("/var/lib/backtide-lab/made-up.password")  # instalar_lab.sh's (T26-3b-1)


@scenario("contrasena-a-la-fuerza")
def test_guessing_the_webs_password_is_slow_and_leaves_a_trace(
    attack: Attack, installed: Installed
) -> None:
    """T26-3b-1: as the web's user, guess the password; read its file; then the right one."""
    from backtide.service import password

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    right = LAB_PASSWORD.read_text().strip()
    kept = password.path_of(layout.STATE_DIR)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    # 1. The file: root's, 0600 in a 0700 folder, only a hash; the web's user cannot read it.
    info, folder = os.stat(kept), os.stat(kept.parent)
    as_file = (info.st_uid, oct(stat.S_IMODE(info.st_mode)), oct(stat.S_IMODE(folder.st_mode)))
    hash_only = right not in kept.read_text() and password.matches(right, kept.read_text())
    read_as_web = sh(
        "setpriv", "--reuid", str(web.pw_uid), "--regid", str(web.pw_gid), "--clear-groups",
        "--", "cat", str(kept), check=False,
    )  # fmt: skip
    # 2. Guessing: five wrong ones are checked, then the bucket says wait, the right one too.
    guesses = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        *({"cmd": "session_password", "password": f"guess-number-{i:04d}-x"} for i in range(6)),
        {"cmd": "session_password", "password": right},
    )  # fmt: skip
    # 3. After the bucket's 12 s, the right one opens a session (then ended).
    time.sleep(13)
    entered = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "session_password", "password": right},
        {"cmd": "session_end", "session": "<session>"},
    )  # fmt: skip
    said = [r.get("outcome") for r in guesses]
    ok = (
        as_file == (0, "0o600", "0o700")
        and hash_only
        and read_as_web.returncode != 0
        and said == ["wrong"] * 5 + ["slow_down", "slow_down"]
        and [r.get("outcome") for r in entered] == ["opened", "ended"]
    )
    attack.check(
        "stopped",
        ok,
        f"el archivo de la contraseña (uid, modo, carpeta): {as_file}, solo su huella "
        f"({hash_only}), y backtide-web no lo lee ({read_as_web.returncode != 0}); adivinando: "
        f"{said} (cinco comprobadas, luego espera, también la buena); a los 12 s la buena: "
        f"{[r.get('outcome') for r in entered]}",
    )

    # The wrong ones reach the black box through the log bridge (once a minute per kind); the
    # entry is its own event.
    def recorded() -> bool:
        seen = any(
            "a wrong password for the web" in str(e.details.get("template", ""))
            for e in installed.box.events(source="system", since_seq=since)
            if e.action == "log"
        )
        if not seen:
            probe_as(web.pw_uid, web.pw_gid, "", path,
                     {"cmd": "session_password", "password": "one more wrong one"})  # fmt: skip
        return seen

    wait(recorded, 150, interval=5)
    events = installed.box.events(since_seq=since)
    opened = [
        e for e in events if e.action == "web_session_opened" and e.details.get("via") == "password"
    ]
    leaked = [e.seq for e in events if right in repr(e.details)]
    attack.check(
        "recorded",
        recorded() and len(opened) >= 1 and not leaked,
        f"las contraseñas equivocadas, en la caja negra ({recorded()}); la entrada con contraseña, "
        f"su evento ({len(opened)}); la contraseña en ningún evento ({leaked or 'ninguno'})",
    )


def soft_key(rp_id: str = "backtide.localhost") -> dict[str, str]:
    """A passkey made here, as the probe needs it: its id and its attestation object (the part
    of a browser's answer that does not depend on the challenge), for ``rp_id``."""
    from tests.passkey_kit import SoftAuthenticator

    options = json.dumps({"challenge": "AAAA", "rp": {"id": rp_id}})
    answer = json.loads(SoftAuthenticator().create(options, "http://backtide.localhost:8765"))
    return {"_credential": answer["id"], "_attestation": answer["response"]["attestationObject"]}


def key_for_the_owner(web: Any, path: str) -> tuple[Any, str]:
    """A session from a link root gives and, as the web's user, the first key registered with it:
    the key (made here, it signs) and the session."""
    from backtide.service import passkeys as pk
    from tests.passkey_kit import SoftAuthenticator

    owner = SoftAuthenticator()
    token = ask_web_link(CONTROL_SOCKET)
    opened, begun = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "session_open", "token": token, "_see": True},
        {"cmd": "passkey_begin", "session": "<session>", "_see": True},
    )  # fmt: skip
    assert begun.get("options"), f"no options to register a key: {begun}"
    answer = owner.create(begun["options"], pk.origin_for(pk.WEB_PORT))
    [added] = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        {"cmd": "passkey_finish", "session": opened["session"], "answer": answer,
         "name": "portátil", "_why": True},
    )  # fmt: skip
    assert added.get("outcome") == "added", f"the owner's key was not registered: {added}"
    return owner, opened["session"]


def recorded_in_time(
    installed: Installed, since: int, kind: str, cause: Callable[[], Any], *, saying: str = ""
) -> bool:
    """A refusal reaches the black box through the log bridge (once a minute per kind): while it
    is not there since the probes began (``saying`` this, if the template is shared), cause it
    again."""

    def seen() -> bool:
        found = any(
            kind in str(e.details.get("template", ""))
            and saying in str(e.details.get("message", ""))
            for e in installed.box.events(source="system", since_seq=since)
            if e.action == "log"
        )
        if not found:
            cause()
        return found

    wait(seen, 150, interval=5)
    return seen()


@scenario("firma-de-otro-sitio")
def test_a_signature_for_another_site_opens_nothing(attack: Attack, installed: Installed) -> None:
    """T26-3c: as the web's user (or a page that fooled a browser), sign in with a true key's
    signature made for another site, another port or another relying party, without the user
    verified, with a key that is not kept, and repeat a good one. Only the good one enters."""
    from backtide.service import passkeys as pk
    from tests.passkey_kit import SoftAuthenticator

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    origin = pk.origin_for(pk.WEB_PORT)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    time.sleep(CHANGES_WAIT)
    stranger = SoftAuthenticator()

    def attempt(signer: Any, at: str, **bend: Any) -> dict:
        [begun] = probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "auth_begin", "_see": True})
        answer = signer.get(begun["options"], at, **bend)
        finish = {"cmd": "auth_finish", "answer": answer, "_why": True, "_see": True}
        [said] = probe_as(web.pw_uid, web.pw_gid, "", path, finish)
        said["answer"] = answer
        return said

    try:
        owner, session = key_for_the_owner(web, path)
        bent = {
            "otro sitio": attempt(owner, "https://evil.example"),
            "otro puerto": attempt(owner, "http://backtide.localhost:9999"),
            "otro dominio": attempt(owner, origin, rp_id="evil.example"),
            "sin verificar": attempt(owner, origin, verified=False),
            "otra llave": attempt(stranger, origin),
        }
        time.sleep(13)  # the answers' bucket: 10 at once, then one every 6 s
        good = attempt(owner, origin)
        repeat = {"cmd": "auth_finish", "answer": good["answer"], "_why": True, "_see": True}
        [again] = probe_as(web.pw_uid, web.pw_gid, "", path, repeat)
        # A touch from another site does not count either: what lasts stays refused.
        [begun] = probe_as(web.pw_uid, web.pw_gid, "", path,
                           {"cmd": "touch_begin", "session": session, "_see": True})  # fmt: skip
        [touch] = probe_as(
            web.pw_uid, web.pw_gid, "", path,
            {"cmd": "touch_finish", "session": session, "_why": True,
             "answer": owner.get(begun["options"], "https://evil.example")},
        )  # fmt: skip
        time.sleep(CHANGES_WAIT)
        forged = {"cmd": "trust", "hold_id": "h-" + secrets.token_hex(6), "_why": True}
        [still] = probe_as(web.pw_uid, web.pw_gid, "", path, {**forged, "session": session})
        # The control: a good touch opens it (it reaches the check of the made-up id), and a
        # session born of signing in with the key has it open without touching.
        [begun] = probe_as(web.pw_uid, web.pw_gid, "", path,
                           {"cmd": "touch_begin", "session": session, "_see": True})  # fmt: skip
        [good_touch] = probe_as(
            web.pw_uid, web.pw_gid, "", path,
            {"cmd": "touch_finish", "session": session, "_why": True,
             "answer": owner.get(begun["options"], origin)},
        )  # fmt: skip
        [opened_by_touch] = probe_as(
            web.pw_uid, web.pw_gid, "", path, {**forged, "session": session}
        )
        [opened_by_entry] = probe_as(
            web.pw_uid, web.pw_gid, "", path, {**forged, "session": good["session"]}
        )
        recorded = recorded_in_time(
            installed, since, "a passkey did not sign in",
            lambda: attempt(owner, "https://evil.example"),
        )  # fmt: skip
        events = installed.box.events(since_seq=since)
    finally:
        pk.path_of(layout.STATE_DIR).unlink(missing_ok=True)
    reasons = {"otra llave": "no está registrada"}
    wrong = {name: r.get("why") for name, r in bent.items()
             if r.get("outcome") != "refused" or r.get("session")
             or reasons.get(name, "firma válida") not in str(r.get("why"))}  # fmt: skip
    ok = (
        not wrong
        and good.get("outcome") == "opened"
        and good.get("session")
        and again.get("outcome") == "refused"
        and not again.get("session")
        and "pendiente" in again.get("why", "")
        and touch.get("outcome") == "refused"
        and "firma válida" in touch.get("why", "")
        and "tocar tu llave" in still.get("why", "")
        and good_touch.get("outcome") == "touched"
        and "tocar tu llave" not in opened_by_touch.get("why", "tocar tu llave")
        and "tocar tu llave" not in opened_by_entry.get("why", "tocar tu llave")
    )
    attack.check(
        "stopped",
        bool(ok),
        f"una firma de otro sitio, otro puerto, otro dominio, sin verificar y con otra llave: "
        f"{ {n: r.get('outcome') for n, r in bent.items()} }, fuera de lo esperado "
        f"{wrong or 'ninguna'}; la buena: {good.get('outcome')}; repetirla: "
        f"{again.get('outcome')} ({again.get('why')}); un toque de otro sitio: "
        f"{touch.get('outcome')}, y lo que dura sigue pidiendo la llave: {still.get('why')}; "
        f"con un toque bueno ({good_touch.get('outcome')}) ya no: {opened_by_touch.get('why')}; y "
        f"la sesión de entrar con la llave tampoco: {opened_by_entry.get('why')}",
    )
    entries = [e for e in events if e.action == "web_session_opened"
               and e.details.get("via") == "passkey"]  # fmt: skip
    touches = [e for e in events if e.action == "web_passkey_touched"]
    attack.check(
        "recorded",
        recorded
        and len(entries) == 1
        and entries[0].details.get("name") == "portátil"
        and set(entries[0].details) <= {"pid", "via", "name", "tail"}
        and len(touches) == 1,
        f"los rechazos, en la caja negra ({recorded}); la única entrada con llave, su evento "
        f"con el nombre y el final de su id ({len(entries)}); el único toque bueno, el suyo "
        f"({len(touches)})",
    )


@scenario("llaves-a-la-fuerza")
def test_a_thousand_answers_are_not_even_looked_at(attack: Attack, installed: Installed) -> None:
    """T26-3c: mil respuestas de entrada seguidas, como la web tomada: las del cubo se comprueban
    y se rechazan, el resto ni se mira, y el dueño entra en cuanto el cubo se rellena."""
    from backtide.service import passkeys as pk

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    time.sleep(CHANGES_WAIT)
    try:
        owner, _ = key_for_the_owner(web, path)
        junk = {"cmd": "auth_finish", "answer": "{}", "_why": True}
        started = time.monotonic()
        said = probe_as(web.pw_uid, web.pw_gid, "", path, *([junk] * 1000), timeout=300)
        took = time.monotonic() - started
        looked = [r for r in said if "Demasiados" not in str(r.get("why", ""))]
        opened_any = [r for r in said if r.get("outcome") == "opened"]
        allowed = 10 + took / 6 + 1  # the bucket: 10 at once, then one every 6 s
        time.sleep(13)
        [begun] = probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "auth_begin", "_see": True})
        answer = owner.get(begun["options"], pk.origin_for(pk.WEB_PORT))
        [entered] = probe_as(web.pw_uid, web.pw_gid, "", path,
                             {"cmd": "auth_finish", "answer": answer})  # fmt: skip
        recorded = recorded_in_time(
            installed, since, "too many %s",
            lambda: probe_as(web.pw_uid, web.pw_gid, "", path, *([junk] * 30)),
        )  # fmt: skip
    finally:
        pk.path_of(layout.STATE_DIR).unlink(missing_ok=True)
    attack.check(
        "stopped",
        len(said) == 1000
        and len(looked) <= allowed
        and not opened_any
        and entered.get("outcome") == "opened",
        f"{len(said)} respuestas en {took:.0f} s: {len(looked)} comprobadas (como mucho "
        f"{allowed:.0f}), ninguna entra ({len(opened_any)}); el dueño, 13 s después: "
        f"{entered.get('outcome')}",
    )
    attack.check(
        "recorded", recorded, f"el aviso de tantos intentos, en la caja negra ({recorded})"
    )


@scenario("entrar-sin-llave")
def test_no_way_in_without_a_session(attack: Attack, installed: Installed) -> None:
    """T26-3c: the installed web by HTTP, at its own prefix: each page and each order without a
    session, with a made-up cookie and with the cookie of a session that ended. As the web's
    user, the key's commands too. Nothing opens, and no key appears."""
    from http.client import HTTPConnection

    from backtide.service import passkeys as pk
    from backtide.web.security import COOKIE_NAME

    prefix = web_prefix()
    base = f"/s/{prefix}"
    host = f"{pk.RP_ID}:{pk.WEB_PORT}"
    origin = pk.origin_for(pk.WEB_PORT)
    time.sleep(CHANGES_WAIT)

    def fetch(method: str, where: str, cookie: str | None = None, csrf: str = "x" * 43) -> int:
        conn = HTTPConnection("127.0.0.1", pk.WEB_PORT, timeout=20)
        headers = {"Host": host, "Origin": origin}
        if cookie is not None:
            headers["Cookie"] = f"{COOKIE_NAME}={cookie}"
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = order_form(where, csrf)
        conn.request(method, base + where, body=body, headers=headers)
        status = conn.getresponse().status
        conn.close()
        return status

    no_way_in(attack, fetch, pk.path_of(layout.STATE_DIR))


def order_form(where: str, csrf: str) -> str:
    """Exactly the fields its form asks for: any other says 403 too, even with a session."""
    more = {"/llaves/registrar": "&answer=x&name=x", "/tocar/responder": "&answer=x",
            "/llaves/quitar": "&ticket=x&llave=x",
            "/llaves/nombre": "&ticket=x&llave=x&nombre=x"}  # fmt: skip
    return f"csrf={csrf}{more.get(where, '')}"


def no_way_in(attack: Attack, fetch: Callable[..., int], keys_file: Path) -> None:
    """`entrar-sin-llave`, by whichever way ``fetch`` takes (method, path, the cookie's value,
    CSRF; it answers the status): the tunnel's names, or the domain's through the proxy (T26-4b)."""
    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    pages = ["/", "/ahora", "/instantaneas", "/peticiones", "/ajustes", "/llaves", "/tocar"]
    orders = ["/llaves/empezar", "/llaves/registrar", "/tocar/empezar", "/tocar/responder",
              "/llaves/quitar", "/llaves/nombre", "/ajustes/cerrar-sesiones", "/salir"]  # fmt: skip
    # Asked without a key, these say 404 with a session too: not in the control below, whose
    # POSTs of them get in (a ticket that is no good, 400).
    key_pages = ["/llaves/quitar", "/llaves/nombre"]
    # The control: the same requests with a live session do get in. "/salir" is left out: it
    # ends the session the rest of this needs, and then the same cookie and CSRF must not.
    request = {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_see": True}
    [opened] = probe_as(web.pw_uid, web.pw_gid, "", path, request)
    live, csrf = opened["session"], opened["csrf"]
    inside = {where: fetch("GET", where, live) for where in pages}
    inside |= {where: fetch("POST", where, live, csrf) for where in orders if where != "/salir"}
    probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "session_end", "session": live})
    shut_out = {f"GET {where}": fetch("GET", where, live) for where in (*pages, *key_pages)}
    shut_out |= {f"POST {where}": fetch("POST", where, live, csrf) for where in orders}
    results = {"cerrada, con su CSRF": shut_out}
    for name, cookie in (("sin cookie", None), ("inventada", "s" * 43)):
        results[name] = {
            f"GET {where}": fetch("GET", where, cookie) for where in (*pages, *key_pages)
        } | {f"POST {where}": fetch("POST", where, cookie) for where in orders}
    # Keys through the socket without a session: nothing to touch, nothing to add. After the
    # keys' bucket has had time to give back what the control above spent.
    time.sleep(CHANGES_WAIT)
    commands = probe_as(
        web.pw_uid, web.pw_gid, "", path,
        *({"cmd": c, "session": "s" * 43, "_why": True}
          for c in ("passkey_begin", "passkey_list", "touch_begin", "touch_status")),
        {"cmd": "touch_finish", "session": "s" * 43, "answer": "{}", "_why": True},
        {"cmd": "passkey_finish", "session": "s" * 43, "answer": "{}", "name": "x", "_why": True},
    )  # fmt: skip
    # With no key at all, a signature has nothing to sign.
    no_keys = probe_as(web.pw_uid, web.pw_gid, "", path, {"cmd": "auth_begin", "_why": True})
    let_in = {name: {w: s for w, s in found.items() if s != 401}
              for name, found in results.items()}  # fmt: skip
    let_in = {name: found for name, found in let_in.items() if found}
    not_inside = {w: s for w, s in inside.items() if s in (401, 403, 404, 405)}
    attack.check(
        "stopped",
        not let_in
        and not not_inside
        and all(
            r.get("outcome") == "refused" and "sesión viva" in r.get("why", "") for r in commands
        )
        and no_keys[0].get("outcome") == "refused"
        and not keys_file.exists(),
        f"{len(pages) + len(key_pages)} páginas y {len(orders)} órdenes sin cookie, con una "
        "inventada y con una "
        f"cerrada: las que no dicen 401: {let_in or 'ninguna'}; con una sesión viva, las que no "
        f"llegan: {not_inside or 'ninguna'}; las órdenes de llaves por "
        f"el socket: {[r.get('why') for r in commands]}; sin llaves no hay reto "
        f"({no_keys[0].get('why')}), y no aparece ninguna llave",
    )


def web_prefix() -> str:
    """The installed web's random prefix: from the link file root reads for `backtide enlace`."""
    return layout.WEB_LINK_FILE.read_text().splitlines()[0].rstrip("/").rsplit("/", 1)[-1]


@scenario("llave-perdida")
def test_a_lost_key_goes_with_its_sessions(attack: Attack, installed: Installed) -> None:
    """T26-3c: two keys; with the real `backtide llaves --quitar`, one goes. Its signature no longer
    signs in and every session ends; the other key still signs in. The web's user cannot ask for
    root's commands, by its socket or by root's; its own way, `key_remove`, has its own scenario
    (`quitar-llave-desde-la-web`)."""
    from backtide.service import passkeys as pk
    from tests.passkey_kit import SoftAuthenticator

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    origin = pk.origin_for(pk.WEB_PORT)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    time.sleep(CHANGES_WAIT)

    def ask(*requests: dict) -> list[dict]:
        return probe_as(web.pw_uid, web.pw_gid, "", path, *requests)

    def sign_in(signer: Any) -> dict:
        [begun] = ask({"cmd": "auth_begin", "_see": True})
        answer = signer.get(begun["options"], origin)
        [said] = ask({"cmd": "auth_finish", "answer": answer, "_why": True})
        return said

    try:
        lost, session = key_for_the_owner(web, path)
        # The second key, from a session that touched the first.
        [begun] = ask({"cmd": "touch_begin", "session": session, "_see": True})
        answer = lost.get(begun["options"], origin)
        [touch] = ask({"cmd": "touch_finish", "session": session, "answer": answer})
        kept = SoftAuthenticator()
        [begun] = ask({"cmd": "passkey_begin", "session": session, "_see": True})
        answer = kept.create(begun["options"], origin)
        [second] = ask({"cmd": "passkey_finish", "session": session, "answer": answer,
                        "name": "móvil", "_why": True})  # fmt: skip
        keys = pk.Passkeys(layout.STATE_DIR, origins=[origin])
        tail = next(k.tail for k in keys.keys() if k.name == "portátil")
        # What the web's user may not do: root's commands, by its socket or by reaching root's.
        refused = ask({"cmd": "passkey_remove", "key": tail, "_why": True},
                      {"cmd": "passkeys", "_why": True})  # fmt: skip
        root_socket = probe_as(web.pw_uid, web.pw_gid, "", str(CONTROL_SOCKET),
                               {"cmd": "passkey_remove", "key": tail})  # fmt: skip
        still_two = len(keys.keys())
        listed = sh(str(layout.BIN_LINK), "llaves", check=False)
        removed = sh(str(layout.BIN_LINK), "llaves", f"--quitar={tail}", check=False)
        [ended] = ask({"cmd": "session_check", "session": session})
        names = [k.name for k in keys.keys()]
        time.sleep(13)  # the answers' bucket, whatever came before
        with_lost, with_kept = sign_in(lost), sign_in(kept)
        recorded = wait(
            lambda: any(e.action == "web_passkey_removed"
                        for e in installed.box.events(since_seq=since)),
            30, interval=1,
        )  # fmt: skip
        events = [e for e in installed.box.events(since_seq=since)
                  if e.action == "web_passkey_removed"]  # fmt: skip
    finally:
        pk.path_of(layout.STATE_DIR).unlink(missing_ok=True)
    attack.check(
        "stopped",
        touch.get("outcome") == "touched"
        and second.get("outcome") == "added"
        and all("no se acepta" in r.get("why", "") for r in refused)
        and root_socket[0].get("errno") == "EACCES"
        and still_two == 2
        and listed.returncode == 0
        and f"…{tail}" in listed.stdout
        and removed.returncode == 0
        and ended.get("outcome") == "expired"
        and names == ["móvil"]
        and "no está registrada" in with_lost.get("why", "")
        and with_kept.get("outcome") == "opened",
        f"como backtide-web, quitarla y listarlas: {[r.get('why') for r in refused]}, y el "
        f"socket de root: {root_socket[0]}; `backtide llaves --quitar`: {removed.returncode}; la "
        f"sesión: {ended.get('outcome')}; quedan: {names}; la llave quitada: "
        f"{with_lost.get('why')}; la otra: {with_kept.get('outcome')}",
    )
    attack.check(
        "recorded",
        bool(recorded)
        and len(events) == 1
        and events[0].details.get("tail") == tail
        and events[0].details.get("uid") == 0,
        f"`web_passkey_removed`, en la caja negra con la llave y quién: {len(events)}",
    )


KEYS_WAIT = 61  # the narrow socket's passkey commands: 20 at once, then one every 3 s


@scenario("quitar-llave-desde-la-web")
def test_from_the_web_a_key_goes_only_by_another_key_and_never_the_last(
    attack: Attack, installed: Installed
) -> None:
    """T26-3d: as the web's user, every way to take a key out or name it without a live session,
    without a key touched, with the end of an id or with a bad name: refused, each for its reason.
    The last key does not go, not even touched. Then what must work does: a key gets a new name;
    with the second key, the lost one goes and every session with it; it signs in no more, the
    other does. Root's way still takes the last one."""
    from backtide.service import passkeys as pk
    from tests.passkey_kit import SoftAuthenticator

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    origin = pk.origin_for(pk.WEB_PORT)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    time.sleep(KEYS_WAIT)  # the keys' bucket and the answers', whatever came before

    def ask(*requests: dict) -> list[dict]:
        return probe_as(web.pw_uid, web.pw_gid, "", path, *requests)

    def sign_in(signer: Any) -> dict:
        [begun] = ask({"cmd": "auth_begin", "_see": True})
        answer = signer.get(begun["options"], origin)
        [said] = ask({"cmd": "auth_finish", "answer": answer, "_why": True, "_see": True})
        return said

    keys = pk.Passkeys(layout.STATE_DIR, origins=[origin])
    try:
        lost, first_session = key_for_the_owner(web, path)
        [only] = keys.keys()
        remove = {"cmd": "key_remove", "key": only.id, "_why": True}
        rename = {"cmd": "key_rename", "key": only.id, "name": "otro", "_why": True}
        no_session = ask({**remove, "session": "x" * 43}, {**rename, "session": "x" * 43})
        untouched = ask({**remove, "session": first_session}, {**rename, "session": first_session})
        names_untouched = [k.name for k in keys.keys()]
        [begun] = ask({"cmd": "touch_begin", "session": first_session, "_see": True})
        answer = lost.get(begun["options"], origin)
        [touch] = ask({"cmd": "touch_finish", "session": first_session, "answer": answer})
        the_last, by_tail, bad_name = ask(
            {**remove, "session": first_session},
            {**remove, "key": only.tail, "session": first_session},
            {**rename, "name": "t.me/x", "session": first_session},
        )
        root_remove = {"cmd": "passkey_remove", "key": only.id, "_why": True}
        root_rename = {"cmd": "passkey_rename", "key": only.id, "name": "x", "_why": True}
        roots_own = ask(root_remove, root_rename)
        names_refused = [k.name for k in keys.keys()]
        # What must work: a new name, a second key.
        [renamed] = ask({**rename, "name": "portatil viejo", "session": first_session})
        names_renamed = [k.name for k in keys.keys()]
        kept = SoftAuthenticator()
        [begun] = ask({"cmd": "passkey_begin", "session": first_session, "_see": True})
        answer = kept.create(begun["options"], origin)
        [second] = ask({"cmd": "passkey_finish", "session": first_session, "answer": answer,
                        "name": "móvil", "_why": True})  # fmt: skip
        # The laptop is lost: the other key signs in and takes it out.
        entered = sign_in(kept)
        [removed] = ask({**remove, "session": entered.get("session")})
        ended = ask({"cmd": "session_check", "session": first_session},
                    {"cmd": "session_check", "session": entered.get("session")})  # fmt: skip
        names_removed = [k.name for k in keys.keys()]
        with_lost, with_kept = sign_in(lost), sign_in(kept)
        # The last one does not go from there, with a key just touched. Root's does.
        [kept_key] = keys.keys()
        [last_again] = ask({**remove, "key": kept_key.id, "session": with_kept.get("session")})
        names_last = [k.name for k in keys.keys()]
        by_root_name = sh(str(layout.BIN_LINK), "llaves", f"--renombrar={kept_key.tail}",
                          "--nombre", "movil viejo", check=False)  # fmt: skip
        names_root = [k.name for k in keys.keys()]
        by_root = sh(str(layout.BIN_LINK), "llaves", f"--quitar={kept_key.tail}", check=False)
        names_end = [k.name for k in keys.keys()]

        def actions() -> list[Any]:
            kinds = ("web_passkey_removed", "web_passkey_renamed")
            return [e for e in installed.box.events(since_seq=since) if e.action in kinds]

        wait(lambda: len(actions()) >= 4, 30, interval=1)
        events = actions()
    finally:
        pk.path_of(layout.STATE_DIR).unlink(missing_ok=True)
    attack.check(
        "stopped",
        all("sesión viva" in r.get("why", "") for r in no_session)
        and all(
            r.get("outcome") == "touch" and "tocar tu llave" in r.get("why", "") for r in untouched
        )
        and names_untouched == ["portátil"]
        and touch.get("outcome") == "touched"
        and the_last.get("outcome") == "last"
        and "última" in the_last.get("why", "")
        and by_tail.get("outcome") == "missing"
        and bad_name.get("outcome") == "name"
        and all("no se acepta" in r.get("why", "") for r in roots_own)
        and names_refused == ["portátil"]
        and renamed.get("outcome") == "renamed"
        and names_renamed == ["portatil viejo"]
        and second.get("outcome") == "added"
        and entered.get("outcome") == "opened"
        and removed.get("outcome") == "removed"
        and all(r.get("outcome") == "expired" for r in ended)
        and names_removed == ["móvil"]
        and "no está registrada" in with_lost.get("why", "")
        and with_kept.get("outcome") == "opened"
        and last_again.get("outcome") == "last"
        and names_last == ["móvil"]
        and by_root_name.returncode == 0
        and names_root == ["movil viejo"]
        and by_root.returncode == 0
        and names_end == [],
        f"sin sesión: {[r.get('why') for r in no_session]}; sin tocar: "
        f"{[r.get('outcome') for r in untouched]}; la última: {the_last.get('outcome')}; por el "
        f"final del id: {by_tail.get('outcome')}; mal nombre: {bad_name.get('outcome')}; las de "
        f"root: {[r.get('why') for r in roots_own]}; nombre nuevo: {renamed.get('outcome')}; "
        f"segunda llave: {second.get('outcome')}; entrar con ella: {entered.get('outcome')}; "
        f"quitar la perdida: {removed.get('outcome')}; las sesiones: "
        f"{[r.get('outcome') for r in ended]}; la perdida: {with_lost.get('why')}; la otra: "
        f"{with_kept.get('outcome')}; otra vez la última: {last_again.get('outcome')}; root: "
        f"{by_root_name.returncode} y {by_root.returncode}; quedan: {names_end}",
    )
    # One of each, from each side: a refusal is not recorded as if it had been done.
    seen = sorted((e.action, e.details.get("via", "root"), e.details.get("tail")) for e in events)
    expected = sorted(
        [("web_passkey_renamed", "web", only.tail), ("web_passkey_removed", "web", only.tail),
         ("web_passkey_renamed", "root", kept_key.tail),
         ("web_passkey_removed", "root", kept_key.tail)]
    )  # fmt: skip
    attack.check(
        "recorded",
        seen == expected,
        f"en la caja negra, con la llave y desde dónde: {seen}",
    )


@scenario("reloj-bajo-el-filtro")
def test_the_service_lives_through_its_clock_check(attack: Attack, installed: Installed) -> None:
    """Incident of 2026-11-01: the filter of the unit killed the service at its first clock check,
    ten minutes in, and no test ran that long. Here the check comes every 20 s, with the real unit:
    after two of them the service is the same process. The control: the same read under
    @system-service alone dies by SIGSYS."""
    unit = (layout.UNIT_DIR / layout.SERVICE_UNIT).read_text()
    [real_filter] = [line for line in unit.splitlines() if line.startswith("SystemCallFilter=")]

    def show(name: str) -> str:
        return sh("systemctl", "show", "-p", name, "--value", layout.SERVICE_UNIT).stdout.strip()

    def under(rule: str) -> Any:
        read = "from backtide.service.clock import clock_synced; print(clock_synced())"
        interpreter = "/opt/backtide/current/.venv/bin/python"
        return sh("systemd-run", "--wait", "--pipe", "--quiet", "-p", rule,
                  interpreter, "-I", "-c", read, check=False)  # fmt: skip

    original = layout.CONFIG_FILE.read_bytes()
    assert b"prune_interval" not in original, "the installation already sets prune_interval"
    head = installed.box.head()
    since = head[0] if head is not None else 0
    try:
        layout.CONFIG_FILE.write_bytes(b"prune_interval = 20\n" + original)
        restart_service(installed)
        pid, restarts = show("MainPID"), show("NRestarts")
        time.sleep(50)
        pid_after, restarts_after = show("MainPID"), show("NRestarts")
    finally:
        layout.CONFIG_FILE.write_bytes(original)
        restart_service(installed)
    allowed, killed = under(real_filter), under("SystemCallFilter=@system-service")
    bad_clock = [
        e.seq for e in installed.box.events(source="system", since_seq=since)
        if "cannot read the state of the clock" in str(e.details.get("template", ""))
    ]  # fmt: skip
    attack.check(
        "stopped",
        pid == pid_after
        and pid != "0"
        and restarts == restarts_after
        and allowed.returncode == 0
        and killed.returncode != 0
        and not bad_clock,
        f"con la comprobación del reloj cada 20 s, 50 s después el proceso es el mismo "
        f"({pid} y {pid_after}) y los reinicios no cambian ({restarts} y {restarts_after}); bajo "
        f"el filtro de la unidad la lectura termina con {allowed.returncode}, sin él con "
        f"{killed.returncode}; avisos de no poder leer el reloj: {bad_clock or 'ninguno'}",
    )


@scenario("registro-sin-sesion")
def test_a_passkey_is_only_registered_from_a_live_session(
    attack: Attack, installed: Installed
) -> None:
    """T26-3b-2: as the web's user, register a passkey without a session, with a made-up one,
    without a challenge, across sessions, from another site and for another relying party, and
    then as the owner would; replay it; read the keys' file. Each refusal is checked for its
    reason, not only for being one (review of T26-3b-2)."""
    from backtide.service import passkeys as pk

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    right = LAB_PASSWORD.read_text().strip()
    kept = pk.path_of(layout.STATE_DIR)
    origin = pk.origin_for(pk.WEB_PORT)
    head = installed.box.head()
    since = head[0] if head is not None else 0
    key, other, elsewhere = soft_key(), soft_key(), soft_key("evil.example")
    time.sleep(13)  # the password's bucket, if another scenario just used it
    steps = [
        ("sin sesión", {"cmd": "passkey_begin", "session": None}, "refused", "sesión viva"),
        ("sesión inventada", {"cmd": "passkey_begin", "session": "s" * 43}, "refused",
         "sesión viva"),
        ("entra (p)", {"cmd": "session_password", "password": right, "_as": "p"}, "opened", ""),
        # The second session from a link root gives: the password's bucket may be spent by now.
        ("entra (q)", {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_as": "q"},
         "opened", ""),
        ("terminar sin empezar", {"cmd": "passkey_finish", "session": "<session:p>",
         "name": "x", "answer": "{}"}, "refused", "no hay un registro pedido"),
        ("empieza p", {"cmd": "passkey_begin", "session": "<session:p>"}, "options", ""),
        ("termina q", {"cmd": "passkey_finish", "session": "<session:q>", "name": "ajena",
         "_origin": origin, **other}, "refused", "no hay un registro pedido"),
        ("empieza p", {"cmd": "passkey_begin", "session": "<session:p>"}, "options", ""),
        ("de otro sitio", {"cmd": "passkey_finish", "session": "<session:p>", "name": "x",
         "_origin": "http://evil.example:8765", **other}, "refused", "no ha dado una llave"),
        ("empieza p", {"cmd": "passkey_begin", "session": "<session:p>"}, "options", ""),
        ("para otro dominio", {"cmd": "passkey_finish", "session": "<session:p>", "name": "x",
         "_origin": origin, **elsewhere}, "refused", "no ha dado una llave"),
        ("empieza p", {"cmd": "passkey_begin", "session": "<session:p>"}, "options", ""),
        ("la del dueño", {"cmd": "passkey_finish", "session": "<session:p>", "name": "portátil",
         "_origin": origin, **key}, "added", ""),
        # With a key kept, adding another asks to touch it first (T26-3c): the repeat stops there.
        ("otra vez la misma", {"cmd": "passkey_finish", "session": "<session:p>",
         "name": "portátil", "_origin": origin, **key}, "refused", "tocar tu llave"),
        ("lista", {"cmd": "passkey_list", "session": "<session:p>"}, "listed", ""),
        ("sale p", {"cmd": "session_end", "session": "<session:p>"}, "ended", ""),
        ("sale q", {"cmd": "session_end", "session": "<session:q>"}, "ended", ""),
    ]  # fmt: skip
    try:
        requests: list[dict] = []
        for number, (_, request, _, _) in enumerate(steps):
            requests.append({**request, "_why": True})
            if number == 6:  # the keys' bucket gives one every 3 s after what it holds at once
                requests.append({"_sleep": 12})
        said = [
            reply
            for reply in probe_as(web.pw_uid, web.pw_gid, "", path, *requests)
            if "slept" not in reply
        ]
        info, folder = os.stat(kept), os.stat(kept.parent)
        as_file = (info.st_uid, oct(stat.S_IMODE(info.st_mode)), oct(stat.S_IMODE(folder.st_mode)))
        text = kept.read_text()
        read_as_web = sh(
            "setpriv", "--reuid", str(web.pw_uid), "--regid", str(web.pw_gid), "--clear-groups",
            "--", "cat", str(kept), check=False,
        )  # fmt: skip
        events = installed.box.events(since_seq=since)
    finally:
        kept.unlink(missing_ok=True)  # the installation as install.sh left it: no key
    wrong = [
        (label, reply.get("outcome"), reply.get("why"))
        for (label, _, outcome, reason), reply in zip(steps, said, strict=False)
        if reply.get("outcome") != outcome or reason not in str(reply.get("why", ""))
    ]
    ok = (
        len(said) == len(steps)
        and not wrong
        and as_file == (0, "0o600", "0o700")
        and "PRIVATE" not in text
        and key["_credential"] in text
        and other["_credential"] not in text
        and elsewhere["_credential"] not in text
        and read_as_web.returncode != 0
    )
    attack.check(
        "stopped",
        ok,
        f"como backtide-web, {len(steps)} pasos (sin sesión, inventada, terminar sin empezar, un "
        f"reto de otra sesión, otro sitio, otro dominio, la del dueño y repetirla): fuera de lo "
        f"esperado {wrong or 'ninguno'}; el archivo (uid, modo, carpeta): {as_file}, solo "
        f"claves públicas ({'PRIVATE' not in text}), ni la de otro sitio ni la de otro dominio "
        f"({other['_credential'] not in text and elsewhere['_credential'] not in text}), y "
        f"backtide-web no lo lee ({read_as_web.returncode != 0})",
    )
    added = [e for e in events if e.source == "system" and e.action == "web_passkey_added"]
    attack.check(
        "recorded",
        len(added) == 1
        and added[0].details.get("name") == "portátil"
        and set(added[0].details) <= {"pid", "name", "tail"},
        f"la llave nueva, en la caja negra con su nombre y el final de su id ({len(added)}), y "
        f"ninguna de las rechazadas",
    )


DOMAIN = "backtide.example.org"
DOMAIN_URL = f"https://{DOMAIN}"


def as_the_proxy(
    method: str,
    where: str,
    *,
    host: str = DOMAIN,
    origin: str | None = None,
    cookie: str | None = None,
    body: str | None = None,
    more: dict[str, str] | None = None,
) -> tuple[int, str, str, str]:
    """A request as the server's reverse proxy brings it, to the web on loopback: its status, its
    text, its Set-Cookie and its Retry-After. Nothing here reaches anything outside the VM."""
    from http.client import HTTPConnection

    from backtide.service import passkeys as pk

    conn = HTTPConnection("127.0.0.1", pk.WEB_PORT, timeout=20)
    headers = {"Host": host, **(more or {})}
    if origin is not None:
        headers["Origin"] = origin
    if cookie is not None:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, where, body=body, headers=headers)
    response = conn.getresponse()
    found = (response.status, response.read().decode(errors="replace"),
             response.getheader("set-cookie") or "",
             response.getheader("retry-after") or "")  # fmt: skip
    conn.close()
    return found


def web_says_domain() -> bool:
    return layout.WEB_LINK_FILE.read_text().splitlines()[0] == f"{DOMAIN_URL}/"


@scenario("web-en-un-dominio")
def test_behind_a_domain_only_its_host_its_origin_and_its_key_get_in(
    attack: Attack, installed: Installed
) -> None:
    """T26-4a: `[web] public_origin` on the real installation, then restored. What a reverse proxy
    would bring to loopback, with a made-up https origin: each refusal for its reason, next to a
    control that gets in with the same request."""
    from backtide.service import passkeys as pk
    from backtide.web.security import COOKIE_NAME, DOMAIN_COOKIE_NAME
    from tests.passkey_kit import SoftAuthenticator

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    right = LAB_PASSWORD.read_text().strip()
    service_toml, web_toml = layout.CONFIG_FILE.read_bytes(), layout.WEB_CONFIG_FILE.read_bytes()
    assert b"[web]" not in service_toml + web_toml, "the installation already has a [web] table"
    kept = pk.path_of(layout.STATE_DIR, DOMAIN)
    assert not kept.exists(), "a key of the domain is left from a run that was killed"
    table = f'\n[web]\npublic_origin = "{DOMAIN_URL}"\n'.encode()
    bad_file = Path("/tmp/backtide-bad-origin.toml")  # noqa: S108 - inside the VM, removed below
    bad_said: list[tuple[int, str, str]] = []
    results: dict[str, Any] = {}

    def probe(*requests: dict) -> list[dict]:
        return probe_as(web.pw_uid, web.pw_gid, "", path, *requests)

    def enlace() -> Any:
        """Root's own command, as root runs it."""
        return sh(str(layout.PROGRAM), "enlace", check=False)

    def links_given(since: int) -> int:
        return sum(e.action == "web_link_given" for e in installed.box.events(since_seq=since))

    try:
        # A bad origin: the web does not start, and says why without quoting it.
        for bad in ("http://backtide.example.org", "https://x:hunter2@backtide.example.org",
                    "https://dev.example.org/backtide"):  # fmt: skip
            bad_file.write_text(
                f'state_dir = "{layout.STATE_DIR}"\nvolume = "/nowhere"\n\n'
                f'[web]\npublic_origin = "{bad}"\n'
            )
            ran = sh(str(layout.PROGRAM), "web", "--config", str(bad_file), "--puerto", "0",
                     "--socket-web", path, "--rebobinar", check=False)  # fmt: skip
            bad_said.append((ran.returncode, ran.stderr, bad))
        layout.CONFIG_FILE.write_bytes(service_toml + table)
        layout.WEB_CONFIG_FILE.write_bytes(web_toml + table)
        restart_service(installed)
        sh("systemctl", "restart", layout.WEB_UNIT, timeout=120)
        assert wait(web_says_domain, 60, interval=1), "the web did not come back on its domain"
        head = installed.box.head()
        since = head[0] if head is not None else 0

        # The controls: the domain's own Host, with root's link, gets the __Host- cookie.
        results["sin cookie"] = as_the_proxy("GET", "/")
        link = as_the_proxy("GET", f"/?t={ask_web_link(CONTROL_SOCKET)}")
        cookie_line = link[2]
        value = cookie_line.partition(";")[0].partition("=")[2]
        cookie = f"{DOMAIN_COOKIE_NAME}={value}"
        results["dentro"] = as_the_proxy("GET", "/panel", cookie=cookie)
        results["cookie sin __Host-"] = as_the_proxy(
            "GET", "/panel", cookie=f"{COOKIE_NAME}={value}"
        )
        # Host: with the cookie that gets in above, so it is the Host that stops each one.
        for host in ("evil.example", f"{DOMAIN}.evil.example", f"127.0.0.1:{pk.WEB_PORT}",
                     f"{pk.RP_ID}:{pk.WEB_PORT}", f"{DOMAIN}:8443"):  # fmt: skip
            results[f"Host {host}"] = as_the_proxy("GET", "/panel", host=host, cookie=cookie)
        results["X-Forwarded-Host"] = as_the_proxy(
            "GET", "/panel", host="evil.example", cookie=cookie,
            more={"X-Forwarded-Host": DOMAIN, "X-Forwarded-Proto": "https",
                  "X-Forwarded-For": "127.0.0.1"},
        )  # fmt: skip
        # Origin: the sign-in's first step, which takes no session, so only the Origin differs.
        begin = "/entrar/llave/empezar"
        for origin in ("https://evil.example", f"http://{DOMAIN}", f"{DOMAIN_URL}:8443",
                       f"http://127.0.0.1:{pk.WEB_PORT}"):  # fmt: skip
            results[f"Origin {origin}"] = as_the_proxy("POST", begin, origin=origin, body="")
        results["Origin bueno"] = as_the_proxy("POST", begin, origin=DOMAIN_URL, body="")
        # The password, the right one, by every way there is.
        results["/entrar"] = as_the_proxy(
            "POST", "/entrar", origin=DOMAIN_URL, body=f"password={right}"
        )
        results["contraseña al socket"] = probe(
            {"cmd": "session_password", "password": right, "_why": True}
        )[0]
        # No way in with no session: every page and order, as `entrar-sin-llave`, at the root.
        pages = ["/", "/ahora", "/instantaneas", "/peticiones", "/ajustes", "/llaves", "/tocar"]
        orders = ["/llaves/empezar", "/tocar/empezar", "/ajustes/cerrar-sesiones", "/salir"]
        made_up = f"{DOMAIN_COOKIE_NAME}={'s' * 43}"
        no_session = {w: as_the_proxy("GET", w)[0] for w in pages}
        no_session |= {f"{w} (inventada)": as_the_proxy("GET", w, cookie=made_up)[0] for w in pages}
        no_session |= {
            w: as_the_proxy("POST", w, origin=DOMAIN_URL, body="csrf=x", cookie=made_up)[0]
            for w in orders
        }
        # What lasts wants a key here even with none yet (D40).
        forged = {"cmd": "trust", "hold_id": "h-" + secrets.token_hex(6), "session": value,
                  "_why": True}  # fmt: skip
        results["sin llave"] = probe(forged)[0]
        # `sudo backtide enlace`: the address is root's configuration, never the web's file. The
        # control: the link it prints gets in. A web taken over that rewrites its file gets no
        # token sent anywhere, and none is even given.
        given = enlace()
        printed = re.search(rf"{re.escape(DOMAIN_URL)}/\?t=([A-Za-z0-9_-]+)", given.stdout)
        results["enlace"] = given.returncode
        results["el enlace entra"] = (
            as_the_proxy("GET", f"/?t={printed[1]}")[0] if printed is not None else 0
        )
        written = layout.WEB_LINK_FILE.read_text()
        before = links_given(since)
        try:
            layout.WEB_LINK_FILE.write_text("https://evil.example/\nmarea-faro-nube\n")
            tricked = enlace()
        finally:
            layout.WEB_LINK_FILE.write_text(written)
        said = tricked.stdout + tricked.stderr
        results["archivo cambiado"] = (tricked.returncode, "no dicen lo mismo" in tricked.stderr,
                                       "?t=" in said or "evil" in said,
                                       links_given(since) - before)  # fmt: skip
        pending = ask_web_link(CONTROL_SOCKET)  # unspent when the first key arrives
        # The first key, of this domain, from the session of root's link.
        begun = probe({"cmd": "passkey_begin", "session": value, "_see": True})[0]
        assert begun.get("options"), f"no options to register a key: {begun}"
        results["dominio de la llave"] = json.loads(begun["options"])["rp"]["id"]
        owner = SoftAuthenticator()
        answer = owner.create(begun["options"], DOMAIN_URL, rp_id=DOMAIN)
        results["llave"] = probe(
            {"cmd": "passkey_finish", "session": value, "answer": answer, "name": "portátil",
             "_why": True},
        )[0]  # fmt: skip
        results["archivo"] = (kept.exists(), pk.path_of(layout.STATE_DIR).exists())

        def attempt(at: str, rp_id: str = DOMAIN) -> dict:
            first = probe({"cmd": "auth_begin", "_see": True})[0]
            signed = owner.get(first["options"], at, rp_id=rp_id)
            return probe({"cmd": "auth_finish", "answer": signed, "_why": True})[0]

        results["firma del túnel"] = attempt(pk.origin_for(pk.WEB_PORT))
        results["firma de otro sitio"] = attempt("https://evil.example")
        results["firma sin https"] = attempt(f"http://{DOMAIN}")
        results["firma de otro dominio"] = attempt(DOMAIN_URL, rp_id=pk.RP_ID)
        results["firma buena"] = attempt(DOMAIN_URL)
        # With a key the link is closed (D40), the one already given too, and root says the way
        # back, which has to work: the key taken out, the sessions gone, and a link again.
        closed = enlace()
        results["enlace con llave"] = (closed.returncode, "llaves --quitar" in closed.stderr,
                                       "?t=" in closed.stdout)  # fmt: skip
        results["enlace ya dado"] = probe(
            {"cmd": "session_open", "token": pending, "_why": True}
        )[0]  # fmt: skip
        key_id = json.loads(kept.read_text())["keys"][0]["id"]
        results["quitar"] = sh(str(layout.PROGRAM), "llaves", "--quitar", key_id,
                               check=False).returncode  # fmt: skip
        results["sesión tras quitar"] = probe({"cmd": "session_check", "session": value})[0]
        results["reto sin llaves"] = probe({"cmd": "auth_begin", "_why": True})[0]
        again = enlace()
        results["enlace otra vez"] = (again.returncode, f"{DOMAIN_URL}/?t=" in again.stdout)
        events = installed.box.events(since_seq=since)
    finally:
        bad_file.unlink(missing_ok=True)
        kept.unlink(missing_ok=True)
        layout.CONFIG_FILE.write_bytes(service_toml)
        layout.WEB_CONFIG_FILE.write_bytes(web_toml)
        try:
            restart_service(installed)
        finally:  # or the web stays on the domain, and the next scenarios fail for that
            sh("systemctl", "restart", layout.WEB_UNIT, timeout=120)
    assert wait(lambda: not web_says_domain(), 60, interval=1), "the web did not go back"
    # And back on the tunnel, with nothing of the domain left: the same request for the old names.
    back = as_the_proxy("GET", f"/s/{web_prefix()}/", host=f"{pk.RP_ID}:{pk.WEB_PORT}")
    domain_gone = as_the_proxy("GET", f"/s/{web_prefix()}/")

    def status(name: str) -> int:
        return results[name][0]

    def says(name: str, text: str) -> bool:
        return text in results[name][1]

    hosts = {n: results[n][:2] for n in results if n.startswith("Host ")}
    origins = {n: results[n][:2] for n in results if n.startswith("Origin ") and "bueno" not in n}
    entries = [e for e in events if e.action == "web_session_opened"]
    ways = sorted(str(e.details.get("via")) for e in entries)
    removed = [e for e in events if e.action == "web_passkey_removed"]
    bad_origins = [
        (code, bad) for code, said, bad in bad_said
        if code != 2 or "public_origin" not in said or "hunter2" in said or bad in said
    ]  # fmt: skip
    signatures = ("firma del túnel", "firma de otro sitio", "firma sin https",
                  "firma de otro dominio")  # fmt: skip
    ok = (
        not bad_origins
        and status("sin cookie") == 401
        and says("sin cookie", 'id="webauthn-go"')
        and not says("sin cookie", 'type="password"')
        and link[0] == 200
        and cookie_line.startswith(f"{DOMAIN_COOKIE_NAME}=")
        and {"secure", "httponly", "samesite=strict", "path=/"}
        <= {part.strip().lower() for part in cookie_line.split(";")[1:]}
        and status("dentro") == 200
        and status("cookie sin __Host-") == 401
        and all(found == (400, "Host not allowed") for found in hosts.values())
        and results["X-Forwarded-Host"][:2] == (400, "Host not allowed")
        and all(found == (403, "A change needs our own Origin") for found in origins.values())
        # The control: with its own Origin it reaches the service, which has no key to sign yet.
        and status("Origin bueno") == 400
        and says("Origin bueno", "ninguna llave")
        and results["/entrar"][:2] == (405, "Read-only")
        and not results["/entrar"][2]
        and results["contraseña al socket"].get("outcome") == "refused"
        and "no lleva contraseña" in results["contraseña al socket"].get("why", "")
        and all(found == 401 for found in no_session.values())
        and "tocar tu llave" in results["sin llave"].get("why", "")
        and results["enlace"] == 0
        and results["el enlace entra"] == 200
        and results["archivo cambiado"] == (1, True, False, 0)
        and results["enlace con llave"] == (1, True, False)
        and results["enlace ya dado"].get("outcome") == "refused"
        and "el enlace no vale" in results["enlace ya dado"].get("why", "")  # the probe cuts at 80
        and results["quitar"] == 0
        and results["sesión tras quitar"].get("outcome") == "expired"
        and "ninguna llave" in results["reto sin llaves"].get("why", "")
        and results["enlace otra vez"] == (0, True)
        and results["dominio de la llave"] == DOMAIN
        and results["llave"].get("outcome") == "added"
        and results["archivo"] == (True, False)
        and all(
            results[name].get("outcome") == "refused"
            and "firma válida" in results[name].get("why", "")
            for name in signatures
        )
        and results["firma buena"].get("outcome") == "opened"
        and back[0] == 401
        and domain_gone[:2] == (400, "Host not allowed")
        and layout.CONFIG_FILE.read_bytes() == service_toml
        and layout.WEB_CONFIG_FILE.read_bytes() == web_toml
    )
    attack.check(
        "stopped",
        ok,
        f"origen malo, la web no arranca: {[c for c, _, _ in bad_said]} (fuera de lo esperado: "
        f"{bad_origins or 'ninguno'}); el control entra con su Host y su cookie ({link[0]}, "
        f"{status('dentro')}) y sin __Host- no ({status('cookie sin __Host-')}); otros Host: "
        f"{hosts}; X-Forwarded-*: {results['X-Forwarded-Host'][:2]}; otros Origin: {origins}; su "
        f"Origin: {results['Origin bueno'][:2]}; /entrar con la contraseña buena: "
        f"{results['/entrar'][:2]}, y por el socket: {results['contraseña al socket'].get('why')}; "
        f"sin sesión: {no_session}; lo que dura, sin llave: {results['sin llave'].get('why')}; la "
        f"llave del dominio: {results['dominio de la llave']}, {results['llave'].get('outcome')}, "
        f"en su archivo {results['archivo']}; firmas de otro sitio: "
        f"{[results[name].get('why') for name in signatures]}; la buena: "
        f"{results['firma buena'].get('outcome')}; `backtide enlace`: {results['enlace']}, y entra "
        f"({results['el enlace entra']}); con el archivo cambiado (código, dice por qué, enseña "
        f"algo, tokens dados): {results['archivo cambiado']}; con llave, enlace nuevo "
        f"{results['enlace con llave']} y el ya dado {results['enlace ya dado'].get('why')}; "
        f"`llaves --quitar`: {results['quitar']}, la sesión "
        f"{results['sesión tras quitar'].get('outcome')}, sin reto "
        f"({results['reto sin llaves'].get('why')}) y otra vez enlace "
        f"{results['enlace otra vez']}; al quitar `public_origin`, el túnel otra vez ({back[0]}) y "
        f"el dominio no ({domain_gone[:2]})",
    )
    attack.check(
        "recorded",
        set(ways) == {"None", "passkey"} and ways.count("passkey") == 1 and len(removed) == 1,
        f"en la caja negra, las entradas con el enlace y una con la llave, ninguna con contraseña: "
        f"{ways}; y la llave quitada ({len(removed)})",
    )


@scenario("cookies-inventadas")
def test_made_up_cookies_do_not_throw_the_owner_out(attack: Attack, installed: Installed) -> None:
    """Review of T26-3c, for T26-4a: with a domain, anyone can send made-up cookies. Hundreds of
    them never leave a live session out: they empty a bucket of their own, past it the word is a
    503, never a 401, and root's link gets in however many wrong ones came first. Through the
    tunnel's names: the buckets are the service's, the same with a domain or without one."""
    from backtide.service import passkeys as pk
    from backtide.web.security import COOKIE_NAME

    web = pwd.getpwnam(layout.WEB_USER)
    path = str(WEB_SOCKET)
    base = f"/s/{web_prefix()}"
    host = f"{pk.RP_ID}:{pk.WEB_PORT}"
    head = installed.box.head()
    since = head[0] if head is not None else 0
    made_up = {"cmd": "session_check", "session": "m" * 43}

    def probe(*requests: dict) -> list[dict]:
        return probe_as(web.pw_uid, web.pw_gid, "", path, *requests)

    # By the socket, faster than the bucket refills: the live one is asked right after them.
    opened = {"cmd": "session_open", "token": ask_web_link(CONTROL_SOCKET), "_see": True}
    live = {"cmd": "session_check", "session": "<session>"}
    said = probe(opened, *[made_up] * 600, *[live] * 5, *[made_up] * 30)
    session = said[0]["session"]
    flood, owner_after, still = said[1:601], said[601:606], said[606:]
    outcomes = {o: sum(r.get("outcome") == o for r in flood) for o in ("expired", "busy", "live")}

    # By HTTP, with the owner's page asked for all through a flood of made-up cookies.
    time.sleep(8)  # its bucket back, so that this flood has something to empty
    stop = threading.Event()
    flood_said: list[int] = []
    owner_said: list[int] = []
    busy_said: list[tuple[int, str, str, str]] = []
    errors: list[str] = []

    def flooding() -> None:
        while not stop.is_set():
            forged = f"{COOKIE_NAME}={secrets.token_urlsafe(32)}"
            try:
                found = as_the_proxy("GET", f"{base}/ahora", host=host, cookie=forged)
            except (OSError, HTTPException) as error:  # or the flood ends here, and nobody knows
                errors.append(type(error).__name__)
                return
            flood_said.append(found[0])
            if found[0] == 503:
                busy_said.append(found)

    threads = [threading.Thread(target=flooding) for _ in range(8)]
    for thread in threads:
        thread.start()
    own = f"{COOKIE_NAME}={session}"
    try:
        for _ in range(60):
            owner_said.append(as_the_proxy("GET", f"{base}/ahora", host=host, cookie=own)[0])
            time.sleep(0.25)
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    # The control of the 401: the made-up cookie alone, with its bucket back.
    time.sleep(8)
    alone = as_the_proxy("GET", f"{base}/ahora", host=host, cookie=f"{COOKIE_NAME}={'m' * 43}")[0]
    # Root's link, after wrong ones past their bucket.
    wrong = {"cmd": "session_open", "token": "w" * 43, "_why": True}
    token = ask_web_link(CONTROL_SOCKET)
    links = probe(*[wrong] * 12, {"cmd": "session_open", "token": token, "_why": True})
    recorded = recorded_in_time(
        installed, since, "too many session_check", lambda: probe(*[made_up] * 400)
    )
    ended = probe({"cmd": "session_end", "session": session})
    ok = (
        outcomes["busy"] > 0
        and outcomes["expired"] > 0
        and outcomes["live"] == 0
        and flood[0].get("outcome") == "expired"
        # Not the very last: the bucket gets 40 tokens back a second while this runs.
        and any(r.get("outcome") == "busy" for r in flood[-30:])
        and all(r.get("outcome") == "live" for r in owner_after)
        and any(r.get("outcome") == "busy" for r in still)
        and all(r.get("outcome") in ("busy", "expired") for r in still)
        and not errors
        and len(flood_said) >= 100
        and set(flood_said) <= {401, 503}
        and busy_said
        # The service's cap, not uvicorn's own 503: its Retry-After and the way in.
        and {found[3] for found in busy_said} == {"5"}
        and all('id="webauthn-go"' in found[1] for found in busy_said)
        and alone == 401
        and owner_said.count(200) >= 57
        and 401 not in owner_said
        and "Demasiadas" in links[-2].get("why", "")
        and links[-1].get("outcome") == "opened"
        and ended[0].get("outcome") == "ended"
    )
    attack.check(
        "stopped",
        ok,
        f"600 cookies inventadas por el socket: {outcomes}, y la sesión viva justo después: "
        f"{[r.get('outcome') for r in owner_after]}, y otras inventadas: "
        f"{sorted({str(r.get('outcome')) for r in still})}. Por HTTP: inventadas "
        f"{sorted(set(flood_said))} ({len(flood_said)}, errores de los hilos: {errors or 'ninguno'}"
        f", Retry-After de los 503: {sorted({found[3] for found in busy_said})}), el dueño a la "
        f"vez {owner_said.count(200)} de {len(owner_said)} dentro y "
        f"{owner_said.count(401)} con 401; una sola, sin avalancha: {alone}. Enlaces equivocados:"
        f" {links[-2].get('why')}; el bueno: "
        f"{links[-1].get('outcome')}",
    )
    attack.check(
        "recorded", recorded, f"el tope, en la caja negra por el puente del registro: {recorded}"
    )
