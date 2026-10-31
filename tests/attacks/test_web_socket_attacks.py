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
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

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
from backtide.service.control import ask_web_end_all, ask_web_link
from backtide.setup import layout
from backtide.snapshots import Snapshot

pytestmark = pytest.mark.instalada
WEB_SOCKET = layout.STATE_DIR / STATE_WEB_SOCKET
CONTROL_SOCKET = layout.STATE_DIR / STATE_SOCKET

# One JSON request per line in argv[2:], each on its own connection; what comes back is either
# the service's reply (outcome and ok only) or the errno of connecting. Plain sockets: nothing of
# backtide runs as the probe. A session a reply opens (T26-3a) is kept, never printed, and put
# where a later request says "<session>"; one opened by a request with "_as": NAME is kept under
# that name too, for "<session:NAME>". {"_sleep": S} waits S seconds (T26-3a-2: expiry). A
# request with "_attestation", "_credential" and "_origin" gets, as its "answer", a browser's
# answer to the last options a reply carried (T26-3b-2): only its clientDataJSON depends on the
# challenge, and that needs nothing but the standard library.
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
        ("otra vez la misma", {"cmd": "passkey_finish", "session": "<session:p>",
         "name": "portátil", "_origin": origin, **key}, "refused", "no hay un registro pedido"),
        ("lista", {"cmd": "passkey_list", "session": "<session:p>"}, "listed", ""),
        ("sale p", {"cmd": "session_end", "session": "<session:p>"}, "ended", ""),
        ("sale q", {"cmd": "session_end", "session": "<session:q>"}, "ended", ""),
    ]  # fmt: skip
    try:
        requests: list[dict] = []
        for number, (_, request, _, _) in enumerate(steps):
            requests.append({**request, "_why": True})
            if number == 6:  # the keys' bucket gives 10 at once, then one every 3 s
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
