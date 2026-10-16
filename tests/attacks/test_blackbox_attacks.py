"""Evil-agent scenarios against the black box (T02), from the host and without the agent.

The attacker here has what the agent would have after escaping the jail: write access to the
black box's files on the host. It never has the key. `vigia verificar` (the real command) has to
notice every manipulation. A second scenario checks that secrets never reach those files at all.
Nothing needs the agent's container, so these run fast, but they still refuse to run outside the
VM like every attack.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from attack_kit import Attack, scenario

from vigia.blackbox import BlackBox, BlackBoxError, Source, create_key
from vigia.blackbox.chain import canonical, compute_hash

REPO = Path(__file__).resolve().parents[2]
SNAPSHOT = "20261016T101500.000000Z-periodic"
ATTACKER_KEY = bytes(range(100, 132))  # the attacker's own key: not the real one
EXIT_TAMPERED, EXIT_UNREADABLE = 1, 2


@dataclass(frozen=True)
class Box:
    directory: Path

    @property
    def db(self) -> Path:
        return self.directory / "blackbox.sqlite3"

    @property
    def checkpoint(self) -> Path:
        return self.directory / "blackbox.checkpoint"

    @property
    def key(self) -> Path:
        return self.directory / "blackbox.key"

    def open(self, key: bytes) -> BlackBox:
        return BlackBox(self.db, key, checkpoint_path=self.checkpoint)


def build_box(directory: Path) -> tuple[Box, bytes]:
    """A black box with the story of a bad afternoon: reads, a write, then a mass delete and a
    DELETE request to a cloud API, which is what the attacker wants to erase."""
    directory.mkdir(mode=0o700)
    box = Box(directory)
    key = create_key(box.key)
    with box.open(key) as black_box:
        black_box.append(Source.EXEC, "run", "ls /workspace/work", risk=0)
        black_box.append(
            Source.FILE, "write", "/workspace/work/notes.md", risk=1, snapshot_id=SNAPSHOT
        )
        black_box.append(
            Source.EXEC, "run", "rm -rf /workspace/work/project", details={"exit": 0}, risk=3
        )
        black_box.append(
            Source.FILE, "delete", "/workspace/work/project/app.db", risk=3, snapshot_id=SNAPSHOT
        )
        black_box.append(
            Source.NET,
            "request",
            "https://api.example.invalid/v1/databases/prod",
            details={"method": "DELETE", "status": 200},
            risk=3,
        )
        black_box.append(Source.GATE, "hold", "DELETE https://api.example.invalid", risk=3)
    return box, key


@contextmanager
def triggers_off(db: Path) -> Iterator[sqlite3.Connection]:
    """The attacker opens the database with plain sqlite3, drops the append-only triggers, does
    the damage and puts the triggers back, byte for byte, to hide that they were gone."""
    connection = sqlite3.connect(db)
    saved = connection.execute("SELECT sql FROM sqlite_master WHERE type = 'trigger'").fetchall()
    names = connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall()
    for (name,) in names:
        connection.execute(f'DROP TRIGGER "{name}"')
    try:
        yield connection
    finally:
        for (sql,) in saved:
            connection.execute(sql)
        connection.commit()
        connection.close()


# The attacks. Each one gets its own copy of the box and returns what it did.


def edit_an_event(box: Box) -> None:
    """Turn the 'rm -rf' (event 3, risk 3) into a harmless read."""
    with triggers_off(box.db) as db:
        db.execute("UPDATE events SET action = 'read', risk = 0 WHERE seq = 3")


def delete_an_event(box: Box) -> None:
    """Remove the mass delete (event 3) from the middle of the record."""
    with triggers_off(box.db) as db:
        db.execute("DELETE FROM events WHERE seq = 3")


def cut_the_tail(box: Box) -> None:
    """Remove the last two events: the DELETE request and its hold."""
    with triggers_off(box.db) as db:
        db.execute("DELETE FROM events WHERE seq > 4")


def cut_the_tail_and_the_checkpoint(box: Box) -> None:
    """Remove the last two events and the checkpoint that says how far the chain reached."""
    cut_the_tail(box)
    box.checkpoint.unlink()


def rechain_with_another_key(box: Box) -> None:
    """Edit event 3 and recompute every hash of the chain with a key of the attacker's."""
    with triggers_off(box.db) as db:
        db.execute("UPDATE events SET action = 'read', risk = 0 WHERE seq = 3")
        previous = "0" * 64
        rows = db.execute(
            "SELECT seq, ts, source, action, target, details, risk, snapshot_id FROM events "
            "ORDER BY seq"
        ).fetchall()
        for seq, ts, source, action, target, details, risk, snapshot_id in rows:
            fields = {
                "seq": seq,
                "ts": ts,
                "source": source,
                "action": action,
                "target": target,
                "details": json.loads(details),
                "risk": risk,
                "snapshot_id": snapshot_id,
                "prev_hash": previous,
            }
            previous = compute_hash(ATTACKER_KEY, canonical(fields))
            db.execute(
                "UPDATE events SET prev_hash = ?, hash = ? WHERE seq = ?",
                (fields["prev_hash"], previous, seq),
            )


def swap_in_another_database(box: Box) -> None:
    """Replace the database with one the attacker made with a key of their own, innocent
    events only."""
    forged_dir = box.directory.parent / f"forged-{box.directory.name}"
    forged_dir.mkdir(mode=0o700)
    forged = Box(forged_dir)
    with forged.open(ATTACKER_KEY) as black_box:
        black_box.append(Source.EXEC, "run", "ls /workspace/work", risk=0)
        black_box.append(Source.FILE, "write", "/workspace/work/notes.md", risk=1)
    shutil.copyfile(forged.db, box.db)


def empty_the_database(box: Box) -> None:
    """Truncate the database file to nothing."""
    box.db.write_bytes(b"")


def delete_the_database(box: Box) -> None:
    """Remove the database: the whole record, gone."""
    box.db.unlink()


ATTACKS: dict[str, tuple[Callable[[Box], None], int]] = {
    "cambiar un evento (rm -rf pasa a ser una lectura)": (edit_an_event, EXIT_TAMPERED),
    "borrar un evento intermedio": (delete_an_event, EXIT_TAMPERED),
    "cortar el final": (cut_the_tail, EXIT_TAMPERED),
    "cortar el final y borrar el punto de control": (
        cut_the_tail_and_the_checkpoint,
        EXIT_TAMPERED,
    ),
    "rehacer toda la cadena con otra clave": (rechain_with_another_key, EXIT_TAMPERED),
    "sustituir la base de datos por otra": (swap_in_another_database, EXIT_TAMPERED),
    "vaciar el archivo de la base de datos": (empty_the_database, EXIT_TAMPERED),
    "borrar la base de datos": (delete_the_database, EXIT_UNREADABLE),
}


def verify(box: Box) -> subprocess.CompletedProcess[str]:
    """`vigia verificar`, exactly as a person would run it."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "vigia.cli",
            "verificar",
            "--db",
            str(box.db),
            "--key",
            str(box.key),
            "--checkpoint",
            str(box.checkpoint),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )


@scenario("manipular-la-caja-negra")
def test_tampering_with_the_black_box(attack: Attack, tmp_path_factory: pytest.TempPathFactory):
    work = tmp_path_factory.mktemp("blackbox-attack")
    original, key = build_box(work / "original")
    intact = verify(original)
    assert intact.returncode == 0 and "6 eventos íntegros" in intact.stdout, intact  # not vacuous

    findings: list[str] = []
    changed, detected = [], []
    for index, (name, (do_attack, expected_exit)) in enumerate(ATTACKS.items()):
        copy = Box(work / f"attack-{index}")
        shutil.copytree(original.directory, copy.directory)
        before = copy.db.read_bytes() if copy.db.exists() else b""
        do_attack(copy)
        after = copy.db.read_bytes() if copy.db.exists() else b""
        changed.append(before != after or not copy.checkpoint.exists())
        report = verify(copy)
        said = (report.stdout + report.stderr).strip().splitlines()
        detected.append(report.returncode == expected_exit)
        findings.append(f"{name}: salida {report.returncode} ({said[0] if said else 'sin texto'})")
        if name.startswith("cambiar un evento"):
            assert "evento 3" in report.stdout, report.stdout  # it points at the right event
        if name.startswith("cortar el final y borrar"):
            # And the recording process refuses to extend the chain over the evidence.
            with copy.open(key) as black_box, pytest.raises(BlackBoxError):
                black_box.append(Source.EXEC, "run", "ls")

    attack.check(
        "stopped",
        all(changed),
        f"desde el anfitrión se pueden editar sus archivos: las {len(ATTACKS)} manipulaciones "
        "cambiaron de verdad la caja negra",
    )
    attack.check(
        "recorded",
        all(detected),
        "la caja intacta sale con 0 y cada manipulación se detecta con `vigia verificar`: "
        + "; ".join(findings),
    )


# Secrets that must never be written (fakes: the shapes of real keys, nothing that works).
SECRETS = {
    "cabecera Authorization": "Bearer abc123SECRETvalue9876",
    "cookie": "session=SESSIONsecret12345",
    "token de GitHub": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    "clave de Anthropic": "sk-ant-api03-ENVsecretXXXXXXXXXXXXXXXXXXXX",
    "clave de OpenAI": "sk-proj-ENVsecret2YYYYYYYYYYYYYYYYYYY",
    "clave en la URL": "URLKEYsecret7777",
    "contraseña en la línea de comandos": "hunter2-secret-pw",
    "usuario:clave de curl": "BASICpass-77x",
    "clave privada": "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUPEMBODY123",
    "clave de AWS": "AKIAIOSFODNN7EXAMPLE",
    "bot de Telegram": "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
}


@scenario("secretos-en-la-caja-negra")
def test_secrets_never_reach_the_black_box(
    attack: Attack, tmp_path_factory: pytest.TempPathFactory
):
    box = Box(tmp_path_factory.mktemp("blackbox-secrets") / "box")
    box.directory.mkdir(mode=0o700)
    key = create_key(box.key)
    s = SECRETS
    with box.open(key) as black_box:
        black_box.append(Source.SYSTEM, "control", "plain-marker-in-the-open", risk=0)
        black_box.append(
            Source.NET,
            "request",
            f"curl -H 'Authorization: {s['cabecera Authorization']}' "
            f"https://api.example.invalid/x?api_key={s['clave en la URL']}",
            details={
                "headers": {
                    "Authorization": s["cabecera Authorization"],
                    "Cookie": s["cookie"],
                },
                "env": {
                    "ANTHROPIC_API_KEY": s["clave de Anthropic"],
                    "OPENAI_API_KEY": s["clave de OpenAI"],
                    "GITHUB_TOKEN": s["token de GitHub"],
                },
            },
            risk=2,
        )
        black_box.append(
            Source.EXEC,
            "run",
            f"mysql -u root --password {s['contraseña en la línea de comandos']} && "
            f"curl -u admin:{s['usuario:clave de curl']} https://example.invalid",
            details={
                "aws": s["clave de AWS"],
                "telegram": s["bot de Telegram"],
                "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"{s['clave privada']}\n-----END OPENSSH PRIVATE KEY-----",
            },
            risk=1,
        )
        # Read the raw files while the database is still open (the WAL holds recent events).
        raw_open = read_all_bytes(box.directory)
        events = black_box.events()
    raw_closed = read_all_bytes(box.directory)

    # Control: a plain word IS found in those bytes, so "no secret found" is not a blind search.
    assert b"plain-marker-in-the-open" in raw_open + raw_closed
    leaked = sorted(
        name for name, secret in SECRETS.items() if secret.encode() in raw_closed + raw_open
    )
    attack.check(
        "stopped",
        leaked == [],
        f"{len(SECRETS)} secretos distintos (cabeceras, cookie, claves de API, contraseñas en la "
        f"línea de comandos, URL, bloque de clave privada, AWS, Telegram) en el destino y en los "
        f"detalles: ninguno aparece en la base de datos, su WAL ni el punto de control"
        + (f"; FILTRADOS: {leaked}" if leaked else ""),
    )
    shown = " ".join(event.target + str(event.details) for event in events)
    attack.check(
        "recorded",
        len(events) == 3 and "[REDACTED]" in shown and box_is_intact(box, key),
        "los eventos sí quedan grabados, con [REDACTED] donde estaba el secreto, y la cadena "
        "sigue íntegra",
    )


def read_all_bytes(directory: Path) -> bytes:
    """Everything the black box wrote beside its key: database, WAL, shared memory, checkpoint."""
    return b"".join(
        path.read_bytes() for path in sorted(directory.iterdir()) if path.name != "blackbox.key"
    )


def box_is_intact(box: Box, key: bytes) -> bool:
    with box.open(key) as black_box:
        return black_box.verify().ok
