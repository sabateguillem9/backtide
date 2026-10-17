import sqlite3
from pathlib import Path

import pytest

from backtide.blackbox import BlackBox, Source, create_key
from backtide.cli import MAX_LISTED_PROBLEMS, NOT_VERIFIED, main


@pytest.fixture
def key_path(tmp_path: Path) -> Path:
    path = tmp_path / "blackbox.key"
    create_key(path)
    return path


@pytest.fixture
def checkpoint(tmp_path: Path) -> Path:
    return tmp_path / "blackbox.checkpoint"


def _make_box(tmp_path: Path, key_path: Path, checkpoint: Path, count: int) -> Path:
    db = tmp_path / "blackbox.db"
    key = key_path.read_bytes()
    with BlackBox(db, key, checkpoint_path=checkpoint) as box:
        for number in range(count):
            box.append(Source.FILE, "write", f"/workspace/{number}.txt")
    return db


@pytest.fixture
def db(tmp_path: Path, key_path: Path, checkpoint: Path) -> Path:
    return _make_box(tmp_path, key_path, checkpoint, 3)


def _tamper(db: Path, *statements: str) -> None:
    conn = sqlite3.connect(db, isolation_level=None)
    conn.execute("DROP TRIGGER events_no_update")
    conn.execute("DROP TRIGGER events_no_delete")
    for statement in statements:
        conn.execute(statement)
    conn.close()


def _run(capsys: pytest.CaptureFixture[str], *args: str | Path) -> tuple[int, str, str]:
    code = main(["verificar", *(str(arg) for arg in args)])
    out, err = capsys.readouterr()
    return code, out, err


def test_an_intact_box_exits_0(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, checkpoint: Path
) -> None:
    code, out, err = _run(capsys, "--db", db, "--key", key_path, "--checkpoint", checkpoint)
    assert code == 0
    assert out == "OK: 3 eventos íntegros (último: 3)\n"
    assert err == ""


def test_without_a_checkpoint_it_warns_and_exits_0(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path
) -> None:
    code, out, _ = _run(capsys, "--db", db, "--key", key_path)
    assert code == 0
    assert out.startswith("AVISO: ")
    assert out.endswith("OK: 3 eventos íntegros (último: 3)\n")


def test_an_empty_box_exits_0(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_path: Path, checkpoint: Path
) -> None:
    db = _make_box(tmp_path, key_path, checkpoint, 0)
    code, out, _ = _run(capsys, "--db", db, "--key", key_path)
    assert code == 0
    assert "OK: 0 eventos íntegros (último: ninguno)" in out


def test_a_changed_event_exits_1_and_names_it(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, checkpoint: Path
) -> None:
    _tamper(db, "UPDATE events SET target = '/workspace/innocent.txt' WHERE seq = 2")
    code, out, _ = _run(capsys, "--db", db, "--key", key_path, "--checkpoint", checkpoint)
    assert code == 1
    assert "MANIPULADO: evento 2: la huella no coincide\n" in out
    assert "MANIPULADO: falta el trigger de solo añadir events_no_update\n" in out
    assert "OK" not in out


def test_deleting_the_last_events_exits_1_with_a_checkpoint(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, checkpoint: Path
) -> None:
    _tamper(db, "DELETE FROM events WHERE seq = 3")
    code, out, _ = _run(capsys, "--db", db, "--key", key_path, "--checkpoint", checkpoint)
    assert code == 1
    assert "MANIPULADO: evento 3: se han borrado eventos del final" in out


def test_a_long_list_of_problems_is_cut(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_path: Path, checkpoint: Path
) -> None:
    db = _make_box(tmp_path, key_path, checkpoint, MAX_LISTED_PROBLEMS + 10)
    other_key = tmp_path / "other.key"
    create_key(other_key)
    code, out, _ = _run(capsys, "--db", db, "--key", other_key)
    assert code == 1
    lines = out.splitlines()
    assert (
        lines[1] == "MANIPULADO: la clave no corresponde a esta caja negra: o es otra clave "
        "o han cambiado la de la base de datos"
    )
    assert sum(line.startswith("MANIPULADO:") for line in lines) == MAX_LISTED_PROBLEMS
    assert "… y 11 problemas más" in lines
    assert lines[-1] == f"La caja negra NO está íntegra: {MAX_LISTED_PROBLEMS + 11} problemas."


def test_a_missing_database_exits_2_and_is_not_created(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_path: Path
) -> None:
    missing = tmp_path / "missing.db"
    code, out, err = _run(capsys, "--db", missing, "--key", key_path)
    assert code == 2
    assert out == ""
    assert err.startswith("ERROR: no existe la base de datos")
    assert not missing.exists()


@pytest.mark.parametrize("content", [b"", b"short", b"x" * 33])
def test_an_invalid_key_exits_2(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path, content: bytes
) -> None:
    bad = tmp_path / "bad.key"
    bad.write_bytes(content)
    bad.chmod(0o600)
    code, _, err = _run(capsys, "--db", db, "--key", bad)
    assert code == 2
    assert err.startswith("ERROR: clave no válida")


def test_a_key_open_to_others_exits_2(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path
) -> None:
    key_path.chmod(0o644)
    code, _, err = _run(capsys, "--db", db, "--key", key_path)
    assert code == 2
    assert "clave no válida" in err


def test_a_missing_key_exits_2(
    capsys: pytest.CaptureFixture[str], db: Path, tmp_path: Path
) -> None:
    code, _, err = _run(capsys, "--db", db, "--key", tmp_path / "missing.key")
    assert code == 2
    assert "clave no válida" in err


def test_a_file_that_is_not_a_database_exits_2(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, key_path: Path
) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database at all" * 50)
    code, _, err = _run(capsys, "--db", junk, "--key", key_path)
    assert code == 2
    assert err.startswith("ERROR: no se puede leer la caja negra")
    assert NOT_VERIFIED in err


@pytest.mark.parametrize("args", [[], ["--db", "x.db"], ["--key", "x.key"], ["--bogus"]])
def test_usage_errors_exit_2(capsys: pytest.CaptureFixture[str], args: list[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["verificar", *args])
    assert exit_info.value.code == 2
    assert "usage: backtide verificar" in capsys.readouterr().err


def _tables(db: Path) -> list[str]:
    conn = sqlite3.connect(db)
    try:
        return [name for (name,) in conn.execute("SELECT name FROM sqlite_master")]
    finally:
        conn.close()


@pytest.mark.parametrize("wipe", ["drop-tables", "zero-bytes"])
def test_a_wiped_database_exits_1_and_is_never_rebuilt(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, wipe: str
) -> None:
    if wipe == "drop-tables":
        conn = sqlite3.connect(db, isolation_level=None)
        conn.execute("DROP TABLE events")
        conn.execute("DROP TABLE meta")
        conn.close()
    else:
        db.write_bytes(b"")
    before = db.read_bytes()

    code, out, _ = _run(capsys, "--db", db, "--key", key_path)  # even without a checkpoint

    assert code == 1
    assert "MANIPULADO: falta la tabla events\n" in out
    assert "OK" not in out
    assert db.read_bytes() == before
    assert _tables(db) == []


def test_an_unreadable_checkpoint_exits_2_as_not_verified(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, tmp_path: Path
) -> None:
    folder = tmp_path / "a-folder"
    folder.mkdir()
    code, out, err = _run(capsys, "--db", db, "--key", key_path, "--checkpoint", folder)
    assert code == 2
    assert out == ""
    assert err.startswith("ERROR: no se puede leer la caja negra")
    assert err.endswith(NOT_VERIFIED + "\n")


def test_names_an_attacker_chose_cannot_rewrite_the_terminal(
    capsys: pytest.CaptureFixture[str], db: Path, key_path: Path, checkpoint: Path
) -> None:
    fake_ok = "\x1b[2K\x1b[1AOK: 3 eventos íntegros"
    conn = sqlite3.connect(db, isolation_level=None)
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute(
        "INSERT INTO sqlite_master VALUES ('table', ?, ?, 0, 'CREATE TABLE x(')", (fake_ok, fake_ok)
    )
    conn.close()

    code, out, err = _run(capsys, "--db", db, "--key", key_path, "--checkpoint", checkpoint)

    assert code == 1
    assert "\x1b" not in out + err
    assert "\\x1b[2K" in out
    assert "MANIPULADO" in out
