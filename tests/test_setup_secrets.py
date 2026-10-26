"""The installer's keys (docs/25, section 3; T13-3): read without an argument, written 0600."""

import io
import os
import stat
from pathlib import Path

import pytest

from backtide.setup import secrets
from backtide.setup.secrets import SecretError, Written

KEY = "sk-ant-api03-" + "x7Kq2mW9pL4vN8rB3cY6hJ1dF5gS0aZt" * 2


@pytest.fixture
def keys(tmp_path: Path) -> Path:
    folder = tmp_path / "keys"
    folder.mkdir(mode=0o700)
    return folder


def test_a_key_file_gives_its_one_line(tmp_path: Path) -> None:
    path = tmp_path / "key.txt"
    path.write_text(f"  {KEY}  \n")
    assert secrets.from_file(path) == KEY


@pytest.mark.parametrize(
    ("content", "said"),
    [
        (b"", "vacío"),
        (b"\n\n", "vacío"),
        (b"zqvlinea1\nzqvlinea2\n", "2 líneas"),
        (b"\xff\xfe", "UTF-8"),
        (b"zqv" * secrets.MAX_SECRET_BYTES, "demasiado grande"),
    ],
    ids=["empty", "blank-lines", "two-lines", "not-utf8", "too-big"],
)
def test_what_is_not_one_key_is_refused_without_quoting_it(
    tmp_path: Path, content: bytes, said: str
) -> None:
    path = tmp_path / "key.txt"
    path.write_bytes(content)
    with pytest.raises(SecretError, match=said) as caught:
        secrets.from_file(path)
    assert "zqv" not in str(caught.value)


def test_a_link_or_a_folder_is_never_read(tmp_path: Path) -> None:
    target = tmp_path / "real.txt"
    target.write_text(KEY)
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(SecretError, match="no se puede abrir"):
        secrets.from_file(tmp_path / "link")
    with pytest.raises(SecretError, match="no es un archivo normal"):
        secrets.from_file(tmp_path)


def test_stdin_and_the_terminal() -> None:
    assert secrets.from_stream(io.BytesIO(KEY.encode() + b"\n")) == KEY
    assert secrets.ask("Clave: ", reader=lambda prompt: KEY) == KEY
    with pytest.raises(SecretError, match="vacío"):
        secrets.ask("Clave: ", reader=lambda prompt: "")

    def interrupted(prompt: str) -> str:
        raise KeyboardInterrupt

    with pytest.raises(SecretError, match="ninguna clave"):
        secrets.ask("Clave: ", reader=interrupted)


def test_the_shape_is_the_settings_pages_rule() -> None:
    secrets.check("anthropic", KEY)
    with pytest.raises(SecretError, match="no parece una clave de anthropic") as caught:
        secrets.check("anthropic", "sk-proj-ThisIsAnOpenAiKey0123456789")
    assert "ThisIsAnOpenAiKey" not in str(caught.value)
    secrets.check("openai", "sk-proj-ThisIsAnOpenAiKey0123456789")


def test_write_makes_a_0600_file_and_says_what_it_did(keys: Path) -> None:
    assert secrets.write(keys, "anthropic.key", KEY) is Written.CREATED
    path = keys / "anthropic.key"
    assert path.read_text() == KEY + "\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    before = os.stat(path)
    assert secrets.write(keys, "anthropic.key", KEY) is Written.UNCHANGED
    assert os.stat(path).st_mtime_ns == before.st_mtime_ns  # not even rewritten
    assert secrets.write(keys, "anthropic.key", KEY[:-1] + "Q") is Written.REPLACED
    assert path.read_text() == KEY[:-1] + "Q\n"
    assert [p.name for p in keys.iterdir()] == ["anthropic.key"]  # no temporary file left


def test_write_refuses_a_folder_open_to_others(tmp_path: Path) -> None:
    folder = tmp_path / "keys"
    folder.mkdir()
    folder.chmod(0o755)
    with pytest.raises(SecretError, match="no se puede escribir"):
        secrets.write(folder, "anthropic.key", KEY)
    folder.chmod(0o710)  # the state folder (D25): fine for the token, not for the keys
    with pytest.raises(SecretError):
        secrets.write(folder, "anthropic.key", KEY)
    assert secrets.write(folder, "gateway.token", "t" * 43, private_dir=False) is Written.CREATED


def test_write_never_goes_through_a_link_or_reads_an_open_file(keys: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("keep")
    (keys / "anthropic.key").symlink_to(elsewhere)
    with pytest.raises(SecretError, match="no es un archivo normal"):
        secrets.write(keys, "anthropic.key", KEY)
    assert elsewhere.read_text() == "keep"
    (keys / "anthropic.key").unlink()
    (keys / "anthropic.key").write_text(KEY)
    (keys / "anthropic.key").chmod(0o644)
    with pytest.raises(SecretError, match="no es 0600"):
        secrets.write(keys, "anthropic.key", KEY)


def test_a_new_token_is_long_and_fresh() -> None:
    first, second = secrets.new_token(), secrets.new_token()
    assert first != second and len(first) >= 43
