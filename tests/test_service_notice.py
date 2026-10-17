"""The fixed notice of a rewind (docs/19, section 7): one text for the CLI, Telegram and the web."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from backtide.jail import openclaw
from backtide.service.notice import ago, rewind_notice

TAKEN = datetime(2026, 10, 16, 11, 50, tzinfo=UTC)
NOW = TAKEN + timedelta(minutes=10)
MADRID = timezone(timedelta(hours=2))


def text_of(paragraphs: tuple[str, ...]) -> str:
    return " ".join(" ".join(paragraphs).split())


def test_it_says_when_in_local_time_and_how_long_ago() -> None:
    first = rewind_notice(TAKEN, now=NOW, tz=MADRID)[0]
    assert first == "Vas a volver a las 13:50:00 del 2026-10-16 (hace 10 min)."


def test_it_says_what_comes_back() -> None:
    text = text_of(rewind_notice(TAKEN, now=NOW, tz=MADRID))
    assert "Se deshace: los archivos de trabajo del agente" in text
    assert "Todo lo que guarda en su carpeta vuelve a como estaba" in text
    assert "lo que recuerda (memoria y conversaciones)" in text


def test_it_says_what_does_not_come_back() -> None:
    text = text_of(rewind_notice(TAKEN, now=NOW, tz=MADRID))
    assert "No se deshace: lo que el agente ya ha enviado fuera" in text
    assert "lo que ya salió de la máquina no vuelve" in text
    # Class C (docs/19, section 7): the config, its tokens and who may talk to the agent.
    assert "quién puede hablar con él" in text
    # ...but what the agent logged into by itself lives in its HOME, inside the rewind.
    assert "sesiones que el agente haya iniciado él mismo en sus herramientas" in text
    assert "la caja negra" in text


def test_it_says_what_the_agent_will_and_will_not_remember() -> None:
    text = text_of(rewind_notice(TAKEN, now=NOW, tz=MADRID))
    assert "no recordará nada posterior a esa hora aunque tus chats sí lo muestren" in text
    assert "puede reenviar algún mensaje que estuviera en cola" in text


def test_it_ends_with_the_undo_point() -> None:
    last = rewind_notice(TAKEN, now=NOW, tz=MADRID)[-1]
    assert last == "Se guarda un punto para deshacer el rebobinado."


def test_the_channel_lines_come_from_the_openclaw_profile() -> None:
    paragraphs = rewind_notice(TAKEN, now=NOW, tz=MADRID)
    for line in openclaw.REWIND_NOTICE_LINES:
        assert line in paragraphs
    text = text_of(paragraphs)
    assert "Telegram" in text
    assert "WhatsApp y Signal no se pueden usar en esta versión" in text
    assert "IMAP" in text
    assert "volvería a leer el correo llegado desde esa hora" in text


def test_another_agent_brings_its_own_lines() -> None:
    paragraphs = rewind_notice(TAKEN, now=NOW, tz=MADRID, agent_lines=("Una línea propia.",))
    assert "Una línea propia." in paragraphs
    assert not any("Telegram" in paragraph for paragraph in paragraphs)
    assert paragraphs[-1] == "Se guarda un punto para deshacer el rebobinado."


def test_the_text_is_fixed_whatever_the_snapshot() -> None:
    """Nothing in it comes from the agent: only the time of the snapshot changes."""
    one = rewind_notice(TAKEN, now=NOW, tz=MADRID)
    other = rewind_notice(TAKEN - timedelta(hours=3), now=NOW, tz=MADRID)
    assert one[1:] == other[1:]


@pytest.mark.parametrize(
    ("elapsed", "said"),
    [
        (timedelta(seconds=-60), "en el futuro (¿reloj mal?)"),
        (timedelta(seconds=-3), "hace unos segundos"),
        (timedelta(seconds=59), "hace unos segundos"),
        (timedelta(minutes=10), "hace 10 min"),
        (timedelta(hours=5), "hace 5 h"),
        (timedelta(days=3), "hace 3 días"),
    ],
)
def test_ago(elapsed: timedelta, said: str) -> None:
    assert ago(elapsed) == said
