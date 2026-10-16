"""The chat box answers from the black box alone, by rules, with no model."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import FakeClock
from tests.webkit import START, new_box
from vigia.web.ask import MAX_WINDOW, answer, normalize, parse, summarize
from vigia.web.i18n import Translator
from vigia.web.reader import BoxReader, BoxUnavailable

ES, EN = Translator("es"), Translator("en")


@pytest.mark.parametrize(
    ("question", "kind", "window"),
    [
        ("¿Qué ha hecho en la última hora?", "summary", timedelta(hours=1)),
        ("que ha hecho en la ultima hora", "summary", timedelta(hours=1)),
        ("¿Qué ha hecho en los últimos 30 minutos?", "summary", timedelta(minutes=30)),
        ("últimos 15 min", "summary", timedelta(minutes=15)),
        ("en las últimas 3 horas", "summary", timedelta(hours=3)),
        ("¿qué ha pasado en el último día?", "summary", timedelta(days=1)),
        ("resumen de la última semana", "summary", timedelta(days=7)),
        ("What has it done in the last hour?", "summary", timedelta(hours=1)),
        ("what happened in the last 45 minutes", "summary", timedelta(minutes=45)),
        ("summary of the last 2 days", "summary", timedelta(days=2)),
        ("¿Qué ha hecho?", "summary", timedelta(hours=1)),
        ("resumen", "summary", timedelta(hours=1)),
        ("what has it done", "summary", timedelta(hours=1)),
        ("últimos 99999 días", "summary", MAX_WINDOW),
    ],
)
def test_summary_questions(question: str, kind: str, window: timedelta) -> None:
    intent = parse(question)
    assert (intent.kind, intent.window) == (kind, window)


def test_today_means_since_midnight() -> None:
    for question in ("¿qué ha hecho hoy?", "what did it do today"):
        intent = parse(question)
        assert intent.kind == "summary" and intent.since_midnight


@pytest.mark.parametrize(
    "question", ["¿Cómo está el agente?", "estado", "is it running?", "status", "how is it"]
)
def test_state_questions(question: str) -> None:
    assert parse(question).kind == "state"


@pytest.mark.parametrize("question", ["", "   ", "ayuda", "help", "¿qué puedes hacer?", "comandos"])
def test_help(question: str) -> None:
    assert parse(question).kind == "help"


@pytest.mark.parametrize(
    "question",
    ["borra todo", "write me a poem", "¿por qué falló el correo de ayer?", "0 minutos", "xyz"],
)
def test_anything_else_is_not_understood(question: str) -> None:
    assert parse(question).kind == "unknown"


def test_normalize_drops_accents_and_punctuation() -> None:
    assert normalize("¿Qué ÚLTIMA   hora?!") == "que ultima hora"


def test_a_huge_question_is_cut_before_it_is_analysed() -> None:
    assert parse("x" * 10_000 + " ayuda").kind == "unknown"


@pytest.fixture
def story(tmp_path: Path):
    """A morning: an hour ago some work, then a burst of deletions, snapshots and a rewind."""
    clock = FakeClock(START)
    box = new_box(tmp_path, clock)
    box.append("system", "service_start", "")
    box.append("system", "agent_start", "")
    box.append("file", "create", "old.txt")  # 10:00:00
    clock.advance(timedelta(hours=2))  # 12:00
    box.append("snapshot", "take", "20261016T120000.000000Z-periodic")
    box.append("file", "create", "work/new.md")
    box.append("file", "modify", "work/new.md")
    for i in range(40):
        box.append("file", "delete", f"work/f{i}.txt", risk=1)
    box.append("file", "summary", ".", details={"counts": {"delete": 100, "modify": 5}})
    box.append("file", "dropped", ".", details={"reason": "queue_overflow"}, risk=1)
    box.append("snapshot", "take", "20261016T120500.000000Z-periodic")
    target = "20261016T120000.000000Z-periodic"
    box.append("snapshot", "rewind_done", target, details={"target": target}, risk=1)
    box.append("system", "agent_stop", "", details={"reason": "rewind"})
    box.append("system", "agent_start", "")
    box.append("file", "delete", "secrets.txt", risk=3)
    now = datetime.fromisoformat(box.events(newest_first=True, limit=1)[0].ts) + timedelta(
        minutes=1
    )
    reader = BoxReader(tmp_path / "blackbox.db")
    yield reader, now
    reader.close()


def ask(question: str, story, t: Translator = ES) -> str:
    reader, now = story
    reply = answer(question, reader=reader, now=now, tz=UTC, t=t)
    return "\n".join([*reply.lines, *reply.risky])


def test_the_hour_summary_counts_what_happened_since_then(story) -> None:
    text = ask("¿Qué ha hecho en la última hora?", story)
    # 1 create + 1 modify + 40 deletes written one by one, plus the summary of 100 + 5.
    assert "Archivos: 1 creado, 6 modificados, 141 borrados." in text
    assert "Se han guardado 2 instantáneas." in text
    assert "Rebobinados: 1." in text
    assert "Arranques del agente: 1. Paradas: 1." in text
    assert "Momentos en que se perdió detalle de los cambios: 1." in text
    assert "old.txt" not in text  # it was two hours ago


def test_the_delicate_moments_are_listed_with_their_sentence(story) -> None:
    text = ask("¿qué ha hecho en la última hora?", story)
    assert "Lo más delicado:" in text
    assert "Ha borrado" in text and ">secrets.txt<" in text


def test_a_longer_window_includes_older_events(story) -> None:
    text = ask("últimas 5 horas", story)
    assert "Archivos: 2 creados" in text  # old.txt and work/new.md
    assert "Arranques del agente: 2." in text


def test_a_quiet_window_says_so(story) -> None:
    reader, now = story
    later = now + timedelta(hours=10)
    reply = answer("en la última hora", reader=reader, now=later, tz=UTC, t=ES)
    assert reply.lines[-1] == "No ha pasado nada en ese tiempo."


def test_english_answers(story) -> None:
    text = ask("What has it done in the last hour?", story, EN)
    assert "Files: 1 created, 6 modified, 141 deleted." in text
    assert "2 snapshots were saved." in text
    assert "The most delicate:" in text


def test_the_state_is_told_from_the_last_signal(story) -> None:
    assert ask("¿cómo está el agente?", story) == "El agente está vigilado."


def test_today_starts_at_local_midnight(story) -> None:
    text = ask("¿qué ha hecho hoy?", story)
    assert "Desde las 00:00:00" in text and "old.txt" not in text
    assert "Archivos: 2 creados" in text  # everything since 00:00 UTC, including old.txt


def test_help_and_unknown_point_to_t15(story) -> None:
    assert "T15" in ask("ayuda", story)
    assert "T15" in ask("escríbeme un poema", story)
    assert "Eso todavía no lo sé responder." in ask("escríbeme un poema", story)


def test_a_huge_window_is_capped_and_says_so(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("vigia.web.ask.MAX_EVENTS", 5)
    box = new_box(tmp_path)
    for i in range(12):
        box.append("file", "create", f"f{i}")
    reader = BoxReader(tmp_path / "blackbox.db")
    now = START + timedelta(minutes=5)
    reply = answer("en la última hora", reader=reader, now=now, tz=UTC, t=ES)
    assert any("solo se han mirado los últimos 5" in line for line in reply.lines)
    assert any("Archivos: 5 creados" in line for line in reply.lines)


def test_an_unreadable_box_raises_for_the_page_to_explain(tmp_path: Path) -> None:
    reader = BoxReader(tmp_path / "missing.db")
    with pytest.raises(BoxUnavailable):
        answer("en la última hora", reader=reader, now=START, tz=UTC, t=ES)


def test_summarize_ignores_counts_it_cannot_trust() -> None:
    from tests.test_web_narrate import ev

    events = [
        ev(1, "file", "summary", ".", details={"counts": {"delete": "9", "create": True}}),
        ev(2, "file", "summary", ".", details={"counts": [1, 2]}),
    ]
    summary = summarize(events, START, START)
    assert dict(summary.files) == {}


def test_agent_text_in_the_answer_is_escaped(tmp_path: Path) -> None:
    box = new_box(tmp_path)
    box.append("file", "delete", "<script>alert(1)</script>.txt", risk=3)
    reader = BoxReader(tmp_path / "blackbox.db")
    reply = answer(
        "en la última hora", reader=reader, now=START + timedelta(minutes=5), tz=UTC, t=ES
    )
    text = "".join(reply.risky)
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert re.search(r"Ha borrado", text)
