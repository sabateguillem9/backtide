"""Events told as short sentences, bursts folded into one line."""

from datetime import UTC, datetime, timedelta

import pytest

from backtide.blackbox import Event, Source
from backtide.web.i18n import Translator
from backtide.web.narrate import Counts, Narrator, line_for, sentence

START = datetime(2026, 10, 16, 10, 0, tzinfo=UTC)
ES, EN = Translator("es"), Translator("en")


def ev(
    seq: int,
    source: str,
    action: str,
    target: str = "",
    *,
    at: float = 0.0,
    details: dict | None = None,
    risk: int = 0,
) -> Event:
    when = START + timedelta(seconds=at)
    return Event(
        seq=seq,
        ts=when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        source=Source(source),
        action=action,
        target=target,
        details=details or {},
        risk=risk,
        snapshot_id=None,
        prev_hash="0" * 64,
        hash="1" * 64,
    )


def say(event: Event, t: Translator = ES) -> str:
    line = line_for(event)
    return str(sentence(t, line.key, line.params, UTC))


def plain(html: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", html)


def test_one_file_one_sentence() -> None:
    assert plain(say(ev(1, "file", "create", "notas.md"))) == "Ha creado notas.md"
    assert plain(say(ev(1, "file", "modify", "a/b.txt"))) == "Ha modificado a/b.txt"
    assert plain(say(ev(1, "file", "delete", "x.txt"))) == "Ha borrado x.txt"
    moved = ev(1, "file", "move", "new.txt", details={"from": "old.txt"})
    assert plain(say(moved)) == "Ha movido old.txt a new.txt"


def test_folders_are_said_as_folders() -> None:
    assert plain(say(ev(1, "file", "create", "work", details={"type": "dir"}))) == (
        "Ha creado la carpeta work"
    )
    assert plain(say(ev(1, "file", "delete", "work", details={"type": "dir"}))) == (
        "Ha borrado la carpeta work"
    )


def test_the_same_in_english() -> None:
    assert plain(say(ev(1, "file", "create", "notas.md"), EN)) == "Created notas.md"
    assert plain(say(ev(1, "system", "agent_start"), EN)) == "The agent started"


def test_a_burst_of_deletions_is_one_line_with_a_count() -> None:
    events = [ev(i, "file", "delete", f"work/f{i}.txt", at=i * 0.01) for i in range(1, 383)]
    (line,) = Narrator().feed(events)
    html = sentence(ES, line.key, line.params, UTC)
    assert plain(str(html)) == "Ha borrado 382 archivos, entre ellos work/f1.txt"
    assert line.id == 1 and line.last_seq == 382


def test_folders_and_files_get_the_right_noun() -> None:
    dirs = [ev(i, "file", "create", f"d{i}", details={"type": "dir"}) for i in (1, 2, 3)]
    (line,) = Narrator().feed(dirs)
    assert "3 carpetas" in plain(str(sentence(ES, line.key, line.params, UTC)))
    mixed = dirs + [ev(4, "file", "create", "f", details={"type": "file"})]
    (line,) = Narrator().feed(mixed)
    assert "4 elementos" in plain(str(sentence(ES, line.key, line.params, UTC)))


def test_another_action_or_kind_of_event_closes_the_burst() -> None:
    events = [
        ev(1, "file", "delete", "a"),
        ev(2, "file", "delete", "b"),
        ev(3, "file", "create", "c"),
        ev(4, "system", "agent_stop", details={"reason": "rewind"}),
        ev(5, "file", "delete", "d"),
    ]
    lines = Narrator().feed(events)
    assert [(line.id, line.count) for line in lines] == [(1, 2), (3, 1), (4, 1), (5, 1)]


def test_a_pause_of_more_than_30_seconds_closes_the_burst() -> None:
    events = [
        ev(1, "file", "modify", "a", at=0),
        ev(2, "file", "modify", "a", at=10),
        ev(3, "file", "modify", "a", at=41),
    ]
    assert [line.count for line in Narrator().feed(events)] == [2, 1]


def test_the_stream_keeps_folding_across_polls_and_returns_the_changed_line() -> None:
    narrator = Narrator()
    first = narrator.feed([ev(i, "file", "delete", f"f{i}") for i in (1, 2)])
    assert [(line.id, line.count) for line in first] == [(1, 2)]
    second = narrator.feed([ev(3, "file", "delete", "f3", at=1)])
    assert [(line.id, line.count) for line in second] == [(1, 3)]  # same id: it is replaced
    third = narrator.feed([ev(4, "snapshot", "take", "s", at=2), ev(5, "file", "delete", "g")])
    assert [(line.id, line.count) for line in third] == [(4, 1), (5, 1)]


def test_the_burst_takes_the_highest_risk() -> None:
    events = [ev(1, "file", "delete", "a", risk=0), ev(2, "file", "delete", "b", risk=2)]
    (line,) = Narrator().feed(events)
    assert line.risk == 2


def test_hostile_names_are_escaped_and_invisible_characters_shown() -> None:
    nasty = 'work/"><img src=x onerror=alert(1)>‮txt.exe\x1b[31m'
    html = str(say(ev(1, "file", "create", nasty)))
    assert "<img" not in html and "onerror=alert(1)>" not in html
    assert "&lt;img" in html
    assert "‮" not in html and "\x1b" not in html
    assert ">U+202E</span>" in html and ">U+001B</span>" in html
    assert html.count("<span") == 1 + 2  # the name's span and two markers


def test_a_name_cannot_inject_fields_or_markup_through_the_template() -> None:
    html = str(say(ev(1, "file", "create", "{path} {n} {noun}")))
    assert "{path} {n} {noun}" in html


def test_long_paths_keep_their_end() -> None:
    long = "d/" * 200 + "important.docx"
    assert plain(say(ev(1, "file", "delete", long))).endswith("important.docx")


def test_a_summary_is_told_in_counts() -> None:
    event = ev(
        1, "file", "summary", ".", details={"counts": {"delete": 380, "create": 2, "bogus": 9}}
    )
    assert plain(say(event)) == "Muchos cambios a la vez: 382 elementos (2 creados, 380 borrados)"
    assert plain(say(event, EN)) == "Many changes at once: 382 items (2 created, 380 deleted)"


def test_a_summary_with_nonsense_counts_does_not_break() -> None:
    event = ev(1, "file", "summary", ".", details={"counts": "lots"})
    assert "0 elementos" in plain(say(event))
    event = ev(1, "file", "summary", ".", details={"counts": {"delete": True, "create": -3}})
    assert "0 elementos" in plain(say(event))
    assert Counts().ORDER == ("create", "modify", "delete", "move")


def test_dropped_says_why() -> None:
    event = ev(1, "file", "dropped", ".", details={"reason": "queue_overflow"}, risk=1)
    assert "demasiados cambios de golpe" in say(event)


def test_system_events() -> None:
    assert say(ev(1, "system", "service_start")) == "backtide ha empezado a vigilar"
    assert say(ev(1, "system", "agent_stop", details={"reason": "rewind"})) == (
        "El agente se ha parado (por un rebobinado)"
    )
    assert say(ev(1, "system", "agent_stop", details={"reason": "something new"})) == (
        "El agente se ha parado"
    )
    assert "congelado" in say(ev(1, "system", "space_pause", details={"frozen": True}))
    assert "parado" in say(ev(1, "system", "space_pause", details={"frozen": False}))


def test_snapshot_events_name_the_time_of_the_target() -> None:
    target = "20261016T093015.000000Z-periodic"
    done = ev(1, "snapshot", "rewind_done", target, details={"target": target})
    assert say(done) == "El espacio de trabajo ha vuelto a las 09:30:15"
    problems = ev(
        1, "snapshot", "rewind_done", target, details={"target": target, "problems": ["x"]}
    )
    assert "con problemas" in say(problems)
    unknown = ev(1, "snapshot", "rewind_failed", "nonsense", details={"target": 5})
    assert say(unknown) == "No se ha podido volver a las ?"


def test_a_snapshot_take_is_a_mark() -> None:
    line = line_for(ev(1, "snapshot", "take", "20261016T093015.000000Z-periodic"))
    assert line.mark


@pytest.mark.parametrize("source", ["exec", "net", "llm", "gate"])
def test_future_sources_have_a_sentence_too(source: str) -> None:
    html = say(ev(1, source, "run", "curl <evil>"))
    assert "&lt;evil&gt;" in html and "<evil>" not in html


def test_unknown_events_are_still_told() -> None:
    assert plain(say(ev(1, "system", "never_seen", "x"))) == "system · never_seen · x"
    assert plain(say(ev(1, "file", "chmod", ""))) == "file · chmod"


def test_agent_text_is_never_taken_as_a_format_string() -> None:
    html = say(ev(1, "system", "never_seen", "{0.__class__}"))
    assert "{0.__class__}" in html


# -- hostile reasons, broken lines, summaries ---------------------------------------------------


def test_a_missing_key_is_never_formatted() -> None:
    """The key can be built from what the agent wrote ("dropped.{reason}"): formatting it would
    let ``{0.__class__}`` read attributes (and a missing field would raise forever)."""
    t = Translator("es")
    assert t("dropped.{0.__class__}") == "dropped.{0.__class__}"
    assert t("no.such.key", n=1) == "no.such.key"
    assert t("{x}") == "{x}"


@pytest.mark.parametrize("reason", ["{0.__class__}", "{reason}", "a{", "}", "../..", "", None, 5])
def test_an_unknown_dropped_reason_is_told_as_another_reason(reason: object) -> None:
    event = ev(1, "file", "dropped", ".", details={"reason": reason}, risk=1)
    html = say(event)
    assert "otro motivo" in html
    assert "__class__" not in html
    assert "otro motivo" not in say(
        ev(1, "file", "dropped", ".", details={"reason": "queue_overflow"})
    )


def test_a_line_that_cannot_be_told_is_a_generic_line_and_the_failure_is_logged(
    monkeypatch, caplog
) -> None:
    from backtide.web import narrate

    line = line_for(ev(7, "file", "create", "x"))

    def broken(*args, **kwargs):
        raise KeyError("boom")

    monkeypatch.setattr(narrate, "sentence", broken)
    with caplog.at_level("ERROR"):
        html = str(narrate.safe_sentence(ES, line, UTC))
    assert "file · create" in html
    assert any("cannot tell" in r.message for r in caplog.records)


def test_a_summary_right_after_a_burst_of_the_same_action_is_the_same_line() -> None:
    """The watcher writes the first few thousand records one by one and the rest as a summary:
    the person sees one burst, not the same deletion told twice."""
    events = [ev(i, "file", "delete", f"f{i}") for i in range(1, 41)]
    events.append(ev(41, "file", "summary", ".", at=3, details={"counts": {"delete": 342}}, risk=0))
    (line,) = Narrator().feed(events)
    assert line.count == 382 and line.id == 1 and line.last_seq == 41
    assert "Ha borrado 382 archivos" in plain(str(sentence(ES, line.key, line.params, UTC)))


def test_a_summary_of_something_else_or_much_later_stays_a_line_of_its_own() -> None:
    other = [
        ev(1, "file", "delete", "a"),
        ev(2, "file", "summary", ".", details={"counts": {"create": 9}}),
    ]
    assert [line.count for line in Narrator().feed(other)] == [1, 1]
    late = [
        ev(1, "file", "delete", "a"),
        ev(2, "file", "summary", ".", at=90, details={"counts": {"delete": 9}}),
    ]
    assert len(Narrator().feed(late)) == 2
    mixed = [
        ev(1, "file", "delete", "a"),
        ev(2, "file", "summary", ".", details={"counts": {"delete": 9, "modify": 4}}),
    ]
    assert len(Narrator().feed(mixed)) == 2


def test_a_summary_alone_is_still_told() -> None:
    (line,) = Narrator().feed([ev(1, "file", "summary", ".", details={"counts": {"delete": 5}})])
    assert "Muchos cambios a la vez: 5 elementos" in plain(
        str(sentence(ES, line.key, line.params, UTC))
    )


def test_the_summary_grows_the_burst_in_place_for_the_stream() -> None:
    narrator = Narrator()
    (first,) = narrator.feed([ev(1, "file", "delete", "a"), ev(2, "file", "delete", "b")])
    (again,) = narrator.feed([ev(3, "file", "summary", ".", details={"counts": {"delete": 8}})])
    assert again.id == first.id == 1 and again.count == 10


# -- a provider waiting for its key (docs/21, section 6) ----------------------------------------


def test_a_provider_without_its_key_is_told_plainly() -> None:
    no_key = ev(1, "llm", "blocked", "anthropic", details={"reason": "no_key", "count": 3})
    assert plain(say(no_key)) == (
        "No ha podido usar el modelo anthropic: falta su clave (ponla en Ajustes)"
    )
    capped = ev(2, "llm", "blocked", "", details={"reason": "spend_cap"})
    assert plain(say(capped)) == "Una llamada al modelo se ha rechazado antes de salir"
    waiting = ev(3, "system", "provider_waiting", details={"provider": "anthropic",
                                                          "problem": "missing"})  # fmt: skip
    assert plain(say(waiting)) == (
        "anthropic no tiene clave: el agente no puede usar el modelo hasta que la pongas en Ajustes"
    )
    broken = ev(4, "system", "provider_waiting", details={"provider": "<b>x</b>",
                                                         "problem": "unusable"})  # fmt: skip
    html = say(broken)
    assert "&lt;b&gt;" in html and "<b>x" not in html and "no se puede usar" in html
    assert plain(say(ev(5, "system", "provider_ready", details={"provider": "openai"}), EN)) == (
        "openai has its key now"
    )
