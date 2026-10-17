"""The words of the web: both languages complete, and the language negotiated."""

import re
from pathlib import Path

import pytest

from backtide.web.i18n import DEFAULT_LANGUAGE, EN, ES, Translator, negotiate

FIELDS = re.compile(r"\{(\w+)\}")


def test_both_languages_have_the_same_keys() -> None:
    assert set(ES) == set(EN)


def test_both_languages_use_the_same_fields_in_each_string() -> None:
    differing = {
        key: (FIELDS.findall(ES[key]), FIELDS.findall(EN[key]))
        for key in ES
        if set(FIELDS.findall(ES[key])) != set(FIELDS.findall(EN[key]))
    }
    assert differing == {}


def test_no_string_is_empty_or_ends_in_an_exclamation() -> None:
    for strings in (ES, EN):
        for key, text in strings.items():
            assert text.strip(), key
            assert "!" not in text, f"{key}: calm copy has no exclamation marks"


def test_the_name_is_written_in_lowercase() -> None:
    for strings in (ES, EN):
        for text in strings.values():
            assert "Backtide" not in text and "BackTide" not in text


def test_every_template_key_exists() -> None:
    """Every t('literal.key') of a template is a real key (computed keys are checked by the
    tests of the pages)."""
    used: set[str] = set()
    for path in (Path(__file__).parent.parent / "backtide/web/templates").glob("*.html"):
        used |= set(re.findall(r"""\bt\(\s*'([\w.]+)'""", path.read_text()))
    assert used, "found no keys: the pattern is wrong"
    literal = {key for key in used if not key.endswith(".")}
    assert literal <= set(ES)
    # t('risk.' ~ n), t('state.' ~ state), t('hist.range.' ~ r): the keys they can build
    assert {f"risk.{n}" for n in range(4)} <= set(ES)
    assert {f"state.{s}" for s in ("watched", "frozen", "stopped", "unknown")} <= set(ES)
    assert {f"hist.range.{r}" for r in ("1h", "24h", "7d", "all")} <= set(ES)


def test_translator_formats_and_pluralises() -> None:
    t = Translator("en")
    assert t("age.min", n=5) == "5 min ago"
    assert t.plural("chat.snapshots", 1) == "1 snapshot was saved."
    assert t.plural("chat.snapshots", 3) == "3 snapshots were saved."
    assert Translator("es").plural("chat.snapshots", 2) == "Se han guardado 2 instantáneas."


def test_an_unknown_language_falls_back_to_the_default() -> None:
    assert Translator("fr").language == DEFAULT_LANGUAGE


def test_missing_key_shows_the_key_not_a_crash() -> None:
    assert Translator("es").raw("no.such.key") == "no.such.key"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, "es"),
        ("", "es"),
        ("en-US,en;q=0.9", "en"),
        ("es-ES,es;q=0.9,en;q=0.8", "es"),
        ("fr-FR,fr;q=0.9,en;q=0.5", "en"),
        ("fr", "es"),
        ("en;q=0.2, es;q=0.8", "es"),
        ("en;q=0", "es"),
        ("en;q=abc", "es"),
        ("*", "es"),
    ],
)
def test_negotiate(header: str | None, expected: str) -> None:
    assert negotiate(header) == expected
