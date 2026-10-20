"""Text the agent chose, made safe to show: nothing it writes can become markup, hide in the
page, or reorder what the person reads."""

import pytest

from backtide.web.text import tail, visible


def test_html_is_escaped() -> None:
    assert str(visible("<img src=x onerror=alert(1)>")) == "&lt;img src=x onerror=alert(1)&gt;"
    assert str(visible('"><script>x</script>')) == "&#34;&gt;&lt;script&gt;x&lt;/script&gt;"


@pytest.mark.parametrize(
    ("char", "code"),
    [
        ("‮", "U+202E"),  # right-to-left override: evil‮txt.exe
        ("⁦", "U+2066"),  # bidi isolate
        ("​", "U+200B"),  # zero-width space
        ("\x1b", "U+001B"),  # escape
        ("\x00", "U+0000"),
        ("\n", "U+000A"),
        ("\r", "U+000D"),
        ("\t", "U+0009"),
        (" ", "U+00A0"),  # no-break space looks like a space
        (" ", "U+2028"),  # line separator
        ("﻿", "U+FEFF"),
        ("\udc80", "U+DC80"),  # a lone surrogate (what a non-UTF-8 byte can become)
    ],
)
def test_invisible_and_control_characters_are_shown(char: str, code: str) -> None:
    html = str(visible(f"a{char}b"))
    assert char not in html
    assert f">{code}</span>" in html
    assert html.startswith("a<span") and html.endswith("</span>b")


def test_plain_text_is_untouched() -> None:
    text = "informe final (v2) ñandú 日本語 – 100%.txt"
    assert str(visible(text)) == text.replace("&", "&amp;")


def test_a_name_that_spells_a_marker_is_not_a_marker() -> None:
    """Only a real invisible character gets the span with class esc: text that merely looks like
    one is plain, so the page can tell them apart."""
    html = str(visible("U+202E"))
    assert "<span" not in html


def test_only_newlines_survive_when_asked_for() -> None:
    kept = str(visible("a\nb‮c", keep_newlines=True))
    assert "a\nb" in kept and "U+202E" in kept and "U+000A" not in kept


def test_limit_cuts_and_says_so() -> None:
    html = str(visible("x" * 50, 10))
    assert html == "x" * 10 + "…"
    assert str(visible("short", 10)) == "short"


def test_non_strings_are_shown_as_text() -> None:
    assert str(visible(42)) == "42"
    assert str(visible(None)) == "None"


def test_tail_keeps_the_end_of_a_path() -> None:
    assert tail("a/b/c.txt", 20) == "a/b/c.txt"
    shortened = tail("x" * 100 + "/final.txt", 20)
    assert shortened.startswith("…") and shortened.endswith("/final.txt")
    assert len(shortened) == 20


# -- printable but empty, and stacked marks ----------------------------------------------------


@pytest.mark.parametrize(
    "char",
    ["ㅤ", "ᅟ", "ᅠ", "ﾠ", "⠀", "឴", "឵", "͏", "⁣"],
)
def test_letters_that_print_as_nothing_are_shown(char: str) -> None:
    """Hangul fillers and the blank braille cell are 'printable', and look like a space: a file
    called ``report<U+3164>.exe`` must not read as ``report.exe``."""
    html = str(visible(f"report{char}.exe"))
    assert char not in html
    assert f"U+{ord(char):04X}" in html


def test_a_few_combining_marks_are_ordinary_text() -> None:
    for text in ("café", "café", "Việt", "á̂̃", "नि"):
        assert "<span" not in str(visible(text)), text


def test_a_tower_of_marks_is_one_marker_with_a_count() -> None:
    tower = "a" + "́" * 40 + "b"
    html = str(visible(tower))
    assert "́" not in html
    assert html.startswith("a<span") and html.endswith("</span>b")
    assert "U+0301×40" in html


def test_marks_with_no_letter_to_sit_on_are_shown() -> None:
    assert "U+0301×1" in str(visible("́x"))  # at the start
    assert "U+0301×2" in str(visible("a ́̂"))  # on a space


def test_enclosing_marks_count_too() -> None:
    assert "U+20DD×5" in str(visible("a" + "⃝" * 5))


def test_two_towers_are_two_markers() -> None:
    html = str(visible("a" + "́" * 9 + "b" + "̀" * 9))
    assert html.count('class="esc"') == 2


def test_visible_middle_keeps_the_end_and_marks_the_cut_as_ours() -> None:
    """Final review of T10, finding 4: an address is cut in the middle, keeping its domain,
    with a marker the agent's text cannot be (a span of ours)."""
    from backtide.web.text import visible_middle

    long = "ana@ejemplo.com." + "x" * 190 + ".malo.io"
    shown = str(visible_middle(long, 120))
    assert shown.startswith("ana@ejemplo.com.") and shown.endswith(".malo.io")
    assert f'<span class="cut">…({len(long) - 120})…</span>' in shown
    assert str(visible_middle("a<b@x.io", 120)) == "a&lt;b@x.io"
    assert "&lt;" in str(visible_middle("<" * 200 + "@x.io", 20)), "both ends escaped"
