"""The glob of the risk rules (T08): what it matches, what it refuses, and that it cannot be made
slow by the text it reads (the agent chooses the text)."""

import time

import pytest

from vigia.analyzer.glob import MAX_GLOB_CHARS, MAX_STARS, Glob


def matches(pattern: str, text: str) -> bool:
    return Glob.compile(pattern).match(text)


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "abcd", False),
        ("abc", "ab", False),
        ("", "x", None),  # refused: see below
        ("*", "", True),
        ("*", "any/thing/at all", True),
        ("*.pem", "keys/server.pem", True),
        ("*.pem", "server.pem.bak", False),
        ("*/.ssh/*", "work/.ssh/id_rsa", True),
        ("*/.ssh/*", ".ssh/id_rsa", False),
        (".ssh/*", ".ssh/id_rsa", True),
        ("a?c", "abc", True),
        ("a?c", "ac", False),
        ("a?c", "abbc", False),
        ("a*b*c", "aXXbYYc", True),
        ("a*b*c", "aXXbYY", False),
        ("a*b*c", "abcabc", True),
        ("*a*a*a*b", "aaaaaaaaaab", True),
        ("**", "x", True),
        ("rm -rf /", "rm -rf /", True),
        ("rm -rf /", "rm -rf /tmp", False),
        ("rm -rf /[*]", "rm -rf /*", True),
        ("rm -rf /[*]", "rm -rf /tmp", False),
        ("[abc]x", "bx", True),
        ("[abc]x", "dx", False),
        ("[a-c]x", "bx", True),
        ("[a-c]x", "dx", False),
        ("[!a-c]x", "dx", True),
        ("[!a-c]x", "bx", False),
        ("[]]x", "]x", True),
        ("é*", "éa", True),
    ],
)
def test_matching(pattern: str, text: str, expected: bool | None) -> None:
    if expected is None:
        with pytest.raises(ValueError):
            Glob.compile(pattern)
    else:
        assert matches(pattern, text) is expected


def test_it_is_case_sensitive() -> None:
    assert not matches("*.pem", "KEY.PEM")


def test_a_class_finds_control_characters_and_nothing_else() -> None:
    pattern = "*[\u0000-\u001f‮]*"
    assert matches(pattern, "work/a\nb")
    assert matches(pattern, "work/a\x1b[2Jb")
    assert matches(pattern, "work/‮gpj.exe")
    assert not matches(pattern, "work/plain name.txt")


@pytest.mark.parametrize(
    "pattern",
    ["[abc", "[]", "[z-a]x", "x" * (MAX_GLOB_CHARS + 1), "*a" * (MAX_STARS + 1), 5, None],
)
def test_bad_patterns_are_refused_in_spanish(pattern: object) -> None:
    with pytest.raises(ValueError, match=r"patr|rango|«|\[") as error:
        Glob.compile(pattern)  # type: ignore[arg-type]
    assert str(error.value)


def test_a_range_error_does_not_echo_raw_control_characters() -> None:
    with pytest.raises(ValueError) as error:
        Glob.compile("[\x1b-\x01]")
    assert "\x1b" not in str(error.value)


def test_the_pattern_at_the_limit_works() -> None:
    assert matches("a" * MAX_GLOB_CHARS, "a" * MAX_GLOB_CHARS)
    pattern = "*a" * MAX_STARS
    assert matches(pattern, "a" * 40)


def test_the_worst_text_for_the_most_stars_is_still_fast() -> None:
    """What a regex would take for ever on: many stars and a text that almost matches."""
    pattern = ("*a" * MAX_STARS) + "b"
    text = "a" * 4096
    began = time.perf_counter()
    for _ in range(20):
        assert not matches(pattern, text)
    assert time.perf_counter() - began < 5.0


def test_the_longest_pattern_against_the_longest_text_is_fast() -> None:
    pattern = "*" + "a?" * 50 + "z"
    began = time.perf_counter()
    assert not matches(pattern, "a" * 4096)
    assert time.perf_counter() - began < 2.0
