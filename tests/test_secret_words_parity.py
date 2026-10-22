r"""Invariant 5: the three barriers that strike secrets agree on which names are secret.

The same table goes through redact (backtide/blackbox/redact.py, every recorded text), the
process sensor's second barrier (backtide/sensors/procs.py, safe_text) and the first one,
Tetragon's RE2 rules (backtide/jail/sensor.py, REDACTION_FILTERS), each on its own and, as in
production, chained: what reaches the black box is procs' reading of what Tetragon wrote. The
rules run in order over the text earlier ones struck, so a rule that strikes the wrong word can
take away the anchor a later one needs: the chain test is the one that sees that.

The RE2 rules are run here with Python's ``re`` in ASCII mode: they use only the subset both
engines read the same way (no lookaround, no possessive, no backreference; test_jail_sensor.py
checks that shape), and ``re.ASCII`` gives ``\s``, ``\w`` and ``\b`` Go's ASCII meaning (a
no-break space is no separator in either). What the simulation cannot show: Python's ASCII
``\s`` also takes a vertical tab, Go's does not; Go's ``(?i)`` folds a few non-ASCII letters
(the Kelvin sign as k), which only strikes more. The VM checks the rules with Tetragon itself
(tests/integration/test_sensor_review.py).

Accepted limits (docs/23, section 5). The rules the earlier reviews checked keep the words they
were checked with (secret_words' ``*_BASE``) and their place in the order; the whole word lists
are in rules that run last (Tetragon: REDACTION_LAST_RULES, where the wrapped-element rule
strikes up to the element's closing quote, only when that quote is followed by whitespace or
the end, and the others only strike a plain word; procs: _LATE_PATTERNS, after redact's). On the
second review's fuzzer corpus nothing the barriers struck before the shared words is lost
(against the commit before: 0 regressions), but:
- A scheme word or a second flag between a checked name and its value is struck instead of the
  value, as before (KNOWN_LEAKS: "--password Bearer x", "token=Bearer x", "--password
  --password x"). Skipping it takes the anchor of a later rule in other forms ("--password
  Bearer -u alice:pw", "token=Basic password 'pw'"): each way leaks something.
- A new name followed by a plain word that starts another form can still take it: the word
  can be ``token:``, ``token=``, ``password`` or ``MYSQL_PWD=`` ("signing_key: token: \"x y\"",
  KNOWN_LEAKS). Striking the word after a secret name is the rule; a targeted corpus finds
  many such forms, all of this kind. Rules never cross a line break, so multi-line text (YAML)
  is not affected.
- Each barrier on its own leaves some forms to the other (Tetragon the quoted values, procs
  "--skip-auth -u alice:pw", as before); the chain is what reaches the black box.

What is deliberately not the same is said by the table's columns:
- ``ALL``: a secret name, struck by the three.
- ``ARGV``: a command-line form only (``--pass x``, ``MYSQL_PWD=x``): the words ``pass``,
  ``pwd`` and ``auth`` are too common in prose for redact, which every text goes through.
- ``TEXT``: a JSON or Python pair (``"name": "value"``): Tetragon's rules take no quoted
  value (docs/23, section 5; test_jail_sensor.py), redact and procs do.
- ``SECOND``: a quoted value with a space, or a JSON value a cut left unclosed: the second
  barrier's (procs) only.
"""

import re

import pytest

from backtide.blackbox import secret_words
from backtide.blackbox.redact import strike_text
from backtide.jail.sensor import REDACTION_FILTERS
from backtide.sensors.procs import safe_text
from tests.scaling import assert_linear

_S = "Qx7vR2mK9pLt4ZwB"  # noqa: S105 - a fake
_T = "Vb6Yc1Df5Gh0JqR2"  # noqa: S105 - a fake


def _tetragon(text: str, binary: str = "/bin/true") -> str:
    """What Tetragon does with its filters, in order: ReplaceAllStringFunc with each rule, and
    in each match, the rule found again (FindStringSubmatchIndex on the matched text alone)
    and its capture groups made *****. A filter with a binary_regex only applies to a binary
    it matches."""
    for regex, rules in REDACTION_FILTERS:
        if regex is not None and not re.search(regex, binary, re.ASCII):
            continue
        for rule in rules:
            pattern = re.compile(rule, re.ASCII)

            def strike(match: re.Match[str], pattern: re.Pattern[str] = pattern) -> str:
                whole = match.group(0)
                again = pattern.search(whole)
                if again is None:
                    return whole
                out, last = [], 0
                for group in range(1, pattern.groups + 1):
                    if again.start(group) < 0 or again.start(group) < last:
                        continue
                    out.append(whole[last : again.start(group)] + "*****")
                    last = again.end(group)
                return "".join(out) + whole[last:]

            text = pattern.sub(strike, text)
    return text


def _chain(text: str, binary: str = "/bin/true") -> str:
    """Production: procs reads the line Tetragon already struck."""
    return safe_text(_tetragon(text, binary), tool=binary)


BARRIERS = {
    "redact": strike_text,
    "procs": safe_text,
    "sensor": _tetragon,
}
ALL = ("redact", "procs", "sensor")
ARGV = ("procs", "sensor")
TEXT = ("redact", "procs")
SECOND = ("procs",)


def _sk(length: int) -> str:
    return "sk-" + ("Qx7vR2mK9pLt4ZwBVb6Yc1Df" * 2)[:length]


SECRETS = [
    # redact's sensitive names, as name=value, --flag value, --flag=value and header lines.
    (f"signing_key={_S} run", _S, ALL),
    (f"MASTER_KEY={_S} run", _S, ALL),
    (f"encryption-key={_S} run", _S, ALL),
    (f"SECRET_KEY={_S} run", _S, ALL),
    (f"DB_PASSWORD={_S} run", _S, ALL),
    (f"x?access_token={_S}&keep=1", _S, ALL),
    (f"--encryption-key {_S} out.bin", _S, ALL),
    (f"--signing-key {_S} out.bin", _S, ALL),
    (f"--master-key={_S} out.bin", _S, ALL),
    (f"--private-key {_S} out.bin", _S, ALL),
    (f"--access-key {_S} out.bin", _S, ALL),
    (f"--api_key {_S} out.bin", _S, ALL),
    (f"--PASSWORD {_S} out.bin", _S, ALL),
    (f"--Token {_S} out.bin", _S, ALL),
    (f"--cookie {_S} out.bin", _S, ALL),
    (f"--authorization {_S} out.bin", _S, ALL),
    (f"Authorization: Bearer {_S}", _S, ALL),
    (f"curl -H 'X-Signing-Key: {_S}' x.invalid", _S, ALL),
    (f"Master-Key: {_S}", _S, ALL),
    (f'{{"master_key": "{_S}"}}', _S, TEXT),
    (f"{{'signing_key': '{_S}'}}", _S, TEXT),
    (f"env SIGNING_KEY={_S} run", _S, ALL),
    (f"Bearer {_S}", _S, ALL),
    # sk- keys: one minimum for every barrier (secret_words.SK_KEY).
    (f"key {_sk(16)} here", _sk(16), ALL),
    (f"key {_sk(19)} here", _sk(19), ALL),
    (f"key {_sk(20)} here", _sk(20), ALL),
    (f"key {_sk(24)} here", _sk(24), ALL),
    # Command-line forms only.
    (f"--pass {_S} out.bin", _S, ARGV),
    (f"--pwd {_S} out.bin", _S, ARGV),
    (f"--auth {_S} out.bin", _S, ARGV),
    (f"--db-pass={_S} out.bin", _S, ARGV),
    (f"MYSQL_PWD={_S} mysql shop", _S, ARGV),
    (f"SSHPASS={_S} sshpass -e ssh h.invalid", _S, ARGV),
    (f"REDISCLI_AUTH={_S} redis-cli ping", _S, ARGV),
    (f"mysql -uroot -p{_S} shop", _S, ARGV),
    (f"aws configure set aws_secret_access_key {_S}", _S, ARGV),
    (f"npm config set //r.invalid/:_authToken {_S}", _S, ARGV),
    (f"git config set signing_key {_S}", _S, ARGV),
    (f'"--signing-key={_S} {_T}" x', _T, ARGV),
    (f'"--master-key {_S} {_T}" x', _T, ARGV),
    (f'"--private-key={_S} {_T}" x', _T, ARGV),
    # The second barrier's.
    (f'--encryption-key "{_S} {_T}" out.bin', _S, SECOND),
    (f'--private-key "{_S} {_T}" out.bin', _S, SECOND),
    (f'--authorization "Bearer {_S}" out.bin', _S, SECOND),
    (f"signing_key = '{_S} {_T}'", _S, SECOND),
    (f'{{"signing_key": "{_S}', _S, SECOND),
    (f"{{'encryption_key': '{_S}", _S, SECOND),
]


@pytest.mark.parametrize(("text", "secret", "barriers"), SECRETS)
@pytest.mark.parametrize("barrier", sorted(BARRIERS))
def test_every_barrier_strikes_its_secrets(
    barrier: str, text: str, secret: str, barriers: tuple[str, ...]
) -> None:
    if barrier not in barriers:
        pytest.skip(f"not {barrier}'s by design (see the module's docstring)")
    struck = BARRIERS[barrier](text)
    assert secret not in struck, struck


# The reviews of the shared words: a rule that strikes the word after a secret name took away
# the anchor ("-u", "Bearer", "-b", a second "--pass") of the rule that knew the secret. The
# chain is the production path; each barrier on its own may leave one to the other.
_P = "Zq9Kx7Lm3Np5Rt8W"  # noqa: S105 - a fake
ANCHORS = [
    ("/usr/bin/curl", f"--anyauth -u alice:{_P} https://h.invalid"),
    ("/usr/bin/curl", f"-s --anyauth --user alice:{_P} https://h.invalid"),
    ("/usr/bin/curl", f"--proxy-anyauth -U alice:{_P} https://h.invalid"),
    ("/usr/bin/curl", f"--anyauth https://alice:{_P}@h.invalid"),
    ("/bin/sh", f'-c "curl --anyauth -u alice:{_P} https://h.invalid"'),
    ("/bin/sh", f'-c "curl --proxy-anyauth -U alice:{_P} https://h.invalid; ls"'),
    ("/usr/bin/mytool", f"--skip-auth -u alice:{_P}"),
    ("/usr/bin/mytool", f"--no-auth --password {_P}"),
    ("/usr/bin/x", f"--auth Bearer {_P}"),
    ("/usr/bin/x", f"--authorization Bearer {_P}"),
    ("/usr/bin/x", f"--master-key Bearer {_P}"),
    ("/usr/bin/x", f"--pass --pass {_P}"),
    ("/usr/bin/x", f"--encryption-key=--encryption-key={_P}"),
    ("/usr/bin/env", f"MASTER_KEY=Bearer {_P} run"),
    ("/usr/bin/x", f"signing_key=Bearer {_P}"),
    ("/usr/bin/x", f"--no-auth MYSQL_PWD={_P}"),
    ("/usr/bin/redis-cli", f"--no-auth-warning -a {_P} ping"),
    ("/usr/bin/openssl", f"enc -k --no-pass -pass pass:{_P}"),
    ("/usr/bin/x", f"--use-cookie -bsid={_P}"),
    # The second review: a quoted value only procs strikes, after a flag or name of the new
    # words (Tetragon wraps every element with a space in quotes).
    ("/usr/bin/curl", f'--anyauth -b "sid={_P}; theme=dark" https://h.invalid'),
    ("/usr/bin/curl", f'--anyauth -s -L --cookie "sid={_P}; x=1" https://h.invalid'),
    ("/usr/bin/curl", f'--proxy-anyauth -b "sid={_P}; x=1" https://h.invalid'),
    ("/bin/sh", f"-c \"curl --anyauth -b 'sid={_P}; x=1' https://h.invalid\""),
    ("/usr/bin/curl", f'--anyauth --pass "{_P} phrase" --cert c.pem https://h.invalid'),
    ("/usr/bin/x", f'--no-auth --token "{_P} x"'),
    ("/bin/true", f'token: -v -u "alice:{_P} x"'),
    ("/bin/true", f'token=-v --password "{_P} x"'),
    ("/bin/true", f'token: -k --user "alice:{_P} x"'),
    ("/bin/true", f'signing_key: --user "alice:{_P} x"'),
    ("/bin/true", f'signing_key: -k password "{_P}"'),
    ("/bin/true", f"token: -v token: {_P}"),
    ("/bin/true", f"token: -v identified by '{_P}'"),
    ("/usr/bin/curl", f"signing_key: -U alice:{_P}"),
    ("/bin/true", f"signing_key: Basic {_P}9/"),
    ("/bin/true", f"--no-auth Bearer Basic {_P}9/"),
    ("/bin/true", f"signing_key: X-Auth-Token: {_P}"),
    # The third review: a wrapped element's value ends at its own closing quote, not at the
    # quote that opens the next element.
    ("/bin/sh", f'-c "--private-key -b "sid={_P}; x"'),
    ("/bin/sh", f'-c "--master-key x --pass "{_P} y" z"'),
    # A scheme word, then a flag (the LOW of the second review): struck as before the change.
    ("/bin/true", f'--auth=Basic -u "alice:{_P} x"'),
    ("/bin/true", f"--password Bearer -u alice:{_P}"),
    ("/usr/bin/curl", f"MYSQL_PWD=Bearer -U alice:{_P}"),
]


@pytest.mark.parametrize(("binary", "text"), ANCHORS)
def test_no_rule_takes_another_ones_anchor(binary: str, text: str) -> None:
    struck = _chain(text, binary)
    assert _P not in struck, struck


# Accepted limits (docs/23, section 5). The rules the earlier reviews checked keep their words
# and their place: the first seven leak through them as they did before the shared words. A
# scheme word or a second flag between a checked name and its value is struck instead of the
# value; skipping it would take the anchor of a later rule in other forms ("--password Bearer
# -u alice:pw", "token=Basic password 'pw'"), which the fuzzing of the second review found. The
# last one is inherent to striking the word after a secret name: that word may start a form.
KNOWN_LEAKS = [
    ("/usr/bin/x", f"--password Bearer {_P}"),
    ("/usr/bin/x", f"--token Bearer {_P}"),
    ("/usr/bin/x", f"--token=bearer {_P}"),
    ("/usr/bin/x", f"--password --password {_P}"),
    ("/usr/bin/x", f"--no-token --token {_P}"),
    ("/bin/true", f'--no-token --token "{_P} x"'),
    ("/usr/bin/x", f"--pass=Basic {_P}"),
    ("/usr/bin/x", f"token=Bearer {_P}"),
    ("/usr/bin/x", f"MYSQL_PWD=Basic {_P} mysql"),
    # A new name, then a plain word that starts a form of its own (token:, token=, password,
    # MYSQL_PWD=): struck as the name's value. One per form of the name.
    ("/bin/true", f'signing_key: token: "{_P} x"'),
    ("/bin/true", f'SIGNING_KEY=token="{_P} y"'),
    ("/bin/true", f"--master-key password = '{_P} y'"),
    ("/bin/true", f'--private-key MYSQL_PWD="{_P} y"'),
    ("/bin/true", f"X-Master-Key: secret='{_P} y'"),
    ("/bin/true", f'config set signing_key token: "{_P} y"'),
]


@pytest.mark.parametrize(("binary", "text"), KNOWN_LEAKS)
@pytest.mark.xfail(strict=True, reason="accepted limit, docs/23 section 5")
def test_the_known_leaks_still_leak(binary: str, text: str) -> None:
    """Strict: if one of these stops leaking, move it to ANCHORS and update docs/23."""
    assert _P not in _chain(text, binary)


@pytest.mark.parametrize(("text", "secret", "barriers"), SECRETS)
def test_the_chain_strikes_every_secret(text: str, secret: str, barriers: tuple[str, ...]) -> None:
    for binary in ("/bin/true", "/bin/sh", "/usr/bin/curl", "/usr/bin/env"):
        assert secret not in _chain(text, binary), (binary, _chain(text, binary))


LOOK_ALIKES = [
    "input_tokens=5 token_count=3",
    "ls -la /tmp --color=auto",
    "setxkbmap --keyboard us",
    "monkey=1 passport=x author=me",
    "ssh --key-file a.pem host.invalid",
    "sort --sort-key name list",
    "pip install sk-learn",
    "risk-assessment-matrix-q4 ready",
    "keyring list --hotkey f5",
    "pwdx 12 --passive",
    "git commit --author me -m 'fix: 12:30 meeting'",
    "sk-short-key",
    "key_id=7 keys=3 --keys 4",
    "echo signing done; master branch",
]


@pytest.mark.parametrize("text", LOOK_ALIKES)
@pytest.mark.parametrize("barrier", [*sorted(BARRIERS), "chain"])
def test_no_barrier_strikes_a_look_alike(barrier: str, text: str) -> None:
    assert {**BARRIERS, "chain": _chain}[barrier](text) == text


def test_the_words_are_one_source() -> None:
    """Each barrier builds its rules from secret_words: no copy of its own to drift."""
    from backtide.blackbox import redact
    from backtide.jail import sensor
    from backtide.sensors import procs

    shared = {id(value) for value in vars(secret_words).values() if isinstance(value, str)}
    starts = ("(?:token|secret|passw", "(?:password|passwd|pass", "(?:pwd|pass", "sk-[")
    for module in (redact, sensor, procs):
        own = {
            name
            for name, value in vars(module).items()
            if isinstance(value, str) and value.startswith(starts) and id(value) not in shared
        }
        assert not own, (module.__name__, own)
    rules = [rule for _, rules in REDACTION_FILTERS for rule in rules]
    assert any(secret_words.SENSITIVE_WORDS in rule for rule in rules)
    assert any(secret_words.FLAG_WORDS in rule for rule in rules)
    assert any(secret_words.ENV_WORDS in rule for rule in rules)
    assert any(secret_words.CONFIG_WORDS in rule for rule in rules)
    assert any(secret_words.SK_KEY in rule for rule in rules)


def test_the_words_are_re2_shaped() -> None:
    """They go into Tetragon's RE2 rules: no lookaround, no possessive, no backreference, no
    group that captures (a capture group is what Tetragon strikes)."""
    for words in (
        secret_words.SENSITIVE_WORDS,
        secret_words.FLAG_WORDS,
        secret_words.ENV_WORDS,
        secret_words.CONFIG_WORDS,
        secret_words.SK_KEY,
    ):
        assert not re.search(r"\(\?<?[=!]|[*+?}]\+|\\[1-9]|\(\?P", words), words
        assert re.compile(words).groups == 0, words


def test_the_flag_words_hold_every_sensitive_word() -> None:
    """The union wins: a flag named like any secret name is a secret flag."""
    flag = re.compile(rf"(?i){secret_words.FLAG_WORDS}")
    for name in ("token", "secret", "password", "passwd", "api_key", "private-key", "cookie"):
        assert flag.fullmatch(name), name
    for name in ("access_key", "signing-key", "encryption_key", "masterkey", "authorization"):
        assert flag.fullmatch(name), name
    for name in ("pass", "pwd", "auth", "apikey"):
        assert flag.fullmatch(name), name


HOSTILE_UNITS = ["--password ", "--pass --password ", "-password-", "--authorization Bearer "]


@pytest.mark.parametrize("unit", HOSTILE_UNITS)
@pytest.mark.parametrize("tail", ["", "   ", '"'])
def test_redact_and_procs_stay_linear_on_runs_of_secret_flags(unit: str, tail: str) -> None:
    """The runs of secret-named flags that redact and procs now skip (one way to split each)."""
    size = 64 * 1024
    small = unit * (size // 8 // len(unit)) + tail
    large = unit * (size // len(unit)) + tail
    assert_linear(strike_text, small, large, 8, floor=0.01, cap=2.0, label=f"redact {unit!r}")
    assert_linear(safe_text, small, large, 8, floor=0.01, cap=2.0, label=f"procs {unit!r}")
