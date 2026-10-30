"""Strike secrets out of what gets recorded, and cut long texts. Pure: no I/O.

This is the second barrier (invariant 5); the first one is the proxy (T06). Redaction
errs on the side of striking too much: a lost word is better than a stored key.
"""

import functools
import html
import json
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, NoReturn
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from backtide.blackbox.secret_words import SENSITIVE_WORDS, SK_KEY

REDACTED = "[REDACTED]"
MAX_TEXT_BYTES = 4096
# Room kept for the "…[truncated N bytes]" suffix, so a cut text stays within MAX_TEXT_BYTES.
_SUFFIX_RESERVE = 64

# A name is secret when it ENDS with one of the sensitive words (secret_words, shared with both
# process-sensor barriers), so "access_token" is secret but "input_tokens" is not.
_SECRET_NAME_RE = re.compile(rf"[\w.-]*?{SENSITIVE_WORDS}")
# Payment cards (T21, docs/36 decision 11): the number, its CVV and a PIN, by the names forms and
# APIs give them. Unlike the words above, a card word must be the whole name or follow a separator
# (also a bracket, raw or %-escaped, as in card[cvc] or card%5Bcvc%5D): "pin" and "pan" are struck,
# "spin", "span" and "pincode" are not. Bare "cid" and "csc" are e-mail and other things: only
# after card or cc.
_NAME_SEP = r"(?:[-_.\[\]]|%5[bBdD])"
_CARD_W = rf"{_NAME_SEP}{{0,2}}"  # between the words of one name: card_number, card][number
_CARD_WORDS = (
    rf"(?:(?:(?:credit|debit|payment){_CARD_W})?card{_CARD_W}(?:number|num|no|nr)"
    rf"|cc{_CARD_W}(?:number|num|no)|primary{_CARD_W}account{_CARD_W}number|pan"
    rf"|(?:(?:card|cc){_CARD_W})?(?:cvv2?|cvc2?|cvn)|(?:card|cc){_CARD_W}(?:csc|cid)"
    rf"|(?:card{_CARD_W})?(?:security{_CARD_W}code|verification{_CARD_W}(?:value|code))"
    rf"|(?:(?:card|atm){_CARD_W})?pin(?:{_CARD_W}(?:number|block))?)"
)
# A name, from its first character: anything up to a separator, then the card words, then maybe
# the closing bracket of card[cvc].
_CARD_NAME = rf"(?:[\w.\[\]%-]*?{_NAME_SEP})?{_CARD_WORDS}(?:\]|%5[dD])?"
_CARD_NAME_RE = re.compile(_CARD_NAME, re.IGNORECASE)
# Headers stored as {"name": "Authorization", "value": "..."} (HAR) or similar pairs.
_PAIR_NAME_KEYS = frozenset({"name", "key", "header"})
_PAIR_VALUE_KEYS = frozenset({"value", "values"})

# Credentials that live in a URL path (the translators of T10-3 know these forms). Between the
# segments, any run of slashes, backslashes (also JSON's "\/") or their %-escapes; a token
# may be %-escaped. Only the token is struck: the ids around it stay readable.
_PATH_SEP = r"(?:[\\/]|%2f|%5c)++"
_PATH_CHAR = r"(?:[a-z0-9_.~-]|%[0-9a-f]{2})"
_PATH_REST = r"[^?#\s\"'<>]"

# Each pattern marks the part to strike with the group "secret". Order matters: whole
# blocks first, then header lines, then single tokens, then name/value pairs. A name is
# matched from its first character (the lookbehinds), which also keeps the scans linear.
_TEXT_PATTERNS = (
    # PEM private keys (and PGP's KEY BLOCK). Without its END line, struck to the end.
    re.compile(
        r"(?P<secret>-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|.*))",
        re.DOTALL,
    ),
    # JSON Web Tokens: base64url('{"...') . base64url('{"...') . signature. The payload and the
    # signature run to the end of their run, with no cap (a payload of 5 KiB is still struck);
    # possessive, and anchored at a bounded header, so the scan stays linear.
    re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_-]{1,512}+\.eyJ[A-Za-z0-9_-]++(?:\.[A-Za-z0-9_-]*+)?)"),
    # Header lines with a secret name: "Authorization: Basic ...", "X-Auth-Token: ..."
    re.compile(rf"(?i)(?<![\w-])[\w-]*?{SENSITIVE_WORDS}[ \t]*:[ \t]*(?P<secret>[^\r\n\"']+)"),
    re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/-]{8,}=*)"),
    # Basic credentials: base64 (with a digit, +, /, = or a case change, unlike a word).
    re.compile(
        r"(?i:\bbasic)\s+"
        r"(?P<secret>(?=[A-Za-z0-9+/]*(?:[0-9+/=]|[a-z][A-Z]))[A-Za-z0-9+/]{8,}={0,2})"
    ),
    re.compile(rf"\b(?P<secret>{SK_KEY})"),  # OpenAI, Anthropic
    re.compile(r"\b(?P<secret>[rs]k_(?:live|test)_[A-Za-z0-9]{16,})"),  # Stripe
    re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})"),  # Google API keys (Gemini)
    re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})"),  # GitHub
    re.compile(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,})"),  # GitLab
    re.compile(r"\b(?P<secret>xox[abprs]-[A-Za-z0-9-]{10,})"),  # Slack
    re.compile(r"\b(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})\b"),  # AWS access key id
    re.compile(r"(?<![0-9])(?P<secret>[0-9]{5,16}:[A-Za-z0-9_-]{30,})"),  # Telegram bot
    # Discord: /webhooks/{id}/{token}[/...] and /interactions/{id}/{token}/callback (also an
    # interaction's /webhooks/{app_id}/{token}/...). Its tokens are 68+ characters; 20 keeps
    # "/webhooks/1/deliveries" readable.
    re.compile(
        rf"(?i)(?:webhooks|interactions){_PATH_SEP}(?:[0-9]|%3[0-9]){{1,20}}+{_PATH_SEP}"
        rf"(?P<secret>{_PATH_CHAR}{{20,}}+)"
    ),
    # Slack's incoming webhooks: /services/T…/B…/<secret>, /workflows/T…/... and /triggers/T…/...
    # Everything after the team (after B… too, for services) goes, if one of its next four
    # segments starts with 16 letters and digits, as the secret does: "/services/translate/v2"
    # stays.
    re.compile(
        rf"(?i)(?:services|workflows|triggers){_PATH_SEP}[TE][A-Z0-9]{{1,31}}+{_PATH_SEP}"
        rf"(?:B[A-Z0-9]{{1,31}}+{_PATH_SEP})?"
        rf"(?P<secret>(?:[^?#\s\"'<>/\\%]{{0,40}}+{_PATH_SEP}){{0,3}}?[a-z0-9]{{16}}{_PATH_REST}*+)"
    ),
    # Credentials inside a URL: scheme://user:password@host
    re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://[^/\s:@]+:(?P<secret>[^/\s@]+)@"),
    # curl -u user:password, --user user:password; between quotes, to the closing one
    # (-u "alice:pass phrase", or the element "--user=alice:pass phrase").
    re.compile(r"(?<!\S)\"?(?:-u|--user)(?:[ \t]+|=)\"[^\s:\"]+:(?P<secret>[^\"\r\n]+)\""),
    re.compile(r"(?<!\S)\"(?:-u|--user)(?:[ \t]+|=)[^\s:\"]+:(?P<secret>[^\"\r\n]+)\""),
    re.compile(r"(?<!\S)(?:-u|--user)(?:[ \t]+|=)'[^\s:']+:(?P<secret>[^'\r\n]+)'"),
    re.compile(r"(?<!\S)(?:-u|--user)(?:[ \t]+|=)[^\s:]+:(?!\[REDACTED\])(?P<secret>\S+)"),
    # A flag with a secret name and its value after a space: --password hunter2. A run of them
    # (--password --password x) is skipped, so the value is struck and not the second name; one
    # dash then [\w-], so each step has one way to split (no exponential retry).
    re.compile(rf"(?i)(?<!\S)(?:-[\w-]*?{SENSITIVE_WORDS}[ \t]+)+(?P<secret>[^\s'\"]+)"),
    # URL parameters that carry a key or a signature: ?key=AIza..., &sig=...
    re.compile(r"(?i)[?&](?:key|sig|signature)=(?P<secret>[^&#\s]+)"),
    # name=value with a secret name: URL parameters, --flags, environment variables.
    re.compile(rf"(?i)(?<![\w.-])[\w.-]*?{SENSITIVE_WORDS}=(?P<secret>[^\s&#;,'\"]+)"),
    # "name": "value" with a secret name: JSON and Python reprs inside a text.
    re.compile(rf"(?i)\"[\w.-]*?{SENSITIVE_WORDS}\"\s*:\s*\"(?P<secret>(?:[^\"\\]|\\.)*)\""),
    re.compile(rf"(?i)'[\w.-]*?{SENSITIVE_WORDS}'\s*:\s*'(?P<secret>(?:[^'\\]|\\.)*)'"),
    # Card fields by name (_CARD_NAME): form and query pairs, JSON and Python reprs (strings and
    # numbers: a CVV may be sent as 123), and --flags.
    re.compile(rf"(?i)(?<![\w.\[\]%-]){_CARD_NAME}=(?P<secret>[^\s&#;,'\"]+)"),
    re.compile(rf"(?i)\"{_CARD_NAME}\"\s*:\s*\"(?P<secret>(?:[^\"\\]|\\.)*)\""),
    re.compile(rf"(?i)'{_CARD_NAME}'\s*:\s*'(?P<secret>(?:[^'\\]|\\.)*)'"),
    re.compile(rf"(?i)[\"']{_CARD_NAME}[\"']\s*:\s*(?P<secret>-?[0-9][0-9.eE+-]*)"),
    re.compile(rf"(?i)(?<!\S)--{_CARD_NAME}[ \t]+(?P<secret>[^\s'\"]+)"),
)

# A payment card number: 13 to 19 digits, maybe in groups split by a space, a dash, a "+" or a
# "%20" (a form's space), starting as every card network's numbers do (2 to 6), and Luhn-valid
# (_is_card_number), so that most other long numbers stay: a timestamp starts with 1, and only one
# in ten random numbers passes Luhn. It must be a whole run: not part of a longer one (20 digits,
# or more groups), nor the decimals of a number. Each match is bounded (at most 18 groups), so the
# scan is linear.
_CARD_NUMBER_RE = re.compile(
    r"(?<![0-9])(?<![0-9][ +.-])(?<![0-9]%20)"
    r"(?P<secret>[2-6](?:(?:[ +-]|%20)?[0-9]){12,18})"
    r"(?!(?:[ +-]|%20)?[0-9])(?!\.[0-9])"
)


def redact(value: Any) -> Any:
    """Return a copy of ``value`` with secrets struck out and every text cut to 4 KiB.

    - Mappings: the value of a secret name becomes REDACTED, whatever its type, and so
      does the "value" of a {"name": <secret name>, "value": ...} pair. Two keys that
      become equal once redacted or cut are both kept: the later one gets "#2", "#3"...
    - Pairs: in a 2-item list or tuple whose first item is a secret name, the second
      becomes REDACTED (headers as [("Cookie", "..."), ...], argv ["--password", "..."]).
    - Texts (values and keys): secret patterns are struck, lone surrogates are escaped
      so the text is valid UTF-8, and texts over MAX_TEXT_BYTES are cut.
    - Lists and tuples become lists. Other values are returned unchanged.
    """
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, list | tuple):
        if len(value) == 2 and _is_secret_name(value[0]):
            return [redact(value[0]), REDACTED]
        return [redact(item) for item in value]
    return value


def _redact_mapping(mapping: Mapping[Any, Any]) -> dict[Any, Any]:
    names_a_secret = any(
        _lower(key) in _PAIR_NAME_KEYS and _is_secret_name(item) for key, item in mapping.items()
    )
    result: dict[Any, Any] = {}
    for key, item in mapping.items():
        hidden = _is_secret_name(key) or (names_a_secret and _lower(key) in _PAIR_VALUE_KEYS)
        result[_unused_key(result, _redact_key(key))] = REDACTED if hidden else redact(item)
    return result


def _unused_key(taken: Mapping[Any, Any], key: Any) -> Any:
    """``key``, or ``key#2``, ``key#3``... if taken: never overwrite another entry."""
    if key not in taken:
        return key
    number = 2
    while f"{key}#{number}" in taken:
        number += 1
    return f"{key}#{number}"


def _lower(key: object) -> str | None:
    return key.strip().lower() if isinstance(key, str) else None


def _is_secret_name(key: object) -> bool:
    if not isinstance(key, str):
        return False
    name = key.strip().lower()
    return _SECRET_NAME_RE.fullmatch(name) is not None or _CARD_NAME_RE.fullmatch(name) is not None


def _redact_key(key: object) -> object:
    return _redact_text(key) if isinstance(key, str) else key


def _redact_text(text: str) -> str:
    return _truncate(strike_text(text))


def strike_text(
    text: str,
    on_strike: Callable[[re.Match[str]], object] | None = None,
    *,
    structured: bool = True,
) -> str:
    """The secret patterns of redact() struck out of ``text``, without cutting it: for callers
    that cut texts themselves (the process sensor keeps the head and the tail of a command).
    ``on_strike`` sees each match before it is struck (the sensor notes long strikes).
    ``structured``: end with strike_structured (the process sensor runs it itself, last)."""
    text = _to_valid_utf8(text)
    strike = _strike_secret
    if on_strike is not None:

        def strike(match: re.Match[str]) -> str:
            on_strike(match)
            return _strike_secret(match)

    for pattern in _TEXT_PATTERNS:
        text = pattern.sub(strike, text)

    def strike_card(match: re.Match[str]) -> str:
        return strike(match) if _is_card_number(match.group("secret")) else match.group(0)

    text = _CARD_NUMBER_RE.sub(strike_card, text)
    return strike_structured(text) if structured else text


# The last pass (T27-9, docs/46): the value of a subscript assignment (os.environ['X_TOKEN']='…',
# $ENV{API_KEY}="…", cfg[:api_key] = '…') and the elements of a tuple or call after a secret
# name (auth=('u', '…')). An anchor finds the name and stops after the "=" or the bracket;
# nothing it matches is ever struck. From there a local reader takes only a clean literal (one
# word between equal quotes: no quote, backslash, whitespace or shell character inside) or a
# flat tuple of them that closes. Anything else is left: a bare word is an expression in these
# languages (d['api_key'] = d['other']), and a literal with a space may span two argv elements,
# the second one a command (env "d['token']='a" rm -rf "/w'"). It runs after every other rule
# and only replaces such literals, so it adds strikes and takes nobody's anchor.
_MAX_LITERAL = 4096
_MAX_ELEMENTS = 8
# The two quotes of a "literal" may instead close one string and open the next, with code
# between them, in one argv element of python3 -c or node -e: print('d[token]=')or(exec(…))or('').
# Brackets and commas are left out, so no call, subscript or tuple fits: Python and JavaScript
# cannot call without "(". Ruby and Perl can ('+exit!+', '.exit.'): the process sensor notes a
# strike of anything but word characters (argv_struck_long), and free text has that residue.
_CLEAN = r"[^\s'\"\\;&|`$<>()\[\]{},]"
# The quotes may come escaped (\"x\" in a script that nests double quotes, or in JSON).
_LITERAL_RE = re.compile(rf"(\\?['\"])({_CLEAN}{{0,{_MAX_LITERAL}}})\1")
_ATOM_RE = re.compile(r"[\w.]{1,64}(?:\([\w., ]{0,64}\))?")
_SPACES_RE = re.compile(r"[ \t]*")


@functools.cache
def _structured_anchors(words: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """A subscript whose key ends with a secret word, then =, ||=, ??= or += (not ==, =~ or
    =>); and NAME=( , NAME=Call( , NAME='…' , or NAME=[REDACTED] where an earlier rule struck
    the "(" (or the "(" and a first element) as a plain value."""
    subscript = re.compile(
        rf"""(?i)[\[{{]:?(?P<quote>(?:\\?['"])?)[\w.-]{{0,64}}?{words}(?P=quote)[\]}}]"""
        r"[ \t]*(?:\|\||\?\?|\+)?=(?![=~>])[ \t]*"
    )
    named = re.compile(
        rf"(?i)(?<![\w.-])[\w.-]{{0,64}}?{words}[ \t]*=(?![=~>])[ \t]*"
        r"(?:(?P<call>[A-Za-z_][\w.]{0,64})?\("
        r"|(?P<struck>\[REDACTED\]|\*\*\*\*\*)(?=[ \t]*[,'\"\\])"
        r"|(?P<literal>(?=\\?['\"])))"
    )
    return subscript, named


def strike_structured(
    text: str, words: str = SENSITIVE_WORDS, on_strike: Callable[[str], object] | None = None
) -> str:
    """The last pass: strike the clean literals that are the value of a secret subscript or
    name, or the elements of its tuple (see above). ``words``: the secret words the anchors end
    with (redact's; the process sensor passes its flag words). ``on_strike`` sees each struck
    literal (the sensor notes one that may be code)."""
    out, last = [], 0
    for start, end in _structured_spans(text, words):
        if on_strike is not None:
            on_strike(text[start:end])
        out += [text[last:start], REDACTED]
        last = end
    return "".join(out) + text[last:] if out else text


def _structured_spans(text: str, words: str) -> list[tuple[int, int]]:
    """The sorted, disjoint spans strike_structured replaces."""
    subscript, named = _structured_anchors(words)
    spans: list[tuple[int, int]] = []
    pos = 0
    # Each anchor is searched again only once the pass has moved past its last match: linear.
    found = {subscript: subscript.search(text), named: named.search(text)}
    while True:
        for anchor, match in found.items():
            if match is not None and match.start() < pos:
                found[anchor] = anchor.search(text, pos)
        candidates = [match for match in found.values() if match is not None]
        if not candidates:
            break
        match = min(candidates, key=lambda candidate: candidate.start())
        if match.re is subscript:
            value = _structured_value(text, match.end())
        elif match.group("literal") is not None:
            literal = _LITERAL_RE.match(text, match.end())
            value = [literal.span(2)] if literal is not None else None
        else:
            # After an earlier strike, "(" and "get_token(" look the same: as for a call, one
            # argument is left alone and from two on, all but the first are struck.
            value = _structured_tuple(
                text,
                match.end(),
                struck_first=match.group("struck") is not None,
                call=match.group("call") is not None or match.group("struck") is not None,
            )
        if value:
            spans += [(s, e) for s, e in value if e > s and text[s:e] != REDACTED]
            pos = max(e for _, e in value)
        else:
            pos = match.end()
    disjoint: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if not disjoint or start >= disjoint[-1][1]:
            disjoint.append((start, end))
    return disjoint


def _structured_value(text: str, i: int) -> list[tuple[int, int]] | None:
    """The spans to strike in a subscript's value at ``i``: a clean literal or a flat tuple."""
    literal = _LITERAL_RE.match(text, i)
    if literal is not None:
        return [literal.span(2)]
    if text.startswith("(", i):
        return _structured_tuple(text, i + 1, struck_first=False, call=False)
    return None


def _structured_tuple(
    text: str, i: int, *, struck_first: bool, call: bool
) -> list[tuple[int, int]] | None:
    """The spans to strike in a flat tuple or argument list that starts at ``i`` (just after the
    opening bracket) and closes, or None. A literal alone is struck (token = ('…')); in a call
    one argument is left (get_token('name')); from two on, all but the first (the user)."""
    literals: list[tuple[int, int, int]] = []  # (position in the tuple, start, end)
    index = 0
    if struck_first:
        # The earlier strike took "(" alone (an element follows at once: it stopped at the quote),
        # "(" and a first element (a comma follows), or a word up to a space (Tetragon's env rule
        # takes "('u'," whole). In the last two the first element is gone.
        spaced = text[i : i + 1] in (" ", "\t")
        i = _SPACES_RE.match(text, i).end()  # type: ignore[union-attr]
        if text.startswith(",", i):
            i += 1
            index = 1
        elif spaced:
            index = 1
    count = 0
    while True:
        i = _SPACES_RE.match(text, i).end()  # type: ignore[union-attr]
        if text.startswith(")", i):
            break
        if count >= _MAX_ELEMENTS:
            return None
        literal = _LITERAL_RE.match(text, i)
        if literal is not None:
            literals.append((index, *literal.span(2)))
            i = literal.end()
        else:
            atom = _ATOM_RE.match(text, i)
            if atom is None:
                return None
            i = atom.end()
        count += 1
        index += 1
        i = _SPACES_RE.match(text, i).end()  # type: ignore[union-attr]
        if text.startswith(",", i):
            i += 1
        elif text.startswith(")", i):
            break
        else:
            return None
    if index == 1 and not call:
        return [(start, end) for _, start, end in literals]
    return [(start, end) for n, start, end in literals if n >= 1]


def _is_card_number(text: str) -> bool:
    """Whether the digits of ``text`` (a _CARD_NUMBER_RE match) pass the Luhn check."""
    total = 0
    for place, char in enumerate(reversed([c for c in text.replace("%20", "") if c.isdigit()])):
        digit = ord(char) - 48
        if place % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def _strike_secret(match: re.Match[str]) -> str:
    start, end = match.span("secret")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + REDACTED + whole[end - offset :]


def _to_valid_utf8(text: str) -> str:
    """Escape lone surrogates (undecodable file names) so the text encodes as UTF-8."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _truncate(text: str) -> str:
    data = text.encode("utf-8")
    if len(data) <= MAX_TEXT_BYTES:
        return text
    # Cut on a byte budget; "ignore" only drops a character split by the cut.
    head = data[: MAX_TEXT_BYTES - _SUFFIX_RESERVE].decode("utf-8", errors="ignore")
    dropped = len(data) - len(head.encode("utf-8"))
    return f"{head}…[truncated {dropped} bytes]"


# --- scrub_known: the secrets backtide knows (T06) ----------------------------------------------

# Shorter secrets would strike ordinary words; the configuration never holds one this short.
MIN_KNOWN_SECRET = 8
_JSON_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_PERCENT_RE = re.compile(r"%([0-9A-F])([0-9A-F])")


# A text cut by someone who did not know a secret may end with its first characters.
MIN_CUT_TAIL = 4
_PARTIAL_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{0,3}|\\|%[0-9a-fA-F]?|&#?[0-9a-zA-Z]{0,8})\Z")


def scrub_known(value: Any, secrets: Iterable[str], *, cut_tails: bool = False) -> Any:
    """Return a copy of ``value`` with each exact appearance of the given secrets (the real
    and fake keys, the Gateway token) replaced by REDACTED, in texts and in keys.

    - Also URL-encoded: ``%xx`` in any letter case, ``+`` for spaces.
    - A text in which a secret still shows once decoded some other way (partly or twice
      URL-encoded, ``\\uXXXX`` JSON escapes, HTML entities) becomes REDACTED as a whole:
      the place cannot be pinned down, so the whole text goes.
    - With ``cut_tails``, a text that ENDS with the first MIN_CUT_TAIL+ characters of a
      secret loses that end too: for texts already cut by someone who did not know the
      secret (backtide re-striking what the proxy sends, docs/21 section 5).
    - Mappings, lists and tuples are walked as in redact(); colliding keys are all kept.

    Run it BEFORE redact() or any cut: a secret split by a cut can no longer be found.
    Raises ValueError for a secret that is not a str or is shorter than MIN_KNOWN_SECRET.
    For many values with the same secrets, build one KnownScrubber and reuse it.
    """
    return KnownScrubber(secrets, cut_tails=cut_tails)(value)


class KnownScrubber:
    """scrub_known() with its secrets prepared once (the pattern is built here)."""

    __slots__ = ("_cut_tails", "_pattern", "_plain")

    def __init__(self, secrets: Iterable[str], *, cut_tails: bool = False) -> None:
        plain: list[str] = []
        for secret in secrets:
            if not isinstance(secret, str) or len(secret) < MIN_KNOWN_SECRET:
                raise ValueError(f"a known secret must be a text of {MIN_KNOWN_SECRET}+ characters")
            plain.append(secret)
        self._plain = tuple(dict.fromkeys(plain))
        self._pattern = _known_pattern(self._plain) if self._plain else None
        self._cut_tails = cut_tails

    def __repr__(self) -> str:
        return f"KnownScrubber({len(self._plain)} secrets)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a KnownScrubber cannot be pickled or copied")

    def __call__(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            result: dict[Any, Any] = {}
            for key, item in value.items():
                new_key = self.text(key) if isinstance(key, str) else key
                result[_unused_key(result, new_key)] = self(item)
            return result
        if isinstance(value, list | tuple):
            return [self(item) for item in value]
        return value

    def text(self, text: str) -> str:
        if self._pattern is None:
            return text
        text = self._pattern.sub(REDACTED, text)
        if any(secret in decoded for decoded in _decodings(text) for secret in self._plain):
            return REDACTED
        if self._cut_tails:
            text = _strike_cut_tail(text, self._plain)
        return text


def _strike_cut_tail(text: str, plain: tuple[str, ...]) -> str:
    longest = 0
    for secret in plain:
        size = _tail_prefix(text, secret)
        longest = max(longest, size)
    if longest:
        return text[: len(text) - longest] + REDACTED
    # The start of a secret may end the text only once decoded (%xx, \\uXXXX, entities):
    # its place in the raw text is unknown, so up to 10 raw characters per character of the
    # secret (the longest HTML entity) are struck from the end. Striking too much is fine.
    # A cut can also split the last escape: it is left out before decoding.
    decodings = _decodings(_PARTIAL_ESCAPE_RE.sub("", text))
    for secret in plain:
        if any(_tail_prefix(decoded, secret) for decoded in decodings):
            return text[: max(0, len(text) - 10 * len(secret))] + REDACTED
    return text


def _tail_prefix(text: str, secret: str) -> int:
    """The length of the longest start of ``secret`` (MIN_CUT_TAIL+) that ends ``text``."""
    for size in range(min(len(secret) - 1, len(text)), MIN_CUT_TAIL - 1, -1):
        if text.endswith(secret[:size]):
            return size
    return 0


def _known_pattern(plain: tuple[str, ...]) -> re.Pattern[str]:
    forms = {
        encoded
        for secret in plain
        for encoded in (
            secret,
            quote(secret, safe=""),
            quote(secret),
            quote_plus(secret, safe=""),
            json.dumps(secret)[1:-1],
        )
    }
    # Longest first, so a secret that contains another is struck whole.
    ordered = sorted(forms, key=len, reverse=True)
    return re.compile("|".join(_PERCENT_RE.sub(_any_case_escape, re.escape(f)) for f in ordered))


def _any_case_escape(match: re.Match[str]) -> str:
    """``%2F`` (already through re.escape) matches ``%2f`` too."""
    high, low = match.group(1), match.group(2)
    return "%" + "".join(f"[{c.upper()}{c.lower()}]" if c.isalpha() else c for c in high + low)


def _decodings(text: str) -> tuple[str, ...]:
    """Ways a server or a program could read ``text`` back."""
    once = unquote(text)
    return (
        once,
        unquote(once),
        unquote_plus(text),
        _JSON_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text).replace("\\/", "/"),
        html.unescape(text),
    )
