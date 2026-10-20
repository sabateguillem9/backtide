"""GitHub's GraphQL API (``POST api.github.com/graphql``), which ``gh`` uses to read (docs/32,
decision 6). Pure. Only this path is translated: the rest of ``api.github.com`` is REST and
follows the gate's plain rules (``GET`` passes, writes are held).

The body is ``{"query": <document>, "variables"?, "operationName"?}``. The document is read with
a small lexer of the GraphQL grammar (strings, block strings, comments, commas), and its
top-level definitions are counted:

- READ: every operation is a ``query`` (or the ``{ ... }`` shorthand); fragments are fine.
- DELETE (risk 3): a ``mutation`` whose top-level fields include one named ``delete...``.
- UNKNOWN (held): any other ``mutation``, a ``subscription``, a document with no operation, a
  persisted query, a batch (a JSON list), or anything the lexer does not read strictly.
"""

import re

from backtide.gate.translate.base import (
    WAIT_DEFAULT,
    Context,
    Effect,
    Note,
    Reading,
    RequestView,
    Shape,
    Unreadable,
    account_id,
    credential,
    json_object,
    media_type,
    parse_pairs,
    split_path,
    unknown,
)

NAME = "github_graphql"
HOST = "api.github.com"
MAX_DOCUMENT = 256 * 1024
MAX_TOKENS = 100_000

_BODY_FIELDS = frozenset({"query", "variables", "operationname"})
_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*", re.ASCII)
_NUMBER_RE = re.compile(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", re.ASCII)
_PUNCTUATORS = frozenset("!$&():=@[]{|}")
_IGNORED = frozenset(" \t\n\r,﻿")
_OPEN = {"{": "}", "(": ")", "[": "]"}
_STRING_ESCAPES = frozenset('"\\/bfnrt')


def claims(view: RequestView, context: Context) -> bool:
    del context  # the same for every configuration
    return view.host == HOST and view.path.split("?", 1)[0].lower() == "/graphql"


def read(view: RequestView, context: Context) -> Reading:
    try:
        segments, query = split_path(view.path)
        parse_pairs(query)
        account = account_id(context, NAME, credential(view.headers))
    except Unreadable as error:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note)
    if len(segments) != 1 or view.method != "POST":
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, account=account)
    try:
        if media_type(view.headers) not in (None, "application/json"):
            raise Unreadable
        body = json_object(view.body)
        if not set(body) <= _BODY_FIELDS or not isinstance(body.get("query"), str):
            raise Unreadable(Note.NOT_IN_TABLE)  # a persisted query, or fields we do not know
        operation_name = body.get("operationname")
        if operation_name is not None and not isinstance(operation_name, str):
            raise Unreadable
        kinds, deletes = operations(body["query"])
    except Unreadable as error:
        return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, error.note, account=account)
    if kinds and all(kind == "query" for kind in kinds):
        return Reading(NAME, "query", Effect.READ, Shape.PLAIN, WAIT_DEFAULT, account=account,
                       notes=(Note.GRAPHQL_QUERY,))  # fmt: skip
    if "mutation" in kinds and deletes:
        return Reading(NAME, "mutation", Effect.DELETE, Shape.PLAIN, WAIT_DEFAULT,
                       account=account, notes=(Note.GRAPHQL_MUTATION,))  # fmt: skip
    note = Note.GRAPHQL_MUTATION if "mutation" in kinds else Note.NOT_IN_TABLE
    return unknown(NAME, Shape.PLAIN, WAIT_DEFAULT, note, account=account)


def tokens(document: str) -> list[str]:
    """The lexical tokens of a GraphQL document: names, numbers, punctuators, ``...`` and
    strings (as the single lexeme ``"``). Unreadable for anything the grammar does not have."""
    if len(document) > MAX_DOCUMENT:
        raise Unreadable(Note.TOO_LARGE)
    found: list[str] = []
    index = 0
    size = len(document)
    while index < size:
        char = document[index]
        if char in _IGNORED:
            index += 1
            continue
        if char == "#":
            while index < size and document[index] not in "\r\n":
                index += 1
            continue
        if len(found) >= MAX_TOKENS:
            raise Unreadable(Note.TOO_LARGE)
        if char in _PUNCTUATORS:
            found.append(char)
            index += 1
        elif document.startswith("...", index):
            found.append("...")
            index += 3
        elif document.startswith('"""', index):
            index = _block_string(document, index + 3)
            found.append('"')
        elif char == '"':
            index = _string(document, index + 1)
            found.append('"')
        elif match := _NAME_RE.match(document, index):
            found.append(match.group(0))
            index = match.end()
        elif match := _NUMBER_RE.match(document, index):
            end = match.end()
            if end < size and (document[end] == "." or _NAME_RE.match(document, end)):
                raise Unreadable  # "1.x", "12abc": not a number GraphQL accepts
            found.append("0")
            index = end
        else:
            raise Unreadable
    return found


def _string(document: str, index: int) -> int:
    size = len(document)
    while index < size:
        char = document[index]
        if char == '"':
            return index + 1
        if char in "\r\n":
            raise Unreadable
        if char == "\\":
            following = document[index + 1 : index + 2]
            if following == "u":
                index += 2
                if document[index : index + 1] == "{":
                    end = document.find("}", index, index + 10)
                    if end < 0 or not re.fullmatch(r"[0-9A-Fa-f]{1,8}", document[index + 1 : end]):
                        raise Unreadable
                    index = end + 1
                    continue
                if not re.fullmatch(r"[0-9A-Fa-f]{4}", document[index : index + 4]):
                    raise Unreadable
                index += 4
                continue
            if following not in _STRING_ESCAPES or not following:
                raise Unreadable
            index += 2
            continue
        index += 1
    raise Unreadable  # unterminated


def _block_string(document: str, index: int) -> int:
    size = len(document)
    while index < size:
        if document.startswith('\\"""', index):
            index += 4
            continue
        if document.startswith('"""', index):
            return index + 3
        index += 1
    raise Unreadable  # unterminated


def operations(document: str) -> tuple[list[str], bool]:
    """(the kind of each operation definition, whether a mutation's top-level fields include a
    ``delete...`` one). Fragments are skipped; any other top-level definition is Unreadable."""
    found = tokens(document)
    kinds: list[str] = []
    deletes = False
    index = 0
    while index < len(found):
        lexeme = found[index]
        if lexeme == "{":
            kinds.append("query")
            index = _skip_block(found, index)
            continue
        if lexeme not in ("query", "mutation", "subscription", "fragment"):
            raise Unreadable
        index += 1
        # The header: name, variables, "on Type" and directives, up to the selection set.
        while index < len(found) and found[index] != "{":
            current = found[index]
            if current in ("(", "["):
                index = _skip_block(found, index)
            elif current == "@" or _NAME_RE.fullmatch(current):
                index += 1
            else:
                raise Unreadable
        if index >= len(found):
            raise Unreadable
        if lexeme == "mutation":
            deletes |= any(name.lower().startswith("delete") for name in _top_fields(found, index))
        if lexeme != "fragment":
            kinds.append(lexeme)
        index = _skip_block(found, index)
    return kinds, deletes


def _skip_block(found: list[str], index: int) -> int:
    """The index after the bracket that closes the one at ``index``. Unreadable if unbalanced."""
    stack = [_OPEN[found[index]]]
    index += 1
    while index < len(found):
        lexeme = found[index]
        if lexeme in _OPEN:
            stack.append(_OPEN[lexeme])
        elif lexeme in ("}", ")", "]"):
            if stack.pop() != lexeme:
                raise Unreadable
            if not stack:
                return index + 1
        index += 1
    raise Unreadable


def _top_fields(found: list[str], index: int) -> list[str]:
    """The field names directly inside the selection set that opens at ``index`` (after an
    alias, if any). A fragment spread there is Unreadable: its fields are elsewhere."""
    names: list[str] = []
    end = _skip_block(found, index) - 1
    index += 1
    while index < end:
        lexeme = found[index]
        if lexeme in _OPEN:
            index = _skip_block(found, index)
            continue
        if lexeme == "...":
            raise Unreadable
        if lexeme == "@":
            index += 2
            continue
        if _NAME_RE.fullmatch(lexeme):
            if index + 2 < end and found[index + 1] == ":":
                names.append(found[index + 2])
                index += 3
            else:
                names.append(lexeme)
                index += 1
            continue
        index += 1
    return names
