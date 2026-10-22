"""OpenAI's streamed usage, asked for by the proxy (T11, docs/33 "include_usage"). Pure: no I/O.

A streamed Chat Completions answer carries no token usage unless the request asks for it with
``stream_options: {"include_usage": true}``; then the provider sends one more chunk before
``[DONE]``, with an empty ``choices`` and the usage of the whole call (and ``"usage": null`` in
every other chunk). Without it the spending cap can only estimate the call, by excess.

So, toward a public ``openai`` provider (never a local one: it costs nothing), the proxy adds
exactly that field to a streamed ``chat`` call whose body has no ``stream_options`` at all
(``usage_insert_at``). The agent's own choice always wins: ``include_usage: false``, ``{}`` or any
other value of its own is left alone (and the call is still estimated). The rewrite is a byte
insertion right after the body's opening ``{`` (``with_include_usage``): nothing the agent wrote
is parsed and written again, so no number, escape or key order changes. It is planned only on a
body the gate read strictly (provider_tools: UTF-8, one object, no duplicate keys even
case-folded, no NaN), uncompressed, that stays within the body limit; the gate then checks the
rewritten body with the same rule before backtide records it.

The extra chunk is read by the tap like any other (sse.UsageStream) and then, since the agent did
not ask for it, dropped before it reaches the agent (``drop_usage_events``): only a whole SSE
event, already checked for the real key, whose data is a JSON object with ``"choices": []`` and
a ``usage`` object. The ``"usage": null`` of the other chunks is left as it came.
"""

import json
import re
from collections.abc import Sequence

INSERTED = b'"stream_options":{"include_usage":true},'
_JSON_SPACE = b" \t\r\n"
_LINE = re.compile(rb"([^\r\n]*)(\r\n|\r|\n)")


def usage_insert_at(
    kind: str,
    endpoint: str | None,
    headers: Sequence[tuple[str, str]],
    body: bytes | None,
    *,
    limit: int,
) -> int | None:
    """Where to insert INSERTED in ``body`` (right after its opening ``{``), or None when the
    proxy must leave the request alone: not ``openai``, not ``chat``, compressed, not a streamed
    call (``"stream": true``, exactly so), a ``stream_options`` of the agent's (any spelling that
    folds to it), or over ``limit`` once rewritten. The caller decides on local providers and
    re-checks the rewritten body; the body is expected to have passed the strict read already."""
    if kind != "openai" or endpoint != "chat" or not body:
        return None
    for name, value in headers:
        if name.lower() == "content-encoding" and value.strip().lower() not in ("", "identity"):
            return None
    if len(body) + len(INSERTED) > limit:
        return None
    try:
        data = json.loads(body.decode("utf-8"))  # strict: UTF-8 only, and a BOM is refused
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or data.get("stream") is not True:
        return None
    if any(key.casefold() == "stream_options" for key in data):
        return None
    at = len(body) - len(body.lstrip(_JSON_SPACE))
    if body[at : at + 1] != b"{":
        return None
    rewritten = with_include_usage(body, at)
    try:
        again = json.loads(rewritten.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if (
        not isinstance(again, dict)
        or again.get("stream_options") != {"include_usage": True}
        or set(again) != set(data) | {"stream_options"}
    ):
        return None
    return at


def with_include_usage(body: bytes, at: int) -> bytes:
    """``body`` with INSERTED right after its opening ``{`` at ``at``. ValueError if ``at`` is not
    that brace (the body changed since it was planned): the request must not go out then."""
    if body[at : at + 1] != b"{" or body[:at].strip(_JSON_SPACE):
        raise ValueError("the body is not the one the include_usage rewrite was planned on")
    return body[: at + 1] + INSERTED + body[at + 1 :]


def drop_usage_events(data: bytes) -> bytes:
    """``data`` (whole SSE events, as the key guard lets them go) without the events that are only
    OpenAI's usage chunk: unnamed (or ``message``) events whose data is a JSON object with
    ``"choices": []`` and a ``usage`` object. Everything else is kept byte for byte."""
    out = bytearray()
    event = bytearray()
    lines: list[bytes] = []
    end = 0
    for match in _LINE.finditer(data):
        if match.start() != end:
            break  # cannot be (the pattern matches every line); kept as it came below
        end = match.end()
        event += match.group(0)
        line = match.group(1)
        if line:
            lines.append(line)
            continue
        if not _usage_only(lines):
            out += event
        event.clear()
        lines.clear()
    out += event  # an event without its blank line (never from the guard): kept
    out += data[end:]
    return bytes(out)


def _usage_only(lines: list[bytes]) -> bool:
    parts: list[bytes] = []
    for line in lines:
        if line.startswith(b":"):
            continue  # a comment
        name, colon, value = line.partition(b":")
        if colon and value.startswith(b" "):
            value = value[1:]
        if name == b"data":
            parts.append(value)
        elif name == b"event" and value not in (b"", b"message"):
            return False
    if not parts:
        return False
    try:
        chunk = json.loads(b"\n".join(parts))
    except (ValueError, RecursionError):
        return False
    return (
        isinstance(chunk, dict)
        and chunk.get("choices") == []
        and isinstance(chunk.get("usage"), dict)
    )
