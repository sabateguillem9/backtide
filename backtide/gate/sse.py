"""A bounded Server-Sent Events parser, and what is kept of a model's answer: the model,
the token usage, the stop reason and the tool names. Never the text. Pure: no I/O.

The proxy lets every chunk through to the agent at once and feeds a copy here. An event over
MAX_EVENT_BYTES is dropped and counted, so a stream never makes the proxy hold more than
that. Design and rationale: docs/21-diseno-t06-proxy.md, section 8.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

MAX_EVENT_BYTES = 1 << 20  # 1 MiB
MAX_TOOL_CALLS = 20
_MAX_NAME = 64
_MAX_MODEL = 128
_MAX_TOKENS = 10**12
_LINE_END = re.compile(rb"[\r\n]")
_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True)
class SseEvent:
    event: str  # "message" when the stream gives no name
    data: str


class SseParser:
    """Turns chunks, cut at any byte, into events (the WHATWG event-stream format).

    ``buffered`` (the bytes held for the current event) never passes ``max_event_bytes``:
    past it, the event is dropped up to its blank line and ``dropped`` grows by one."""

    def __init__(self, max_event_bytes: int = MAX_EVENT_BYTES) -> None:
        self._max = max_event_bytes
        self._line = bytearray()
        self._data: list[bytes] = []
        self._name = b""
        self._size = 0  # bytes of the current event already kept (data lines and name)
        self._skipping_line = False  # dropping the rest of a line over the limit
        self._discard = False  # the current event went over the limit
        self._pending_cr = False  # the last chunk ended with "\r": a "\n" may follow
        self._first_line = True
        self.dropped = 0
        self.incomplete = False  # finish() found an event without its blank line

    @property
    def buffered(self) -> int:
        return self._size + len(self._line)

    def feed(self, chunk: bytes) -> list[SseEvent]:
        out: list[SseEvent] = []
        start = 0
        if self._pending_cr:
            self._pending_cr = False
            if chunk[:1] == b"\n":
                start = 1
        while start < len(chunk):
            match = _LINE_END.search(chunk, start)
            if match is None:
                self._append(chunk[start:])
                break
            end = match.start()
            self._append(chunk[start:end])
            self._end_line(out)
            if chunk[end : end + 1] == b"\r":
                if end + 1 == len(chunk):
                    self._pending_cr = True
                elif chunk[end + 1 : end + 2] == b"\n":
                    end += 1
            start = end + 1
        return out

    def finish(self) -> list[SseEvent]:
        """The end of the stream. An event without its blank line is not dispatched."""
        self.incomplete = bool(self._line or self._data or self._discard or self._skipping_line)
        self._reset_event()
        self._line.clear()
        self._skipping_line = False
        return []

    def _append(self, part: bytes) -> None:
        if self._skipping_line or not part:
            return
        if self.buffered + len(part) > self._max:
            self._skipping_line = True
            self._discard = True
            self._line.clear()
            self._data.clear()
            self._size = 0
            return
        self._line += part

    def _end_line(self, out: list[SseEvent]) -> None:
        if self._skipping_line:
            self._skipping_line = False
            return
        line = bytes(self._line)
        self._line.clear()
        if self._first_line:
            self._first_line = False
            line = line.removeprefix(_BOM)
        if not line:
            self._dispatch(out)
            return
        if self._discard or line.startswith(b":"):
            return
        name, colon, value = line.partition(b":")
        if colon and value.startswith(b" "):
            value = value[1:]
        if name == b"data":
            self._data.append(value)
            self._size += len(value) + 1
        elif name == b"event":
            self._size += len(value) - len(self._name)
            self._name = value

    def _dispatch(self, out: list[SseEvent]) -> None:
        if self._discard:
            self.dropped += 1
        elif self._data:
            name = self._name.decode("utf-8", "replace") or "message"
            data = b"\n".join(self._data).decode("utf-8", "replace")
            out.append(SseEvent(name, data))
        self._reset_event()

    def _reset_event(self) -> None:
        self._data = []
        self._name = b""
        self._size = 0
        self._discard = False


@dataclass
class LlmSummary:
    """What is kept of one answer. ``usage`` has the keys ``input``, ``output``,
    ``cache_read`` and ``cache_write`` (and Anthropic's ``cache_write_5m`` / ``cache_write_1h``
    split) that were seen, as the provider counts them:
    Anthropic's ``input`` leaves the cache out, OpenAI's includes it (docs/24)."""

    model: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    stop_reason: str | None = None
    tool_calls: list[str] = field(default_factory=list)
    tool_call_count: int = 0
    complete: bool = False
    dropped: int = 0  # events over the limit or whose data is not JSON

    def details(self) -> dict[str, Any]:
        """The fields of an ``llm/response`` event that come from the answer."""
        result: dict[str, Any] = {"model": self.model}
        if self.usage:
            result["usage"] = dict(self.usage)
        else:
            result["usage_missing"] = True
        result["stop_reason"] = self.stop_reason
        result["tool_calls"] = list(self.tool_calls)
        result["tool_call_count"] = self.tool_call_count
        result["complete"] = self.complete
        return result

    def _tool(self, name: object) -> None:
        self.tool_call_count += 1
        if isinstance(name, str) and len(self.tool_calls) < MAX_TOOL_CALLS:
            self.tool_calls.append(name[:_MAX_NAME])

    def _model(self, value: object) -> None:
        if isinstance(value, str) and value:
            self.model = value[:_MAX_MODEL]

    def _stop(self, value: object) -> None:
        if isinstance(value, str) and value:
            self.stop_reason = value[:_MAX_NAME]

    def _usage(self, usage: object, names: dict[str, tuple[str, ...]]) -> None:
        if not isinstance(usage, dict):
            return
        for key, path in names.items():
            value = _dig(usage, path)
            if type(value) is int and 0 <= value <= _MAX_TOKENS:
                self.usage[key] = value


_ANTHROPIC_USAGE = {
    "input": ("input_tokens",),
    "output": ("output_tokens",),
    "cache_read": ("cache_read_input_tokens",),
    "cache_write": ("cache_creation_input_tokens",),
    # The split of the cache writes by how long they live (T11: 1.25x or 2x of the input).
    "cache_write_5m": ("cache_creation", "ephemeral_5m_input_tokens"),
    "cache_write_1h": ("cache_creation", "ephemeral_1h_input_tokens"),
}
_OPENAI_CHAT_USAGE = {
    "input": ("prompt_tokens",),
    "output": ("completion_tokens",),
    "cache_read": ("prompt_tokens_details", "cached_tokens"),
}
_OPENAI_RESPONSES_USAGE = {
    "input": ("input_tokens",),
    "output": ("output_tokens",),
    "cache_read": ("input_tokens_details", "cached_tokens"),
}
_ANTHROPIC_TOOL_BLOCKS = frozenset({"tool_use", "server_tool_use", "mcp_tool_use"})
_KINDS = frozenset({"anthropic", "openai"})


def _dig(value: object, path: tuple[str, ...]) -> object:
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _check_kind(kind: str) -> str:
    kind = str(kind)
    if kind not in _KINDS:
        raise ValueError("unknown provider kind")
    return kind


class UsageStream:
    """Feeds a streamed answer (SSE chunks) and keeps its summary."""

    def __init__(self, kind: str) -> None:
        self._kind = _check_kind(kind)
        self._parser = SseParser()
        self._summary = LlmSummary()

    def feed(self, chunk: bytes) -> None:
        for event in self._parser.feed(chunk):
            self._event(event)

    def finish(self) -> LlmSummary:
        self._parser.finish()
        self._summary.dropped += self._parser.dropped
        return self._summary

    def _event(self, event: SseEvent) -> None:
        if self._kind == "openai" and event.data.strip() == "[DONE]":
            self._summary.complete = True
            return
        try:
            data = json.loads(event.data)
        except (ValueError, RecursionError):  # RecursionError: nested too deep
            self._summary.dropped += 1
            return
        if not isinstance(data, dict):
            self._summary.dropped += 1
        elif self._kind == "anthropic":
            _anthropic_event(self._summary, data)
        else:
            _openai_event(self._summary, data)


def _anthropic_event(summary: LlmSummary, data: dict[str, Any]) -> None:
    kind = data.get("type")
    if kind == "message_start":
        message = data.get("message")
        if isinstance(message, dict):
            summary._model(message.get("model"))
            summary._usage(message.get("usage"), _ANTHROPIC_USAGE)
    elif kind == "content_block_start":
        block = data.get("content_block")
        if isinstance(block, dict) and block.get("type") in _ANTHROPIC_TOOL_BLOCKS:
            summary._tool(block.get("name"))
    elif kind == "message_delta":
        summary._stop(_dig(data, ("delta", "stop_reason")))
        summary._usage(data.get("usage"), _ANTHROPIC_USAGE)  # cumulative: the last one wins
    elif kind == "message_stop":
        summary.complete = True


def _openai_event(summary: LlmSummary, data: dict[str, Any]) -> None:
    kind = data.get("type")
    if isinstance(kind, str) and kind.startswith("response."):
        _openai_responses_event(summary, kind, data)
        return
    summary._model(data.get("model"))
    choices = data.get("choices")
    for choice in choices if isinstance(choices, list) else []:
        if not isinstance(choice, dict):
            continue
        summary._stop(choice.get("finish_reason"))
        calls = _dig(choice, ("delta", "tool_calls"))
        for call in calls if isinstance(calls, list) else []:
            name = _dig(call, ("function", "name"))
            if isinstance(name, str):  # only the first chunk of each call has the name
                summary._tool(name)
    summary._usage(data.get("usage"), _OPENAI_CHAT_USAGE)


def _openai_responses_event(summary: LlmSummary, kind: str, data: dict[str, Any]) -> None:
    response = data.get("response")
    if isinstance(response, dict):
        summary._model(response.get("model"))
    if kind == "response.output_item.added":
        item = data.get("item")
        if isinstance(item, dict) and item.get("type") == "function_call":
            summary._tool(item.get("name"))
    elif kind in {"response.completed", "response.incomplete", "response.failed"}:
        if isinstance(response, dict):
            summary._stop(response.get("status"))
            summary._usage(response.get("usage"), _OPENAI_RESPONSES_USAGE)
        summary.complete = True


def summarize_json(kind: str, body: bytes) -> LlmSummary:
    """The summary of an answer that came whole, as JSON (no streaming)."""
    kind = _check_kind(kind)
    summary = LlmSummary()
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):  # RecursionError: nested too deep
        return summary
    if not isinstance(data, dict):
        return summary
    summary.complete = True
    summary._model(data.get("model"))
    if kind == "anthropic":
        summary._stop(data.get("stop_reason"))
        summary._usage(data.get("usage"), _ANTHROPIC_USAGE)
        blocks = data.get("content")
        for block in blocks if isinstance(blocks, list) else []:
            if isinstance(block, dict) and block.get("type") in _ANTHROPIC_TOOL_BLOCKS:
                summary._tool(block.get("name"))
    elif data.get("object") == "response":
        summary._stop(data.get("status"))
        summary._usage(data.get("usage"), _OPENAI_RESPONSES_USAGE)
        items = data.get("output")
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and item.get("type") == "function_call":
                summary._tool(item.get("name"))
    else:
        summary._usage(data.get("usage"), _OPENAI_CHAT_USAGE)
        choices = data.get("choices")
        for choice in choices if isinstance(choices, list) else []:
            if not isinstance(choice, dict):
                continue
            summary._stop(choice.get("finish_reason"))
            calls = _dig(choice, ("message", "tool_calls"))
            for call in calls if isinstance(calls, list) else []:
                summary._tool(_dig(call, ("function", "name")))
    return summary
