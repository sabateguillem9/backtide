import json

import pytest

from backtide.gate.sse import (
    MAX_EVENT_BYTES,
    MAX_TOOL_CALLS,
    LlmSummary,
    SseEvent,
    SseParser,
    UsageStream,
    summarize_json,
)


def sse(*events: tuple[str | None, object], newline: str = "\n") -> bytes:
    """A stream: each event as ``event: <name>`` (when given) and a ``data:`` line."""
    out = []
    for name, data in events:
        text = data if isinstance(data, str) else json.dumps(data)
        lines = ([f"event: {name}"] if name else []) + [f"data: {text}", ""]
        out.append(newline.join(lines) + newline)
    return "".join(out).encode()


ANTHROPIC_EVENTS = [
    (
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": "msg_1",
                "model": "claude-opus-5-5",
                "content": [],
                "usage": {
                    "input_tokens": 12,
                    "output_tokens": 1,
                    "cache_creation_input_tokens": 100,
                    "cache_read_input_tokens": 2000,
                },
            },
        },
    ),
    (
        "content_block_start",
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    ),
    (
        "content_block_delta",
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "SECRET-PROMPT"}},
    ),
    ("ping", {"type": "ping"}),
    (
        "content_block_start",
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "tool_use", "id": "t1", "name": "exéc", "input": {}},
        },
    ),
    (
        "content_block_delta",
        {
            "type": "content_block_delta",
            "delta": {"type": "input_json_delta", "partial_json": '{"cmd": "SECRET-ARG"}'},
        },
    ),  # fmt: skip
    (
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 345},
        },
    ),  # fmt: skip
    ("message_stop", {"type": "message_stop"}),
]
ANTHROPIC_STREAM = sse(*ANTHROPIC_EVENTS)
ANTHROPIC_DETAILS = {
    "model": "claude-opus-5-5",
    "usage": {"input": 12, "output": 345, "cache_read": 2000, "cache_write": 100},
    "stop_reason": "tool_use",
    "tool_calls": ["exéc"],
    "tool_call_count": 1,
    "complete": True,
}


def read(kind: str, chunks: list[bytes]) -> LlmSummary:
    stream = UsageStream(kind)
    for chunk in chunks:
        stream.feed(chunk)
    return stream.finish()


# --- the parser --------------------------------------------------------------------------------


def test_the_parser_reads_events_names_and_multi_line_data() -> None:
    parser = SseParser()
    events = parser.feed(b"event: a\ndata: one\ndata:two\n\n: a comment\ndata: x\n\n")
    assert events == [SseEvent("a", "one\ntwo"), SseEvent("message", "x")]


def test_the_parser_ignores_ids_retries_and_events_without_data() -> None:
    parser = SseParser()
    assert parser.feed(b"id: 1\nretry: 10\n\nevent: only-a-name\n\ndata\n\n") == [
        SseEvent("message", "")
    ]


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_the_parser_accepts_every_line_ending(newline: str) -> None:
    stream = sse(*ANTHROPIC_EVENTS, newline=newline)
    events = SseParser().feed(stream)
    assert [e.event for e in events] == [name for name, _ in ANTHROPIC_EVENTS]


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_chunks_cut_at_any_byte_give_the_same_events(newline: str) -> None:
    stream = sse(*ANTHROPIC_EVENTS, newline=newline)
    whole = SseParser().feed(stream)
    for cut in range(len(stream) + 1):
        parser = SseParser()
        events = parser.feed(stream[:cut]) + parser.feed(stream[cut:]) + parser.finish()
        assert events == whole, cut
    parser = SseParser()
    one_by_one = [e for i in range(len(stream)) for e in parser.feed(stream[i : i + 1])]
    assert one_by_one + parser.finish() == whole


def test_a_bom_at_the_start_is_ignored() -> None:
    assert SseParser().feed(b"\xef\xbb\xbfdata: x\n\n") == [SseEvent("message", "x")]


def test_an_event_without_its_blank_line_is_not_dispatched() -> None:
    parser = SseParser()
    assert parser.feed(b"data: cut") == []
    assert parser.finish() == []
    assert parser.incomplete


def test_invalid_utf8_does_not_break_the_parser() -> None:
    assert SseParser().feed(b"data: \xff\xfe ok\n\n") == [SseEvent("message", "�� ok")]


def test_an_event_over_the_limit_is_dropped_and_counted() -> None:
    parser = SseParser()
    huge = b"data: " + b"x" * (MAX_EVENT_BYTES + 1) + b"\n\n"
    events = parser.feed(huge + b"data: after\n\n")
    assert events == [SseEvent("message", "after")]
    assert parser.dropped == 1


def test_many_data_lines_over_the_limit_are_dropped_too() -> None:
    parser = SseParser(max_event_bytes=100)
    events = parser.feed(b"data: 0123456789\n" * 20 + b"\ndata: ok\n\n")
    assert events == [SseEvent("message", "ok")]
    assert parser.dropped == 1


def test_the_parser_never_holds_more_than_the_limit() -> None:
    parser = SseParser()
    chunk = b"y" * 65536
    for _ in range(80):  # 5 MiB without a single line ending
        assert parser.feed(chunk) == []
        assert parser.buffered <= MAX_EVENT_BYTES
    assert parser.feed(b"\n\ndata: next\n\n") == [SseEvent("message", "next")]
    assert parser.dropped == 1


# --- Anthropic ---------------------------------------------------------------------------------


def test_anthropic_usage_comes_from_message_start_and_the_last_message_delta() -> None:
    summary = read("anthropic", [ANTHROPIC_STREAM])
    assert summary.details() == ANTHROPIC_DETAILS


def test_anthropic_usage_survives_any_cut() -> None:
    for cut in range(0, len(ANTHROPIC_STREAM) + 1, 7):
        summary = read("anthropic", [ANTHROPIC_STREAM[:cut], ANTHROPIC_STREAM[cut:]])
        assert summary.details() == ANTHROPIC_DETAILS, cut


def test_the_summary_never_holds_the_text_of_the_stream() -> None:
    text = json.dumps(read("anthropic", [ANTHROPIC_STREAM]).details())
    assert "SECRET-PROMPT" not in text
    assert "SECRET-ARG" not in text


def test_a_cut_anthropic_stream_is_not_complete_and_keeps_what_it_saw() -> None:
    stream = sse(*ANTHROPIC_EVENTS[:3])
    details = read("anthropic", [stream]).details()
    assert details["complete"] is False
    assert details["usage"] == {"input": 12, "output": 1, "cache_read": 2000, "cache_write": 100}


def test_a_stream_without_usage_says_so() -> None:
    stream = sse(("message_stop", {"type": "message_stop"}))
    details = read("anthropic", [stream]).details()
    assert details["usage_missing"] is True
    assert "usage" not in details


def test_bad_usage_values_are_ignored() -> None:
    stream = sse(
        ("message_start", {"type": "message_start", "message": {"model": 42, "usage": {
            "input_tokens": -1, "output_tokens": True, "cache_read_input_tokens": "9",
            "cache_creation_input_tokens": 10**15}}}),
    )  # fmt: skip
    details = read("anthropic", [stream]).details()
    assert details["usage_missing"] is True
    assert details["model"] is None


def test_tool_calls_are_names_only_and_capped() -> None:
    blocks = [
        ("content_block_start", {"type": "content_block_start", "index": i,
                                 "content_block": {"type": "tool_use", "name": f"tool{i}"}})
        for i in range(MAX_TOOL_CALLS + 5)
    ]  # fmt: skip
    blocks.append(
        ("content_block_start", {"type": "content_block_start",
                                 "content_block": {"type": "tool_use", "name": "n" * 500}})
    )  # fmt: skip
    details = read("anthropic", [sse(*blocks)]).details()
    assert details["tool_calls"] == [f"tool{i}" for i in range(MAX_TOOL_CALLS)]
    assert details["tool_call_count"] == MAX_TOOL_CALLS + 6


def test_unparsable_and_dropped_events_are_counted() -> None:
    stream = b"data: {not json\n\n" + b"data: " + b"x" * (MAX_EVENT_BYTES + 5) + b"\n\n"
    summary = read("anthropic", [stream, ANTHROPIC_STREAM])
    assert summary.dropped == 2
    assert summary.details()["usage"] == ANTHROPIC_DETAILS["usage"]


# --- OpenAI ------------------------------------------------------------------------------------


def chunk(delta: dict[str, object], finish: str | None = None, usage: object = None) -> dict:
    return {
        "id": "c1",
        "object": "chat.completion.chunk",
        "model": "gpt-5.5",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        if delta or finish
        else [],
        "usage": usage,
    }


OPENAI_STREAM = sse(
    (None, chunk({"role": "assistant", "content": "SECRET-PROMPT"})),
    (None, chunk({"tool_calls": [{"index": 0, "id": "x", "function": {"name": "read_file",
                                                                       "arguments": ""}}]})),
    (None, chunk({"tool_calls": [{"index": 0, "function": {"arguments": "SECRET-ARG"}}]})),
    (None, chunk({}, finish="tool_calls")),
    (None, chunk({}, usage={"prompt_tokens": 50, "completion_tokens": 7,
                            "prompt_tokens_details": {"cached_tokens": 30}})),
    (None, "[DONE]"),
)  # fmt: skip


def test_openai_chat_usage_comes_from_the_last_chunk() -> None:
    assert read("openai", [OPENAI_STREAM]).details() == {
        "model": "gpt-5.5",
        "usage": {"input": 50, "output": 7, "cache_read": 30},
        "stop_reason": "tool_calls",
        "tool_calls": ["read_file"],
        "tool_call_count": 1,
        "complete": True,
    }


def test_openai_chat_survives_any_cut() -> None:
    whole = read("openai", [OPENAI_STREAM]).details()
    for cut in range(0, len(OPENAI_STREAM) + 1, 5):
        assert read("openai", [OPENAI_STREAM[:cut], OPENAI_STREAM[cut:]]).details() == whole


def test_openai_without_include_usage_is_usage_missing() -> None:
    stream = sse(
        (None, chunk({"content": "hi"})), (None, chunk({}, finish="stop")), (None, "[DONE]")
    )
    details = read("openai", [stream]).details()
    assert details["usage_missing"] is True
    assert details["stop_reason"] == "stop"
    assert details["complete"] is True


def test_openai_responses_api_stream() -> None:
    stream = sse(
        ("response.created", {"type": "response.created",
                              "response": {"model": "gpt-5.5", "status": "in_progress"}}),
        ("response.output_item.added", {"type": "response.output_item.added",
                                        "item": {"type": "function_call", "name": "web_fetch"}}),
        ("response.output_text.delta", {"type": "response.output_text.delta",
                                        "delta": "SECRET-PROMPT"}),
        ("response.completed", {"type": "response.completed", "response": {
            "model": "gpt-5.5", "status": "completed",
            "usage": {"input_tokens": 80, "output_tokens": 9,
                      "input_tokens_details": {"cached_tokens": 64}}}}),
    )  # fmt: skip
    assert read("openai", [stream]).details() == {
        "model": "gpt-5.5",
        "usage": {"input": 80, "output": 9, "cache_read": 64},
        "stop_reason": "completed",
        "tool_calls": ["web_fetch"],
        "tool_call_count": 1,
        "complete": True,
    }


def test_an_unknown_kind_is_refused() -> None:
    with pytest.raises(ValueError):
        UsageStream("gemini")


# --- whole JSON responses ----------------------------------------------------------------------


def test_anthropic_json_response() -> None:
    body = {
        "model": "claude-opus-5-5",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "SECRET-PROMPT"},
                    {"type": "tool_use", "name": "exec", "input": {"c": "SECRET-ARG"}}],
        "usage": {"input_tokens": 3, "output_tokens": 4, "cache_read_input_tokens": 0},
    }  # fmt: skip
    details = summarize_json("anthropic", json.dumps(body).encode()).details()
    assert details == {
        "model": "claude-opus-5-5",
        "usage": {"input": 3, "output": 4, "cache_read": 0},
        "stop_reason": "end_turn",
        "tool_calls": ["exec"],
        "tool_call_count": 1,
        "complete": True,
    }


def test_openai_json_responses() -> None:
    chat = {
        "model": "gpt-5.5",
        "choices": [{"finish_reason": "stop", "message": {"content": "SECRET-PROMPT",
                     "tool_calls": [{"function": {"name": "grep", "arguments": "SECRET"}}]}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2},
    }  # fmt: skip
    details = summarize_json("openai", json.dumps(chat).encode()).details()
    assert details["usage"] == {"input": 1, "output": 2}
    assert details["tool_calls"] == ["grep"]
    assert details["stop_reason"] == "stop"
    responses = {
        "object": "response",
        "model": "gpt-5.5",
        "status": "completed",
        "output": [{"type": "function_call", "name": "ls"}],
        "usage": {"input_tokens": 5, "output_tokens": 6},
    }
    details = summarize_json("openai", json.dumps(responses).encode()).details()
    assert details["usage"] == {"input": 5, "output": 6}
    assert details["tool_calls"] == ["ls"]


@pytest.mark.parametrize(
    "body", [b"", b"not json", b"[1, 2]", b'{"error": {"type": "x"}}', b"\xff"]
)
def test_a_json_response_without_usage_is_usage_missing(body: bytes) -> None:
    details = summarize_json("anthropic", body).details()
    assert details["usage_missing"] is True
    assert "SECRET" not in json.dumps(details)


def test_deeply_nested_data_is_dropped_not_raised() -> None:
    deep = b"[" * 200_000
    summary = read("anthropic", [b"data: " + deep + b"\n\n", ANTHROPIC_STREAM])
    assert summary.dropped == 1
    assert summary.details()["usage"] == ANTHROPIC_DETAILS["usage"]
    assert summarize_json("openai", deep).details()["usage_missing"] is True
