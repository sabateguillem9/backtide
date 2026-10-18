"""The provider's answer, checked for the real key before it reaches the agent
(backtide/gate/echo.py, T06-6).

A provider that echoed the real key (in an error, in the model's text, encoded) would hand it to
the agent. A whole answer is checked before any byte of it goes on; a streamed one (SSE) is held
back event by event, checked, and cut at once when the key shows, even split over several deltas.
Made-up keys only.
"""

import base64
import json
from urllib.parse import quote

import pytest

from backtide.gate import echo
from backtide.gate.echo import EventTooLarge, KeyEcho, KeyScanner, SseGuard, key_forms

REAL = "sk-ant-api03-TEST" + "4dd0nR3alK3y" * 5
OTHER = "sk-proj-TEST" + "0p3nAiR3al" * 5


def scanner() -> KeyScanner:
    return KeyScanner([REAL, OTHER])


def sse(*events: tuple[str | None, object]) -> bytes:
    out = b""
    for name, data in events:
        text = data if isinstance(data, str) else json.dumps(data)
        out += (b"" if name is None else f"event: {name}\n".encode()) + f"data: {text}\n\n".encode()
    return out


def text_delta(text: str, index: int = 0) -> tuple[str, object]:
    return (
        "content_block_delta",
        {"type": "content_block_delta", "index": index,
         "delta": {"type": "text_delta", "text": text}},
    )  # fmt: skip


START = ("message_start", {"type": "message_start", "message": {"model": "claude-x"}})
STOP = ("message_stop", {"type": "message_stop"})


def run(guard: SseGuard, body: bytes, size: int = 7) -> bytes:
    out = b"".join(guard.feed(body[i : i + size]) for i in range(0, len(body), size))
    return out + guard.finish()


# --- the key's forms -----------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["", "a", "ab", "abc", "abcd", "key: "])
def test_the_key_is_found_in_base64_at_any_alignment(prefix: str) -> None:
    data = f"{prefix}{REAL} and more".encode()
    assert scanner().found(base64.b64encode(data).decode())
    assert scanner().found(base64.urlsafe_b64encode(data).decode())


@pytest.mark.parametrize(
    "form",
    [
        REAL,
        REAL.lower(),
        REAL.upper(),
        quote(REAL, safe=""),
        "".join(f"%{b:02x}" for b in REAL.encode()),
        "".join(f"\\u{ord(c):04x}" for c in REAL),
        "".join(f"&#{ord(c)};" for c in REAL),
        REAL.encode().hex(),
        REAL.encode().hex().upper(),
        OTHER,
    ],
)
def test_the_key_is_found_in_each_of_its_forms(form: str) -> None:
    assert scanner().found(f"before {form} after")


def test_text_without_the_key_is_clean() -> None:
    assert not scanner().found("sk-ant-api03-TEST and a lot of ordinary text " * 50)


def test_the_forms_are_long_enough_to_search_for() -> None:
    assert all(len(form) >= 8 for form in key_forms([REAL]))


def test_a_whole_answer_is_checked_in_each_part() -> None:
    assert scanner().found_in(b"clean", json.dumps({"error": f"bad key {REAL}"}).encode())
    assert not scanner().found_in(b"clean", None, "also clean")


# --- a streamed answer ---------------------------------------------------------------------------


def test_a_clean_stream_passes_untouched() -> None:
    body = sse(START, text_delta("Hello "), text_delta("world"), STOP)
    for size in (1, 7, 64, len(body)):
        assert run(SseGuard(scanner()), body, size) == body


def test_an_event_is_only_let_through_once_it_is_whole() -> None:
    guard = SseGuard(scanner())
    first = sse(text_delta("Hello"))
    assert guard.feed(first[:-3]) == b""
    assert guard.feed(first[-3:]) == first


@pytest.mark.parametrize("ending", [b"\r\n", b"\r", b"\n"])
def test_every_line_ending_is_understood(ending: bytes) -> None:
    body = sse(START, text_delta("hi"), STOP).replace(b"\n", ending)
    assert run(SseGuard(scanner()), body, 1) == body


def test_a_cr_at_the_end_of_a_chunk_waits_for_what_follows() -> None:
    guard = SseGuard(scanner())
    assert guard.feed(b"data: {}\r\n\r") == b""
    assert guard.feed(b"\n") == b"data: {}\r\n\r\n"


def test_an_event_with_the_key_is_never_let_through() -> None:
    guard = SseGuard(scanner())
    out = guard.feed(sse(START))
    with pytest.raises(KeyEcho):
        guard.feed(sse(text_delta(f"your key is {REAL}")))
    assert REAL[:8] not in out.decode()


@pytest.mark.parametrize(
    "pieces",
    [
        [REAL[:20], REAL[20:]],
        [REAL[:5], REAL[5:9], REAL[9:60], REAL[60:]],
        [c for c in REAL],
    ],
)
def test_a_key_split_over_deltas_cuts_the_stream_when_it_is_whole(pieces: list[str]) -> None:
    guard = SseGuard(scanner())
    out = guard.feed(sse(START))
    with pytest.raises(KeyEcho):
        for piece in pieces:
            out += guard.feed(sse(text_delta(piece)))
    assert REAL not in out.decode()


def test_deltas_of_other_blocks_in_between_do_not_hide_a_split_key() -> None:
    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(sse(text_delta(REAL[:30], index=0)))
        guard.feed(sse(text_delta("noise", index=1)))
        guard.feed(sse(text_delta(REAL[30:], index=0)))


def test_a_key_split_over_openai_chat_deltas_is_found() -> None:
    def chunk(text: str) -> tuple[None, object]:
        return None, {"object": "chat.completion.chunk",
                      "choices": [{"index": 0, "delta": {"content": text}}]}  # fmt: skip

    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(sse(chunk(OTHER[:10])) + sse(chunk(OTHER[10:])))


def test_a_key_split_over_openai_tool_call_arguments_is_found() -> None:
    def chunk(text: str) -> tuple[None, object]:
        call = {"index": 1, "function": {"arguments": text}}
        return None, {"choices": [{"index": 0, "delta": {"tool_calls": [call]}}]}

    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(sse(chunk(OTHER[:10])))
        guard.feed(sse(chunk(OTHER[10:])))


def test_a_key_split_over_responses_deltas_is_found() -> None:
    def delta(text: str) -> tuple[str, object]:
        return "response.output_text.delta", {
            "type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0,
            "content_index": 0, "sequence_number": len(text), "delta": text,
        }  # fmt: skip

    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(sse(delta(OTHER[:31])))
        guard.feed(sse(delta(OTHER[31:])))


def test_a_key_in_base64_split_over_deltas_is_found() -> None:
    encoded = base64.b64encode(REAL.encode()).decode()
    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        for i in range(0, len(encoded), 9):
            guard.feed(sse(text_delta(encoded[i : i + 9])))


def test_a_key_in_raw_json_escapes_is_found() -> None:
    escaped = "".join(f"\\u{ord(c):04x}" for c in REAL)
    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(f'data: {{"type": "x", "text": "{escaped}"}}\n\n'.encode())


def test_a_key_in_data_that_is_not_json_is_found() -> None:
    guard = SseGuard(scanner())
    with pytest.raises(KeyEcho):
        guard.feed(f"data: {REAL}\n\n".encode())


def test_an_unfinished_event_is_never_let_through() -> None:
    """mitmproxy marks the end with an empty chunk, but an empty chunk may also come in the
    middle (an empty HTTP/2 DATA frame): either way only whole events go on, and the rest
    waits. An event without its blank line at the very end is dropped, as SSE clients do."""
    guard = SseGuard(scanner())
    assert guard.feed(f"data: {REAL[:20]}".encode()) == b""
    assert guard.finish() == b""
    with pytest.raises(KeyEcho):
        guard.feed(f"{REAL[20:]}\n\n".encode())


def test_a_final_cr_ends_the_last_event_at_the_end() -> None:
    guard = SseGuard(scanner())
    assert guard.feed(b"data: {}\r\r") == b""
    assert guard.finish() == b"data: {}\r\r"


def test_an_event_over_the_limit_stops_the_stream() -> None:
    guard = SseGuard(scanner(), max_event=1000)
    with pytest.raises(EventTooLarge):
        guard.feed(b"data: " + b"x" * 2000)


def test_many_blocks_keep_a_bounded_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(echo, "MAX_CHANNELS", 8)
    guard = SseGuard(scanner())
    for index in range(100):
        guard.feed(sse(text_delta("x" * 2000, index=index)))
    assert guard.channels <= 8
    assert guard.held <= guard.window * 8


def test_deep_or_wide_events_are_walked_within_a_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(echo, "MAX_DEPTH", 4)
    guard = SseGuard(scanner())
    deep = "[" * 500 + "1" + "]" * 500
    wide = json.dumps({"x": list(range(100_000))})
    assert guard.feed(f"data: {deep}\n\n".encode()) != b""
    assert guard.feed(f"data: {wide}\n\n".encode()) != b""
    assert guard.channels <= echo.MAX_CHANNELS


def test_long_field_names_and_places_are_kept_short() -> None:
    guard = SseGuard(scanner())
    event = {"item_id": "i" * 100_000, "y" * 100_000: "text"}
    guard.feed(f"data: {json.dumps(event)}\n\n".encode())
    assert guard.key_bytes <= 4 * echo.MAX_PATH_PART * (echo.MAX_DEPTH + 8)
