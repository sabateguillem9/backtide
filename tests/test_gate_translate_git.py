"""The git translator (backtide/gate/translate/git.py, T17b-1): git's smart HTTP on GitHub.

Reads pass (the discovery, ``git-upload-pack``, the probe before a large push); a push is held
saying which repository and which refs it creates, updates or deletes, with risk 3 when it
deletes one; and whatever cannot be read strictly is held as unknown, never let through.

The bodies in ``tests/fixtures/git/`` are what git 2.54 really sent to a local fake server
(127.0.0.1, never GitHub): a push that creates ``main`` in an empty repository, one that
updates ``main``, deletes ``old`` and creates ``feature/x``, the deletion of a tag, a forced
push, a push with ``-o ci.skip``, and a clone and a fetch (protocol v2 and v0). Every token is
fake.
"""

import base64
import gzip
import time
from dataclasses import replace
from pathlib import Path

import pytest

from backtide.blackbox.redact import KnownScrubber
from backtide.gate import protocol
from backtide.gate.fingerprint import fingerprint
from backtide.gate.phrase import action, describe, note_texts
from backtide.gate.translate import Context, Effect, RequestView, has_translator, translate
from backtide.gate.translate.base import MAX_BODY, TARGET_CHARS, Note, Shape
from backtide.gate.translate.git import (
    MAX_COMMANDS,
    escape_ref,
    parse_push,
    pkt_line,
    short_ref,
)
from backtide.notify.hold_notice import batch_label, batch_question, batches_text
from backtide.service.holds import BatchKind, BatchRefused, BatchRule, HoldBook, reading_scope
from tests.gate_translate_kit import CTX, KEY, read, request, scrubbed

FIXTURES = Path(__file__).parent / "fixtures" / "git"
HOST = "github.com"
REPO = "/octo/demo.git"
TOKEN = "x-access-token:fake-github-token-for-tests"  # noqa: S105 (a fake one)
AUTH = ("authorization", "Basic " + base64.b64encode(TOKEN.encode()).decode())
OTHER_AUTH = ("authorization", "Basic " + base64.b64encode(b"x-access-token:other").decode())
RECEIVE_TYPE = ("content-type", "application/x-git-receive-pack-request")
UPLOAD_TYPE = ("content-type", "application/x-git-upload-pack-request")
ZERO = "0" * 40
A, B = "236ba31c653774ce8397075c08372276771ea1dd", "ffdcfec9451f88095fc2a495007810a1133d7f31"
CAPS = b" report-status-v2 side-band-64k quiet object-format=sha1 agent=git/2.54.0-Darwin"
PACK = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x02" * 20  # an empty pack (fake checksum)


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def pkt(data: bytes) -> bytes:
    return f"{len(data) + 4:04x}".encode() + data


def commands(*lines: str, caps: bytes = CAPS, pack: bytes | None = PACK) -> bytes:
    """A push body as git sends it: the commands (capabilities after the first), a flush and
    the pack (none when ``pack`` is None)."""
    packets = [pkt(lines[0].encode() + b"\0" + caps)] + [pkt(line.encode()) for line in lines[1:]]
    return b"".join(packets) + b"0000" + (pack or b"")


def push(
    body: bytes,
    *,
    path: str = f"{REPO}/git-receive-pack",
    headers: tuple[tuple[str, str], ...] = (AUTH, RECEIVE_TYPE),
    host: str = HOST,
    **kwargs: object,
) -> RequestView:
    return request("POST", host, path, body=body, headers=headers, **kwargs)  # type: ignore[arg-type]


def fetch(body: bytes, *, path: str = f"{REPO}/git-upload-pack") -> RequestView:
    return request("POST", HOST, path, body=body, headers=(AUTH, UPLOAD_TYPE))


def held(view: RequestView, context: Context = CTX, seconds: float = 3.0) -> object:
    start = time.monotonic()
    reading = translate(view, context)
    elapsed = time.monotonic() - start
    assert reading is not None and reading.translator == "git"
    assert reading.effect is Effect.UNKNOWN, reading
    assert reading.risk >= 2 and reading.recipients == ()
    assert reading.canonical is None  # never a fingerprint that a yes could be reused on
    assert elapsed < seconds, f"took {elapsed:.2f} s"
    return reading


# --- what git really sends ----------------------------------------------------------------------


def test_a_push_to_an_empty_repository_creates_main() -> None:
    reading = read(push(fixture("push-create.bin")))
    assert reading.effect is Effect.CHANGE and reading.risk == 2
    assert reading.operation == "receive-pack" and reading.shape is Shape.PLAIN
    assert reading.recipients == ("refs/heads/main",)
    assert reading.target == "github.com/octo/demo: crea main"
    assert reading.wait_s == 90 and reading.account is not None
    assert not reading.secret_seen and reading.notes == ()


def test_a_push_that_deletes_a_branch_is_risk_3_and_says_what_it_does_to_each_ref() -> None:
    reading = read(push(fixture("push-mixed.bin")))
    assert reading.effect is Effect.DELETE and reading.risk == 3
    assert reading.recipients == ("refs/heads/main", "refs/heads/old", "refs/heads/feature/x")
    assert reading.target == "github.com/octo/demo: actualiza main; crea feature/x; borra old"


def test_deleting_a_tag_is_risk_3() -> None:
    reading = read(push(fixture("push-delete-tag.bin")))
    assert reading.effect is Effect.DELETE and reading.risk == 3
    assert reading.recipients == ("refs/tags/v1",)
    assert reading.target == "github.com/octo/demo: borra etiqueta v1"


def test_a_forced_push_reads_like_any_update_and_the_notice_says_it_cannot_tell() -> None:
    """``git push --force`` sends the same command as a fast-forward: whether the old id is an
    ancestor of the new one is only in the server's history. backtide does not guess."""
    forced = read(push(fixture("push-force.bin")))
    assert forced.effect is Effect.CHANGE and forced.risk == 2
    assert forced.target == "github.com/octo/demo: actualiza main"
    summary = forced.summary()
    assert "push forzado" in "; ".join(note_texts(summary))
    assert "puede saber si es un push forzado" in describe(summary)


def test_push_options_are_held_as_unknown() -> None:
    """The server may act on them (GitLab opens merge requests with ``-o``)."""
    reading = held(push(fixture("push-options.bin")))
    assert Note.NOT_IN_TABLE in reading.notes  # type: ignore[attr-defined]
    assert reading.target == "github.com/octo/demo"  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", ["fetch-v2-ls-refs.bin", "fetch-v2-fetch.bin", "fetch-v0.bin"])
def test_clone_and_fetch_pass(name: str) -> None:
    reading = read(fetch(fixture(name)))
    assert reading.effect is Effect.READ and reading.risk == 0
    assert reading.operation == "upload-pack"


def test_the_probe_before_a_large_push_passes() -> None:
    """Over ``http.postBuffer`` git first POSTs a lone flush-pkt (git 2.54 did here, with
    ``-c http.postBuffer=4096``): an empty command list, which the server does nothing with."""
    reading = read(push(b"0000"))
    assert reading.effect is Effect.READ and reading.operation == "receive-pack.probe"
    # ...and the chunked push that follows is read as decoded, like any other.
    big = commands(f"{ZERO} {B} refs/heads/big", pack=PACK + b"\x00" * 60_000)
    assert read(push(big)).effect is Effect.CHANGE


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"{REPO}/info/refs?service=git-upload-pack"),
        ("GET", f"{REPO}/info/refs?service=git-receive-pack"),
        ("HEAD", f"{REPO}/info/refs?service=git-upload-pack"),
        ("GET", f"{REPO}/info/refs"),  # the dumb protocol's discovery
        ("GET", "/octo/demo/info/refs?service=git-upload-pack"),  # without .git
    ],
)
def test_the_discovery_passes(method: str, path: str) -> None:
    reading = read(request(method, HOST, path, headers=(AUTH,)))
    assert reading.effect is Effect.READ and reading.operation == "info-refs"


# --- what is claimed, and what is left to the plain rules ---------------------------------------


@pytest.mark.parametrize(
    ("host", "path"),
    [
        (HOST, "/octo/demo"),
        (HOST, "/octo/demo/blob/main/info/refs"),
        (HOST, "/octo/demo/raw/main/git-receive-pack"),
        (HOST, "/login/oauth/access_token"),
        (HOST, "/octo/demo.git/info/lfs/objects/batch"),
        (HOST, "/octo/demo.git/git-receive-pack/x"),
        (HOST, "/octo/demo.git/GIT-RECEIVE-PACK"),
        ("api.github.com", "/octo/demo.git/git-receive-pack"),
        ("gitlab.com", "/octo/demo.git/git-receive-pack"),
        ("github.com.evil.example", "/octo/demo.git/git-receive-pack"),
    ],
)
def test_other_paths_and_hosts_are_left_to_the_plain_rules(host: str, path: str) -> None:
    view = push(commands(f"{ZERO} {B} refs/heads/main"), host=host, path=path)
    assert not has_translator(view, CTX)
    assert translate(view, CTX) is None


def test_the_host_header_never_picks_it() -> None:
    view = push(
        commands(f"{ZERO} {B} refs/heads/main"),
        host="example.com",
        headers=(AUTH, RECEIVE_TYPE, ("host", HOST)),
    )
    assert translate(view, CTX) is None


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/../demo/git-receive-pack"),
        ("POST", "/octo/../git-receive-pack"),
        ("POST", "/octo/./git-receive-pack"),
        ("POST", "/octo//git-receive-pack"),
        ("POST", "/octo/.git/git-receive-pack"),
        ("POST", "/octo/de%6do/git-receive-pack"),
        ("POST", "/octo/de;mo/git-receive-pack"),
        ("POST", "/-octo/demo/git-receive-pack"),
        ("POST", f"{REPO}/git-receive-pack?x=1"),
        ("POST", f"{REPO}/git-receive-pack#x"),
        ("GET", f"{REPO}/git-receive-pack"),
        ("PUT", f"{REPO}/git-receive-pack"),
        ("post", f"{REPO}/git-receive-pack"),
        ("GET", f"{REPO}/git-upload-pack"),
        ("POST", f"{REPO}/info/refs"),
        ("GET", f"{REPO}/info/refs?service=git-upload-archive"),
        ("GET", f"{REPO}/info/refs?service=git-upload-pack&service=git-receive-pack"),
        ("GET", f"{REPO}/info/refs?service=git-upload-pack&x=1"),
        ("DELETE", f"{REPO}/info/refs"),
    ],
)
def test_odd_paths_and_methods_on_a_git_route_are_held(method: str, path: str) -> None:
    body = commands(f"{ZERO} {B} refs/heads/main") if method != "GET" else b""
    held(request(method, HOST, path, body=body, headers=(AUTH, RECEIVE_TYPE)))


def test_a_discovery_with_a_body_is_held() -> None:
    held(request("GET", HOST, f"{REPO}/info/refs?service=git-upload-pack", body=b"0000"))


@pytest.mark.parametrize(
    "headers",
    [
        (AUTH,),  # no Content-Type
        (AUTH, UPLOAD_TYPE),  # the fetch's
        (AUTH, ("content-type", "application/json")),
        (AUTH, RECEIVE_TYPE, ("content-type", "application/x-git-receive-pack-request")),
        (AUTH, AUTH, RECEIVE_TYPE),  # two credentials: whose push?
    ],
)
def test_a_push_without_its_own_content_type_or_with_two_credentials_is_held(
    headers: tuple[tuple[str, str], ...],
) -> None:
    held(push(commands(f"{ZERO} {B} refs/heads/main"), headers=headers))


def test_a_fetch_without_its_own_content_type_is_held() -> None:
    body = fixture("fetch-v2-fetch.bin")
    held(request("POST", HOST, f"{REPO}/git-upload-pack", body=body, headers=(AUTH, RECEIVE_TYPE)))


# --- hostile bodies ------------------------------------------------------------------------------

GOOD = commands(f"{A} {B} refs/heads/main")
HOSTILE_PUSHES = {
    "empty": b"",
    "truncated_header": b"00",
    "truncated_line": GOOD[:30],
    "truncated_before_flush": GOOD[: GOOD.index(b"0000PACK")],
    "length_not_hex": b"zzzz" + GOOD[4:],
    "length_with_sign": b"+0b6" + GOOD[4:],
    "oversized_length": b"ffff" + b"a" * 0xFFFB + b"0000",
    "length_past_the_end": b"fff0" + GOOD[4:],
    "packet_0003": b"0003" + GOOD,
    "empty_packet_0004": b"0004" + GOOD,
    "delim_in_commands": GOOD.replace(b"0000PACK", b"00010000PACK"),
    "response_end_in_commands": pkt(f"{A} {B} refs/heads/main".encode()) + b"0002" + b"0000",
    "pack_and_no_commands": PACK,
    "flush_then_pack": b"0000" + PACK,
    "two_flushes": b"00000000",
    "garbage_after_commands": GOOD.replace(b"0000PACK", b"0000JUNK"),
    "pack_after_deletes_only": commands(f"{A} {ZERO} refs/heads/old"),
    "json": b'{"ref":"refs/heads/main"}',
    "nul_in_second_command": commands(f"{A} {B} refs/heads/a", f"{A} {B} refs/heads/b\0x"),
    "upper_case_id": commands(f"{A.upper()} {B} refs/heads/main"),
    "short_id": commands(f"{A[:39]} {B} refs/heads/main"),
    "id_not_hex": commands(f"{'g' * 40} {B} refs/heads/main"),
    "both_ids_zero": commands(f"{ZERO} {ZERO} refs/heads/main"),
    "no_ref": commands(f"{A} {B}"),
    "two_spaces": commands(f"{A}  {B} refs/heads/main"),
    "ref_too_long": commands(f"{A} {B} refs/heads/{'x' * 300}"),
    "signed_push": pkt(b"push-cert\0 report-status") + pkt(b"certificate version 0.1\n") + b"0000",
    "two_object_formats": commands(
        f"{A} {B} refs/heads/main", caps=b" object-format=sha1 object-format=sha256"
    ),
    "unknown_object_format": commands(f"{A} {B} refs/heads/main", caps=b" object-format=md5"),
    "sha1_ids_in_a_sha256_push": commands(
        f"{A} {B} refs/heads/main", caps=b" object-format=sha256"
    ),
    "push_options_with_a_value": commands(
        f"{A} {B} refs/heads/main", caps=CAPS + b" push-options=1", pack=PACK
    ),
    "unknown_capability": commands(f"{A} {B} refs/heads/main", caps=CAPS + b" exfil=hola"),
    "capability_with_a_control": commands(f"{A} {B} refs/heads/main", caps=b" agent=\x1b[2J"),
    "bad_shallow_line": pkt(b"shallow nothex") + GOOD,
    "shallow_after_commands": GOOD.replace(b"0000PACK", pkt(f"shallow {A}".encode()) + b"0000PACK"),
}


@pytest.mark.parametrize("name", list(HOSTILE_PUSHES))
def test_hostile_pushes_are_held_quickly(name: str) -> None:
    held(push(HOSTILE_PUSHES[name]))


def test_an_oversized_length_says_too_large() -> None:
    reading = held(push(HOSTILE_PUSHES["oversized_length"]))
    assert Note.TOO_LARGE in reading.notes  # type: ignore[attr-defined]


def test_pkt_line_reads_exactly_and_refuses_the_rest() -> None:
    assert pkt_line(b"0009done\n", 0) == (b"done\n", 9)
    assert pkt_line(b"0000", 0) == (0, 4) and pkt_line(b"0001", 0) == (1, 4)
    assert pkt_line(b"0009DONE\n", 0)[0] == b"DONE\n"
    assert pkt_line(b"000A123456", 0) == (b"123456", 10)  # git reads upper-case hex too


def test_many_refs_are_held_past_the_cap_and_shown_cut_below_it() -> None:
    lines = [f"{ZERO} {B} refs/heads/branch-{n:03d}" for n in range(MAX_COMMANDS + 1)]
    over = held(push(commands(*lines)))
    assert Note.TOO_MANY_RECIPIENTS in over.notes  # type: ignore[attr-defined]
    reading = read(push(commands(*lines[:MAX_COMMANDS])))
    assert reading.effect is Effect.CHANGE and len(reading.recipients) == MAX_COMMANDS
    assert reading.target is not None and len(reading.target) <= TARGET_CHARS
    assert reading.target.startswith("github.com/octo/demo: crea branch-000, branch-001")
    assert reading.target.endswith(" más")
    shown = reading.target.count("branch-")
    assert reading.target.endswith(f" y {MAX_COMMANDS - shown} más")
    assert protocol.fit_reading(reading.summary())["cut"] is False


def test_many_shallow_lines_are_held_in_bounded_time() -> None:
    body = b"".join(pkt(f"shallow {A}".encode()) for _ in range(5000)) + GOOD
    reading = held(push(body))
    assert Note.TOO_LARGE in reading.notes  # type: ignore[attr-defined]


def test_a_huge_push_is_held_as_too_large() -> None:
    reading = held(push(commands(f"{A} {B} refs/heads/main", pack=PACK + b"\0" * MAX_BODY)))
    assert Note.TOO_LARGE in reading.notes  # type: ignore[attr-defined]


def test_the_same_ref_twice_is_held() -> None:
    body = commands(f"{A} {B} refs/heads/main", f"{B} {A} refs/heads/main")
    reading = held(push(body))
    assert Note.DUPLICATE in reading.notes  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "ref",
    [
        b"HEAD",
        b"main",
        b"refs/heads/a..b",
        b"refs/heads/.hidden",
        b"refs/heads/x.lock",
        b"refs/heads/x/",
        b"refs/heads/x.",
        b"refs/heads//x",
        b"refs/heads/a@{1}",
        b"refs/heads/a,crea-main",  # git allows a comma: it would write in our list
        b"refs/heads/a;borra-main",
        b"refs/heads/a~1",
        b"refs/heads/caf\xc3\xa9",  # git allows UTF-8: shown escaped, never trusted
        b"refs/heads/ma\x07in\x1b[31m",
        b"refs/heads/\xe2\x80\xaeniam",  # a right-to-left override
        b"refs/heads/a\\b",
    ],
)
def test_ref_names_that_are_not_plain_are_held_and_shown_escaped(ref: bytes) -> None:
    body = pkt(f"{A} {B} ".encode() + ref + b"\0" + CAPS) + b"0000" + PACK
    reading = held(push(body))
    target = reading.target  # type: ignore[attr-defined]
    assert target is not None and target.startswith("github.com/octo/demo: actualiza ")
    assert target.isprintable() and target.isascii()
    assert escape_ref(ref).removeprefix("refs/heads/") in target


def test_escape_ref_shows_every_byte_that_is_not_plain() -> None:
    assert escape_ref(b"refs/heads/ma\x07in") == "refs/heads/ma\\x07in"
    assert escape_ref(b"a b\x7f\\") == "a\\x20b\\x7f\\\\"
    assert escape_ref("‮".encode()) == "\\xe2\\x80\\xae"


def test_a_ref_name_with_a_secret_is_held_with_risk_3_and_struck() -> None:
    secret = "ghp_" + "a1B2c3D4e5" * 4
    reading = held(push(commands(f"{ZERO} {B} refs/heads/{secret[:36]}")))
    assert reading.secret_seen and reading.risk == 3  # type: ignore[attr-defined]
    assert secret[:36] not in (reading.target or "")  # type: ignore[attr-defined]


def test_a_known_secret_in_a_capability_or_the_repository_is_held_with_risk_3() -> None:
    context = scrubbed("supersecretvalue123")
    caps = CAPS + b" session-id=supersecretvalue123"
    reading = held(push(commands(f"{ZERO} {B} refs/heads/main", caps=caps)), context)
    assert reading.secret_seen and reading.risk == 3  # type: ignore[attr-defined]
    path = "/octo/supersecretvalue123/git-receive-pack"
    named = held(push(commands(f"{ZERO} {B} refs/heads/main"), path=path), context)
    assert named.secret_seen  # type: ignore[attr-defined]
    assert "supersecretvalue123" not in (named.target or "")  # type: ignore[attr-defined]


def test_a_sha256_push_and_shallow_lines_are_read() -> None:
    old, new = "a" * 64, "b" * 64
    body = commands(f"{old} {new} refs/heads/main", caps=b" object-format=sha256")
    assert read(push(body)).effect is Effect.CHANGE
    shallow = pkt(f"shallow {A}\n".encode()) + GOOD
    assert read(push(shallow)).effect is Effect.CHANGE


# --- hostile fetches -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"00",
        b"0014command=ls-ref",  # truncated
        b"ffff" + b"a" * 0xFFFB,
        b"0003",
        b"zzzzcommand=fetch",
        fixture("fetch-v2-fetch.bin") + b"x",
        b"0009want\n" * 8000,  # 72 000 bytes: over a read's 64 KiB
    ],
)
def test_hostile_fetches_are_held(body: bytes) -> None:
    held(fetch(body))


def test_a_fetch_that_carries_a_secret_is_held_with_risk_3() -> None:
    secret = "ghp_" + "a1B2c3D4e5" * 4
    body = pkt(b"command=ls-refs") + b"0001" + pkt(f"ref-prefix refs/{secret[:36]}".encode())
    reading = held(fetch(body + b"0000"))
    assert reading.secret_seen and reading.risk == 3  # type: ignore[attr-defined]


V2_FETCH = pkt(b"command=fetch\n") + pkt(b"agent=git/2.54.0\n") + pkt(b"object-format=sha1\n")
V0_WANT = f"want {A} multi_ack_detailed side-band-64k thin-pack ofs-delta agent=git/2.54.0\n"


@pytest.mark.parametrize(
    "body",
    [
        V2_FETCH + b"0001" + pkt(f"want {A}\n".encode()) + pkt(b"done\n") + b"0000",
        V2_FETCH
        + b"0001"
        + pkt(f"want {A}\n".encode())
        + pkt(b"filter blob:none\n")
        + pkt(b"deepen 1\n")
        + pkt(b"include-tag\n")
        + pkt(b"done\n")
        + b"0000",
        pkt(b"command=ls-refs\n") + b"0001" + pkt(b"peel\n") + pkt(b"ref-prefix HEAD\n") + b"0000",
        pkt(b"command=ls-refs\n") + b"0000",
        pkt(b"command=object-info\n")
        + b"0001"
        + pkt(b"size\n")
        + pkt(f"oid {A}\n".encode())
        + b"0000",
        pkt(V0_WANT.encode())
        + pkt(f"want {B}\n".encode())
        + pkt(f"shallow {A}\n".encode())
        + pkt(b"deepen 1\n")
        + b"0000"
        + pkt(f"have {B}\n".encode())
        + pkt(b"done\n"),
    ],
    ids=["v2-fetch", "v2-fetch-args", "v2-ls-refs", "v2-ls-refs-bare", "v2-object-info", "v0"],
)
def test_fetches_in_their_grammar_pass(body: bytes) -> None:
    assert read(fetch(body)).effect is Effect.READ


@pytest.mark.parametrize(
    "body",
    [
        pkt(b"command=fetch\n") + pkt(b"server-option=anything\n") + b"0000",
        pkt(b"command=bundle-uri\n") + b"0000",
        pkt(b"command=push\n") + b"0000",
        pkt(b"command=fetch\n") + pkt(b"x-exfil=hola\n") + b"0000",
        V2_FETCH + b"0001" + pkt(b"hello world\n") + b"0000",
        V2_FETCH + b"0001" + pkt(b"want nothex\n") + b"0000",
        V2_FETCH + b"0001" + pkt(b"peel\n") + b"0000",  # an ls-refs argument in a fetch
        V2_FETCH + b"0001" + pkt(f"want {A}\n".encode()) + b"0000" + V2_FETCH + b"0000",
        V2_FETCH,  # no flush
        V2_FETCH + b"0001" + pkt(b"deepen many\n") + b"0000",
        V2_FETCH + b"0001" + pkt(b"filter a b\n") + b"0000",
        pkt(b"command=ls-refs\n") + b"0001" + pkt(b"ref-prefix refs/a b\n") + b"0000",
        pkt(f"want {A} multi_ack exfil-capability\n".encode()) + b"0000",
        pkt(b"hello\n") + b"0000",
        pkt(f"have {A}\n".encode()) + pkt(b"done\n"),  # no want
        pkt(V0_WANT.encode()) + pkt(f"want {B} side-band\n".encode()) + b"0000",
        pkt(V0_WANT.encode()) + b"0001" + pkt(b"done\n"),
    ],
    ids=[
        "server-option",
        "bundle-uri",
        "push-command",
        "unknown-capability",
        "free-text",
        "bad-want",
        "ls-refs-arg-in-fetch",
        "two-commands",
        "no-flush",
        "bad-deepen",
        "bad-filter",
        "bad-ref-prefix",
        "v0-unknown-capability",
        "v0-free-text",
        "v0-no-want",
        "v0-caps-on-second-want",
        "v0-delim",
    ],
)
def test_fetches_outside_their_grammar_are_held(body: bytes) -> None:
    held(fetch(body))


GHP = "ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3"  # 36 after the prefix, like GitHub's
PAT = "github_pat_" + "A1b2c3D4e5" * 2 + "Zz" + "_" + "q9W8e7R6t5" * 5 + "y4U3i2O1p"
FOREIGN = "sk-ant-api03-" + "Ab1" * 30
GATEWAY_HEX = "9f" * 24  # a secret of letters and digits only, like a Gateway token


def _basic(user: str, password: str) -> tuple[str, str]:
    return ("authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())


@pytest.mark.parametrize(
    "header",
    [
        ("authorization", f"Bearer {FOREIGN}"),
        ("authorization", f"token {FOREIGN}"),
        _basic("x-access-token", FOREIGN),
        _basic(FOREIGN, "x"),
        ("private-token", FOREIGN),
        ("cookie", f"session={FOREIGN}"),
        ("authorization", f"Bearer {GHP}{FOREIGN}"),  # glued after a GitHub token
        ("authorization", f"Bearer {GHP}-{FOREIGN}"),
        _basic("x-access-token", GHP + FOREIGN),
        _basic(GHP + FOREIGN, "x"),
        # Letters and digits only, glued on: part of "one token" if any length were one.
        ("authorization", f"token {GHP}{GATEWAY_HEX}"),
        ("authorization", f"Bearer {PAT}{GATEWAY_HEX}"),
    ],
)
def test_another_services_key_toward_github_is_held_with_risk_3(header: tuple[str, str]) -> None:
    """The gate lets a translated read pass whatever its credential says (it is the API's own),
    so the git translator itself refuses a key the redaction knows that is not GitHub's: else
    an agent could hand out the model's key with a harmless fetch."""
    for view in (
        request("GET", HOST, f"{REPO}/info/refs?service=git-upload-pack", headers=(header,)),
        request("POST", HOST, f"{REPO}/git-upload-pack", body=fixture("fetch-v0.bin"),
                headers=(header, UPLOAD_TYPE)),
        push(GOOD, headers=(header, RECEIVE_TYPE)),
    ):  # fmt: skip
        reading = held(view)
        assert reading.secret_seen and reading.risk == 3  # type: ignore[attr-defined]


def test_a_known_secret_as_the_credential_is_held_too() -> None:
    context = scrubbed("the-real-model-key-123456")
    view = request(
        "GET", HOST, f"{REPO}/info/refs", headers=(_basic("u", "the-real-model-key-123456"),)
    )
    assert held(view, context).secret_seen  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "header",
    [
        ("authorization", f"Bearer {GHP}"),
        ("authorization", f"token {GHP}"),
        _basic("x-access-token", GHP),
        _basic("octo", PAT),
        _basic("x-access-token", "fake-github-token"),
    ],
)
def test_githubs_own_tokens_pass(header: tuple[str, str]) -> None:
    view = request("GET", HOST, f"{REPO}/info/refs?service=git-upload-pack", headers=(header,))
    assert read(view).effect is Effect.READ


def test_a_compressed_body_is_read_only_once_decoded() -> None:
    """git gzips a large fetch body. The addon decodes it and drops its Content-Encoding; a body
    still encoded is held (``base.common_refusal``), never read as it came."""
    raw = fixture("fetch-v0.bin")
    still = request(
        "POST",
        HOST,
        f"{REPO}/git-upload-pack",
        body=gzip.compress(raw),
        headers=(AUTH, UPLOAD_TYPE, ("content-encoding", "gzip")),
    )
    held(still)
    assert read(fetch(raw)).effect is Effect.READ


def test_trailers_and_override_headers_are_held() -> None:
    held(push(GOOD, trailers=True))
    held(push(GOOD, headers=(AUTH, RECEIVE_TYPE, ("x-http-method-override", "GET"))))
    held(replace(fetch(fixture("fetch-v0.bin")), trailers=True))


# --- the account, the fingerprint and the batches ------------------------------------------------


def test_the_account_is_the_credential_and_the_repository() -> None:
    body = commands(f"{ZERO} {B} refs/heads/main")
    base = read(push(body)).account
    assert read(push(body, path="/octo/demo/git-receive-pack")).account == base
    assert read(push(body, path="/Octo/Demo.GIT/git-receive-pack")).account == base
    assert read(push(body, path="/octo/other/git-receive-pack")).account != base
    assert read(push(body, headers=(OTHER_AUTH, RECEIVE_TYPE))).account != base
    assert read(push(body, headers=(RECEIVE_TYPE,))).account not in (None, base)
    assert read(request("GET", HOST, f"{REPO}/info/refs", headers=(AUTH,))).account == base
    assert read(push(body), Context(bytes(range(1, 33)))).account != base


def _fp(view: RequestView) -> str:
    reading = read(view)
    return fingerprint(
        KEY,
        method=view.method,
        host=view.host,
        port=view.port,
        path=view.path,
        headers=view.headers,
        body=view.body,
        canonical=reading.canonical,
    )


def test_the_semantic_fingerprint_ignores_the_agent_and_session_but_not_what_moves() -> None:
    line = f"{A} {B} refs/heads/main"
    same = _fp(push(commands(line)))
    assert _fp(push(commands(line, caps=CAPS.replace(b"2.54.0", b"2.47.1")))) == same
    assert _fp(push(commands(line, caps=CAPS + b" session-id=20261022T1-123"))) == same
    assert _fp(push(commands(line, caps=CAPS + b" atomic"))) != same
    assert _fp(push(commands(f"{A} {A} refs/heads/main"))) != same
    assert _fp(push(commands(f"{A} {B} refs/heads/dev"))) != same
    assert _fp(push(commands(line, pack=PACK + b"x"))) != same  # another pack
    assert _fp(push(commands(line), path="/octo/other/git-receive-pack")) != same
    exact = fingerprint(KEY, method="POST", host=HOST, port=443,
                        path=f"{REPO}/git-receive-pack", headers=(AUTH, RECEIVE_TYPE),
                        body=commands(line))  # fmt: skip
    assert exact != same  # a semantic fingerprint is never an exact one


def test_the_canonical_form_is_never_shown() -> None:
    reading = read(push(fixture("push-mixed.bin")))
    assert reading.canonical is not None
    assert reading.canonical.startswith(b"backtide-semantic-v1\n")
    assert "canonical" not in reading.summary() and "canonical" not in repr(reading)


def _scope(view: RequestView) -> object:
    reading = read(view)
    return reading_scope(protocol.fit_reading(reading.summary()), risk=reading.risk,
                         scheme="https", port=443)  # fmt: skip


def _held_in(book: HoldBook, view: RequestView, fp: str = "a" * 64):  # type: ignore[no-untyped-def]
    hold = book.open(fp, risk=2, reason="send", event={}, scope=_scope(view))
    assert hold is not None
    book.recorded(hold, 1)
    return hold


def test_a_push_that_moves_an_existing_ref_never_rides_a_batch() -> None:
    """Security review of T17b-1 (M1): an update may be a forced push (to an orphan commit, say)
    and the body cannot tell, so it is always asked, one by one."""
    for body in (
        commands(f"{A} {B} refs/heads/main"),
        fixture("push-force.bin"),
        commands(f"{ZERO} {B} refs/heads/new", f"{A} {B} refs/heads/main"),
    ):
        reading = read(push(body))
        assert reading.effect is Effect.CHANGE and reading.risk == 2
        assert Note.MOVES_REF in reading.notes
        assert not _scope(push(body)).batchable  # type: ignore[attr-defined]
    book = HoldBook()
    hold = _held_in(book, push(commands(f"{A} {B} refs/heads/main")))
    assert book.offers(hold) == ()
    assert book.add_batch(hold, BatchKind.KIND) is BatchRefused.NOT_BATCHABLE


def test_only_pushes_that_create_new_refs_in_one_repository_ride_its_batch() -> None:
    book = HoldBook()
    hold = _held_in(book, push(commands(f"{ZERO} {B} refs/heads/feature/x")))
    assert book.offers(hold) == (BatchKind.KIND,)  # a recipient batch would add nothing
    assert book.add_batch(hold, BatchKind.RECIPIENT) is BatchRefused.NOT_BATCHABLE
    rule = book.add_batch(hold, BatchKind.KIND)  # "pushes que crean ramas nuevas, 1 h"
    assert isinstance(rule, BatchRule)

    def covered(view: RequestView) -> bool:
        return book.batch_for(_scope(view)) is rule  # type: ignore[arg-type]

    assert covered(push(commands(f"{ZERO} {A} refs/heads/feature/y")))
    assert covered(push(commands(f"{ZERO} {A} refs/tags/v2")))
    assert covered(push(commands(f"{ZERO} {A} refs/heads/z"), path="/Octo/Demo/git-receive-pack"))
    assert not covered(push(commands(f"{A} {B} refs/heads/main")))  # an update
    assert not covered(push(commands(f"{A} {'c' * 40} refs/heads/main")))  # maybe forced
    assert not covered(push(commands(f"{B} {A} refs/heads/feature/x")))  # the ref just made
    assert not covered(push(commands(f"{ZERO} {A} refs/heads/n", f"{A} {B} refs/heads/main")))
    assert not covered(push(commands(f"{ZERO} {A} refs/heads/z"), path="/octo/x/git-receive-pack"))
    assert not covered(
        push(commands(f"{ZERO} {A} refs/heads/z"), headers=(OTHER_AUTH, RECEIVE_TYPE))
    )
    assert not covered(push(commands(f"{A} {ZERO} refs/heads/old", pack=None)))  # a deletion
    assert not covered(push(fixture("push-options.bin")))  # unknown


def test_what_may_never_ride_a_batch() -> None:
    for view in (
        push(fixture("push-mixed.bin")),  # deletes a branch
        push(fixture("push-delete-tag.bin")),
        push(fixture("push-force.bin")),
        push(HOSTILE_PUSHES["garbage_after_commands"]),
    ):
        assert not _scope(view).batchable  # type: ignore[attr-defined]


def _notice(view: RequestView) -> dict[str, object]:
    reading = read(view)
    return {"hold_id": "h-0123456789ab", "risk": reading.risk,
            "reading": protocol.fit_reading(reading.summary()), "expires_in_s": 300,
            "method": "POST", "host": HOST, "path": view.path}  # fmt: skip


def test_the_batch_question_says_what_a_git_batch_covers_and_what_it_never_does() -> None:
    notice = _notice(push(commands(f"{ZERO} {B} refs/heads/feature/x")))
    assert batch_label(notice, "kind") == "Pushes que crean ramas nuevas, 1 h"
    question = batch_question(notice, "kind")
    ours, _, agent = question.partition("Lo que pide el agente")
    assert "solo crea ramas o etiquetas nuevas" in ours and "este mismo repositorio" in ours
    assert "Mover o borrar una rama o etiqueta que ya existe" in ours
    assert "GitHub Actions" in ours
    assert "cualquier destinatario" not in question
    assert "github" in agent and "octo/demo: crea feature/x" in agent  # the agent's, apart
    assert "octo/demo" not in ours
    listed = batches_text([{"translator": "git", "scope": "kind", "effect": "change",
                            "left_s": 3000, "uses": 2}])  # fmt: skip
    assert "git, pushes que crean ramas nuevas, 1 h" in listed


# --- the sentence ---------------------------------------------------------------------------------


def test_the_sentence_says_the_repository_and_each_ref() -> None:
    created = read(push(fixture("push-create.bin"))).summary()
    assert action(created) == "git: push a un repositorio"
    assert describe(created) == (
        "git: push a un repositorio (github.com/octo/demo: crea main; backtide no ve el código "
        "que lleva)"
    )
    deleting = read(push(fixture("push-mixed.bin"))).summary()
    assert action(deleting) == "git: push que borra ramas o etiquetas"
    assert "borra old" in describe(deleting)
    # The web gives ``action`` and ``note_texts`` only the translator and the effect.
    assert note_texts({"translator": "git", "effect": "change"})
    unknown = read(push(fixture("push-options.bin"))).summary()
    forced = read(push(fixture("push-force.bin"))).summary()
    assert "mueve una rama o etiqueta que ya existe" in describe(forced)
    assert "mueve" not in describe(created)
    assert action(unknown) == "git: una petición que backtide no entiende"
    assert not any("forzado" in text for text in note_texts(unknown))


def test_every_git_reading_crosses_the_channel() -> None:
    views = [
        push(fixture(name))
        for name in ("push-create.bin", "push-mixed.bin", "push-options.bin", "push-force.bin")
    ] + [fetch(fixture("fetch-v0.bin")), push(b"0000"), push(HOSTILE_PUSHES["json"])]
    for view in views:
        reading = read(view)
        checked = protocol.fit_reading(reading.summary())
        assert checked["translator"] == "git" and checked["risk"] == reading.risk


def test_parse_push_keeps_the_pack_apart() -> None:
    parsed = parse_push(fixture("push-create.bin"))
    assert parsed.pack.startswith(b"PACK") and len(parsed.commands) == 1
    assert parsed.commands[0].verb == "create" and parsed.capabilities[-1].startswith(b"agent=")
    assert replace(parsed.commands[0], old=b"1" * 40, new=b"0" * 40).verb == "delete"
    assert replace(parsed.commands[0], old=b"1" * 40).verb == "update"


def test_a_scrubber_strikes_nothing_in_an_ordinary_push() -> None:
    reading = read(push(fixture("push-mixed.bin")), Context(KEY, KnownScrubber(("unrelated",))))
    assert reading.effect is Effect.DELETE and not reading.secret_seen


def test_every_verb_shows_even_with_long_ref_names() -> None:
    long = "x" * 240
    body = commands(
        f"{A} {B} refs/heads/{long}a",
        f"{ZERO} {B} refs/heads/{long}b",
        f"{A} {ZERO} refs/heads/{long}c",
        pack=PACK,
    )
    target = read(push(body)).target
    assert target is not None and len(target) <= TARGET_CHARS
    for verb in ("actualiza ", "crea ", "borra "):
        assert verb in target, target
    assert "…(" in target  # each name cut in the middle


def test_a_branch_named_like_a_tag_is_shown_whole() -> None:
    assert short_ref("refs/heads/refs/tags/v1") == "refs/heads/refs/tags/v1"
    assert short_ref("refs/heads/main") == "main"
    assert short_ref("refs/tags/v1") == "etiqueta v1"
    reading = read(push(commands(f"{ZERO} {B} refs/heads/refs/tags/v1")))
    assert reading.target == "github.com/octo/demo: crea refs/heads/refs/tags/v1"
