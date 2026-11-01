"""The terminal relay of `backtide entrar` (T26-5c, backtide/service/terminal_relay.py).

The filter is pure: every sequence is fed whole and byte by byte, because a read can cut anywhere.
The pump runs for real on pseudo-terminals, in a process of its own (it changes the terminal's
modes and takes signals), with a small program in the place of the docker CLI. The VM test runs
it with docker and Claude Code (tests/integration/test_claude_code.py) and the attack is
``escapes-en-la-terminal``.
"""

import fcntl
import os
import random
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import textwrap
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from backtide import shell_cli
from backtide.jail import docker
from backtide.service.config import ServiceConfig
from backtide.service.terminal_relay import (
    _MODES,
    _PRIVATE_MODES,
    MAX_SEQUENCE,
    TerminalFilter,
)
from tests.test_cli_shell import READY, write_config

REPO = Path(__file__).resolve().parent.parent


def filtered(data: bytes) -> bytes:
    relay = TerminalFilter()
    return relay.feed(data) + relay.finish()


def filtered_bytewise(data: bytes) -> bytes:
    relay = TerminalFilter()
    out = b"".join(relay.feed(data[i : i + 1]) for i in range(len(data)))
    return out + relay.finish()


# --- what passes unchanged -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"hola, mundo",
        b"linea\r\n\ttabulada\x08\x07",
        "cañón € ─│┌ 🙂 ⛰".encode(),  # continuation bytes in 0x80-0x9f are text, not controls
        b"\x1b[m\x1b[0m\x1b[1;31m\x1b[38;5;208m\x1b[38;2;255;100;0m\x1b[48:2::1:2:3m\x1b[4:3m",
        b"\x1b[A\x1b[2B\x1b[3C\x1b[4D\x1b[5E\x1b[6F\x1b[7G\x1b[1;1H\x1b[10;20f\x1b[5d\x1b[3`",
        b"\x1b[J\x1b[2J\x1b[K\x1b[2K\x1b[3L\x1b[3M\x1b[3P\x1b[3X\x1b[3@\x1b[2S\x1b[2T\x1b[1;24r",
        b"\x1b[s\x1b[u\x1b[I\x1b[Z\x1b[g\x1b[3b\x1b[4h\x1b[4l",
        b"\x1b[?25l\x1b[?25h\x1b[?1049h\x1b[?1049l\x1b[?47h\x1b[?1047h\x1b[?1048h\x1b[?1h\x1b[?7l",
        b"\x1b[?1000;1006h\x1b[?1002h\x1b[?1003h\x1b[?1004h\x1b[?1015h\x1b[?2004h\x1b[?2026h",
        b"\x1b[!p\x1b[2 q",  # soft reset, cursor style
        b"\x1b7\x1b8\x1b=\x1b>\x1bM\x1bD\x1bE\x1bH\x1bc\x1b(B\x1b(0\x1b)0\x0e\x0f",
        b"\x1b]0;mi ventana\x07\x1b]2;otro t\xc3\xadtulo; con punto y coma\x07",
    ],
)
def test_what_a_normal_program_prints_passes_unchanged(data: bytes) -> None:
    assert filtered(data) == data
    assert filtered_bytewise(data) == data


# --- what never reaches the terminal -------------------------------------------------------------

ST = b"\x1b\\"
DROPPED = [
    # OSC but the title: clipboard, links, colours and their questions, the iTerm2 file transfer
    b"\x1b]52;c;ZXZpbA==\x07",
    b"\x1b]52;c;ZXZpbA==" + ST,
    b"\x1b]52;c;?\x07",
    b"\x1b]8;;https://evil.test/\x07",
    b"\x1b]8;;https://evil.test/" + ST,
    b"\x1b]1;icono\x07",
    b"\x1b]4;1;rgb:ff/00/00\x07",
    b"\x1b]10;?\x07",
    b"\x1b]11;?\x07",
    b"\x1b]7;file://h/x\x07",
    b"\x1b]9;aviso\x07",
    b"\x1b]104\x07",
    b"\x1b]133;A\x07",
    b"\x1b]777;notify;a;b\x07",
    b"\x1b]1337;File=name=eA==:ZXZpbA==\x07",
    b"\x1b]00;no es 0\x07",
    b"\x1b]0\x07",
    b"\x1b]\x07",
    # A title that asks instead of setting
    b"\x1b]2;?\x07",
    b"\x1b]0;?" + ST,
    # DCS, APC, PM and SOS, whole: DECRQSS, XTGETTCAP, tmux's passthrough, sixel, DECUDK, images
    b"\x1bP$qm" + ST,
    b"\x1bP+q544e" + ST,
    b"\x1bPtmux;\x1b\x1b]52;c;ZXZpbA==\x07" + ST,
    b"\x1bPq#0;2;0;0;0#0~~" + ST,
    b"\x1bP0|23/ZXZpbA==" + ST,
    b"\x1b_Ga=T,f=100;ZXZpbA==" + ST,
    b"\x1b^mensaje" + ST,
    b"\x1bXcadena" + ST,
    # CSI that asks the terminal for a report
    b"\x1b[c",
    b"\x1b[0c",
    b"\x1b[>c",
    b"\x1b[=c",
    b"\x1b[5n",
    b"\x1b[6n",
    b"\x1b[?6n",
    b"\x1b[?996n",
    b"\x1b[x",
    b"\x1b[1x",
    b"\x1b[>0q",
    b"\x1b[?u",
    b"\x1b[?1$p",
    b"\x1b[4$p",
    b"\x1b[1$u",
    b"\x1b[1$w",
    b"\x1b[1;1;1;1;1;1*y",
    b"\x1b[?1;1S",
    b"\x1b[?25$p",
    # CSI t, window operations and reports: the title, the size, moving or iconifying it
    b"\x1b[21t",
    b"\x1b[20t",
    b"\x1b[18t",
    b"\x1b[14t",
    b"\x1b[11t",
    b"\x1b[2t",
    b"\x1b[3;0;0t",
    b"\x1b[8;999;999t",
    # What outlives the session or changes how the terminal reads input
    b"\x1b[>1u",
    b"\x1b[<1u",
    b"\x1b[=1;1u",
    b"\x1b[>4;2m",
    b"\x1b[?4m",
    b"\x1b[?2031h",
    b"\x1b[?1007h",
    b"\x1b[2h",
    b"\x1b[12h",
    b"\x1b[20h",
    b"\x1b[5i",
    b"\x1b[4i",
    b"\x1b[1;2$x",
    b'\x1b[1"q',
    # Answerback and the other questions and switches outside CSI
    b"\x05",
    b"\x1bZ",
    b"\x1b%@",
    b"\x1b%G",
    b"\x1b G",
    b"\x1b F",
    b"\x1b#8",
    b"\x1bN",
    b"\x1bO",
    b"\x1bn",
    b"\x1bk",
    b"\x1b\\",
    # Other C0
    b"\x00\x01\x02\x03\x04\x06\x10\x11\x13\x1c\x1d\x1e\x1f\x7f",
    # The 8-bit forms, as UTF-8 (some terminals take U+0080-U+009F as controls)
    "\u009d52;c;ZXZpbA==\u009c".encode(),
    "\u009d52;c;ZXZpbA==\x07".encode(),
    "\u009b6n".encode(),
    "\u009bc".encode(),
    "\u0090$qm\u009c".encode(),
    "\u009fGa=T\u009c".encode(),
    "\u009emensaje\u009c".encode(),
    "\u0098cadena\u009c".encode(),
    "\u009c".encode(),
    "\u0085\u0084\u0088".encode(),
]


@pytest.mark.parametrize("data", DROPPED)
def test_it_never_reaches_the_terminal(data: bytes) -> None:
    assert filtered(data) == b""
    assert filtered_bytewise(data) == b""


@pytest.mark.parametrize("data", DROPPED)
def test_what_is_around_it_stays(data: bytes) -> None:
    assert filtered(b"antes" + data + b"despues") == b"antesdespues"
    assert filtered_bytewise(b"antes" + data + b"despues") == b"antesdespues"


@pytest.mark.parametrize(
    "raw",
    [
        b"\x9d52;c;ZXZpbA==\x07",
        b"\x9b6n",
        b"\x90$qm\x9c",
        b"\x9fGa\x9c",
        b"\xc0\x9b6n",
        b"\xe0\x80\x9b6n",
    ],
)
def test_raw_8_bit_controls_and_overlong_forms_are_not_controls(raw: bytes) -> None:
    """Not UTF-8: each bad byte comes out as U+FFFD, so nothing that the terminal could take for
    a control is left. What follows is plain text."""
    for out in (filtered(raw), filtered_bytewise(raw)):
        text = out.decode()
        assert "�" in text
        assert not any(0x80 <= ord(c) <= 0x9F or ord(c) == 0x1B for c in text)


def test_every_mode_it_lets_through_is_undone_when_the_session_ends() -> None:
    """Each mode by name, on or off as it has to end up. Leaving the alternate screen covers its
    two other forms, and a blinking cursor is left as it is. A mode added to the lists has to be
    added to the reset."""
    elsewhere = {"47", "1047", "1048", "12"}
    ends_on = {"7", "25"}  # line wrap, the cursor
    for mode in _PRIVATE_MODES - elsewhere:
        setting = "h" if mode in ends_on else "l"
        assert f"\x1b[?{mode}{setting}" in shell_cli.TERMINAL_RESET, mode
    for mode in _MODES:
        assert f"\x1b[{mode}l" in shell_cli.TERMINAL_RESET, mode
    assert "\x1b[20l" in shell_cli.TERMINAL_RESET  # dropped, but it costs nothing to be sure
    assert shell_cli.TERMINAL_RESET.startswith("\x18\x1b[?1049l\x1b[!p")  # CAN: a cut sequence ends
    # Margins and origin send the cursor home: not over what is on the screen.
    assert "\x1b7\x1b[r\x1b[?6l\x1b8" in shell_cli.TERMINAL_RESET
    # Restoring the cursor brings back its colours and character sets: those go after it.
    assert shell_cli.TERMINAL_RESET.index("\x1b8") < shell_cli.TERMINAL_RESET.index("\x1b[0m")
    assert shell_cli.TERMINAL_RESET.index("\x1b8") < shell_cli.TERMINAL_RESET.index("\x1b(B")


# --- the title -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x1b]0;a\x01b\x7fc\x07", b"\x1b]0;abc\x07"),
        (b"\x1b]2;a\tb\nc\x07", b"\x1b]2;abc\x07"),
        ("\x1b]2;a‮b​c\x07".encode(), b"\x1b]2;abc\x07"),  # right-to-left, zero width
        (b"\x1b]2;titulo" + ST, b"\x1b]2;titulo\x07"),  # always written the same way
        ("\x1b]2;titulo\u009c".encode(), b"\x1b]2;titulo\x07"),
        (b"\x1b]0;\x07", b"\x1b]0;\x07"),
        (b"\x1b]0;\xff\x07", "\x1b]0;�\x07".encode()),
    ],
)
def test_a_title_comes_out_clean(data: bytes, expected: bytes) -> None:
    assert filtered(data) == expected
    assert filtered_bytewise(data) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x1b]0;a\x1b[31mb", b"\x1b[31mb"),  # ESC ends the title: it is lost, the rest goes on
        (b"\x1b]0;a\x18b", b"b"),  # CAN
        (b"\x1b]0;a\x1ab", b"b"),  # SUB
        ("\x1b]0;a\u009b31mb".encode(), b"\x1b[31mb"),  # a C1 too
        (b"\x1b]0;sin final", b""),
    ],
)
def test_an_interrupted_title_is_lost(data: bytes, expected: bytes) -> None:
    assert filtered(data) == expected
    assert filtered_bytewise(data) == expected


def test_a_long_title_is_lost_whole_and_memory_stays_bounded() -> None:
    relay = TerminalFilter()
    assert relay.feed(b"\x1b]0;" + b"x" * (10 * MAX_SEQUENCE)) == b""
    assert relay.buffered() <= MAX_SEQUENCE
    assert relay.feed(b"\x07fin") == b"fin"


# --- sequences that are cut, interrupted or hostile ---------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x1b[31", b""),  # cut by the end of the session
        (b"\x1b", b""),
        (b"\x1b[", b""),
        (b"\x1bP", b""),
        (b"\xe2\x94", "�".encode()),  # half a character
        (b"\x1b[31\x18m", b"m"),  # CAN and SUB end any sequence, what follows is text
        (b"\x1b[31\x1am", b"m"),
        (b"\x1b\x18m", b"m"),
        (b"\x1b(\x18B", b"B"),
        (b"\x1bPa\x18b", b"b"),
        (b"\x1b[31\x1b[32m", b"\x1b[32m"),  # ESC starts over
        (b"\x1b\x1b[32m", b"\x1b[32m"),
        (b"\x1b[3\n1m", b"\x1b[31m"),  # C0 inside a sequence is dropped; the sequence goes on
        (b"\x1b\n[31m", b"\x1b[31m"),
        (b"\x1b[3\xc3\xa11m", "á1m".encode()),  # text ends it
        ("\x1bá".encode(), "á".encode()),
        (b"\x1b(\xc3\xa1", "á".encode()),
        (b"\x1b[31;?m", b""),  # out of order: never a sequence we can vouch for
        (b"\x1b[?1049 h", b""),
        (b"\x1b[31 m", b""),
        (b"\x1b[1:2H", b""),  # colons only in colours
        (b"\x1b[?25;2031h", b""),  # one mode outside the list drops all of it
        (b"\x1b[4;2h", b""),
        (b"\x1b[1u", b""),
        (b"\x1bPa\x1b]52;c;ZXZpbA==\x07b", b"b"),  # a string cut by another: dropped too
        (b"\x1bPa\x1b[31mb", b"\x1b[31mb"),
        (b"\x1bPa\x07b" + ST + b"c", b"c"),  # BEL does not end a DCS
        (b"\x1b]52;c;\x1bPa" + ST + b"b", b"b"),
        (b"\x1b]0;a\x1b\x1b]2;b\x07", b"\x1b]2;b\x07"),
    ],
)
def test_cut_and_interrupted_sequences(data: bytes, expected: bytes) -> None:
    assert filtered(data) == expected
    assert filtered_bytewise(data) == expected


def test_an_endless_csi_is_dropped_and_memory_stays_bounded() -> None:
    relay = TerminalFilter()
    assert relay.feed(b"\x1b[" + b"1;" * MAX_SEQUENCE) == b""
    assert relay.buffered() <= MAX_SEQUENCE
    assert relay.feed(b"mfin") == b"fin"


def test_a_csi_of_the_longest_length_still_passes() -> None:
    longest = b"\x1b[" + b"1" * MAX_SEQUENCE + b"m"
    assert filtered(longest) == longest


def test_an_endless_string_keeps_nothing() -> None:
    relay = TerminalFilter()
    assert relay.feed(b"\x1bP" + b"x" * (1024 * 1024)) == b""
    assert relay.buffered() == 0
    assert relay.feed(b"\x1b\\fin") == b"fin"


# --- any input at all ----------------------------------------------------------------------------

# All the filter may ever emit: text and the few C0, the sequences it rebuilt, and nothing else.
_TEXT = r"[^\x00-\x06\x0e-\x1f\x7f-\x9f]|[\x0e\x0f]"
_CSI = r"\x1b\[[0-9;:]*[@A-HIJKLMPSTXZ`abdefgmrsu]"
_MODE = r"\x1b\[(?:\?[0-9;]+|[0-9;]*)[hl]"
_OTHER = r"\x1b\[!p|\x1b\[[0-9;]* q|\x1b[78=>MDEHc]|\x1b[()][B0]"
_TITLE = r"\x1b\][02];[^\x00-\x1f\x7f-\x9f]*\x07"
GRAMMAR = re.compile(rf"(?:{_TEXT}|{_CSI}|{_MODE}|{_OTHER}|{_TITLE})*", re.DOTALL)
# The alphabet of an attacker: what opens and closes sequences, in every form, and some filler.
PIECES = [
    b"\x1b", b"\x1b[", b"\x1b]", b"\x1bP", b"\x1b_", b"\x1b^", b"\x1bX", b"\x1b\\", b"\x07",
    b"\x18", b"\x1a", b"\x05", b"\x9b", b"\x9d", b"\x9c", b"\x90", "\u009b".encode(),
    "\u009d".encode(),
    "\u009c".encode(), "\u0090".encode(), b"\xc2", b"\xe2", b"\xe2\x94", b"\xf0\x9f", b"\xc0",
    b"52;c;ZXZpbA==", b"8;;http://x/", b"0;", b"2;", b"?", b"6n", b"c", b"21t", b"m", b"h", b"l",
    b"1049", b"$p", b" ", b"!", b"(", b")", b"%", b"#", b"1", b";", b":", b"a", "é─".encode(),
    b"\n",
]  # fmt: skip


def test_whatever_comes_in_only_the_allowed_grammar_comes_out() -> None:
    """The output is canonical: every sequence in it was rebuilt by the filter, so the terminal
    and the filter cannot read it differently. A cut anywhere changes nothing."""
    rng = random.Random(0x7265)  # noqa: S311 (seeded on purpose: the same run every time)
    for _ in range(2000):
        data = b"".join(rng.choice(PIECES) for _ in range(rng.randrange(1, 40)))
        whole = filtered(data)
        text = whole.decode()  # always valid UTF-8
        assert GRAMMAR.fullmatch(text), (data, whole)
        relay = TerminalFilter()
        cuts = sorted(rng.randrange(len(data) + 1) for _ in range(rng.randrange(0, 6)))
        pieces = [data[a:b] for a, b in zip([0, *cuts], [*cuts, len(data)], strict=True)]
        assert b"".join(relay.feed(p) for p in pieces) + relay.finish() == whole, (data, cuts)


# --- the pump, on real pseudo-terminals ---------------------------------------------------------

# In the place of the docker CLI: raw on its terminal, as docker sets it, says what it gets.
PROGRAM = textwrap.dedent(
    r"""
    import os, signal, sys, termios, tty
    tty.setraw(0)
    def size(*_):
        cols, rows = os.get_terminal_size(1)
        os.write(1, f"size={rows}x{cols}\r\n".encode())
    signal.signal(signal.SIGWINCH, size)
    os.write(1, f"pid={os.getpid()} ctty=".encode())
    try:
        os.close(os.open("/dev/tty", os.O_RDONLY))
        os.write(1, b"yes\r\n")
    except OSError:
        os.write(1, b"no\r\n")
    size()
    os.write(2, b"e\x1b]52;c;ZXZpbA==\x07f\r\n")
    os.write(1, b"a\x1b]52;c;ZXZpbA==\x07b\x1b[31mc\x1b[6nd\x1b]0;tit\x01ulo\x07listo\r\n")
    while True:
        try:
            got = os.read(0, 65536)
        except InterruptedError:
            continue
        if not got or b"\x1d" in got:
            os._exit(137)
        os.write(1, b"got=" + got.hex().encode() + b"\r\n")
    """
)
# The relay in a process of its own, as `backtide entrar` runs it, on the owner's terminal.
RELAY = textwrap.dedent(
    r"""
    import sys
    from backtide.service.terminal_relay import relay_terminal
    code = relay_terminal(sys.argv[1:], 0, 1)
    sys.stdout.write(f"\r\nrelay-code={code}\r\n")
    """
)


class Owner:
    """The owner's terminal: the leader side of a pseudo-terminal with a program on the other."""

    def __init__(
        self, argv: list[str], *, rows: int = 40, cols: int = 140, stdin: int | None = None
    ) -> None:
        self.leader, follower = os.openpty()
        fcntl.ioctl(follower, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.output = bytearray()
        env = {**os.environ, "PYTHONPATH": str(REPO)}
        self.process = subprocess.Popen(
            argv,
            stdin=follower if stdin is None else stdin,
            stdout=follower,
            stderr=follower,
            start_new_session=True,
            # This terminal is its controlling one, as a person's shell has it: closing it hangs
            # up, a new size signals, and only a session of its own keeps the program out of it.
            preexec_fn=lambda: fcntl.ioctl(1, termios.TIOCSCTTY, 0),
            env=env,
        )
        self.follower = follower

    def read_until(self, wanted: bytes | Callable[[], bool], timeout: float = 20.0) -> None:
        done = wanted if callable(wanted) else lambda: wanted in self.output
        deadline = time.monotonic() + timeout
        while not done():
            left = deadline - time.monotonic()
            assert left > 0, f"{wanted!r} never came; so far: {bytes(self.output)!r}"
            ready, _, _ = select.select([self.leader], [], [], left)
            if ready:
                try:
                    chunk = os.read(self.leader, 65536)
                except OSError:
                    chunk = b""
                assert chunk, f"closed before {wanted!r}; so far: {bytes(self.output)!r}"
                self.output += chunk

    def typed_back(self) -> bytes:
        """What the program says it got, whole lines only: its read may come in pieces."""
        return bytes.fromhex(b"".join(re.findall(rb"got=([0-9a-f]+)\r\n", self.output)).decode())

    def type(self, data: bytes) -> None:
        os.write(self.leader, data)

    def pid_of_program(self) -> int:
        self.read_until(b" ctty=")
        found = re.search(rb"pid=(\d+) ctty=", self.output)
        assert found
        return int(found.group(1))

    def close(self) -> None:
        """Hang up first: macOS keeps a dying session leader until its terminal's output is read."""
        if self.process.poll() is None:
            self.process.kill()
        for fd in (self.leader, self.follower):
            if fd >= 0:
                os.close(fd)
        self.process.wait(timeout=30)


def is_gone(pid: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def owner():
    owned = Owner([sys.executable, "-c", RELAY, sys.executable, "-c", PROGRAM])
    yield owned
    owned.close()


def test_what_the_program_prints_is_filtered_on_its_way_to_the_owner(owner: Owner) -> None:
    owner.read_until(b"listo")
    assert b"ab\x1b[31mcd\x1b]0;titulo\x07listo" in owner.output
    assert b"ef\r\n" in owner.output  # stderr goes through the same terminal
    assert b"]52" not in owner.output and b"\x1b[6n" not in owner.output


def test_the_program_runs_on_a_terminal_that_is_not_the_owners(owner: Owner) -> None:
    owner.read_until(b"listo")
    assert b"ctty=no" in owner.output  # in its own session: it cannot open the owner's /dev/tty
    assert b"size=40x140" in owner.output  # with the owner's size from the start


def test_keys_go_through_untouched_on_a_raw_terminal(owner: Owner) -> None:
    owner.read_until(b"listo")
    assert not termios.tcgetattr(owner.follower)[3] & (termios.ICANON | termios.ECHO | termios.ISIG)
    keys = b"h\r\x03\x04\x1a\x1b[A\x7f\xc3\xa1"  # Ctrl-C and Ctrl-D are the agent's business
    owner.type(keys)
    owner.read_until(lambda: owner.typed_back() == keys)


def test_the_exit_code_of_the_program_comes_back(owner: Owner) -> None:
    owner.read_until(b"listo")
    owner.type(b"\x1d")
    owner.read_until(b"relay-code=137")
    assert owner.process.wait(timeout=20) == 0


def test_a_new_window_size_reaches_the_program(owner: Owner) -> None:
    owner.read_until(b"listo")
    fcntl.ioctl(owner.follower, termios.TIOCSWINSZ, struct.pack("HHHH", 25, 90, 0, 0))
    owner.process.send_signal(signal.SIGWINCH)
    owner.read_until(b"size=25x90")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGHUP])
def test_a_signal_ends_the_program_and_the_relay_returns(owner: Owner, signum: int) -> None:
    """The relay holds the owner's terminal raw: it must get to `finally`, not just die."""
    pid = owner.pid_of_program()
    owner.read_until(b"listo")
    owner.process.send_signal(signum)
    owner.read_until(b"relay-code=")
    assert owner.process.wait(timeout=20) == 0
    assert is_gone(pid)


def test_a_terminal_that_goes_away_ends_the_program(owner: Owner) -> None:
    pid = owner.pid_of_program()
    owner.read_until(b"listo")
    os.close(owner.follower)
    owner.follower = -1
    os.close(owner.leader)
    owner.leader = -1
    owner.process.wait(timeout=20)
    assert is_gone(pid)


ECHO = textwrap.dedent(
    r"""
    import os, tty
    tty.setraw(0)
    os.write(1, b"listo")
    while True:
        got = os.read(0, 65536)
        if b"\x1d" in got:
            os._exit(0)
        os.write(1, got)
    """
)


def test_a_big_paste_and_a_big_output_at_once_do_not_block_each_other() -> None:
    """The program blocks writing until its output is read, while the relay still has input for
    it: the relay reads both ways at once, with what it holds bounded."""
    owner = Owner([sys.executable, "-c", RELAY, sys.executable, "-c", ECHO])
    try:
        owner.read_until(b"listo")
        total = 1024 * 1024
        piece = b"x" * 3000 + b"\r"  # raw on both sides: nothing waits for a whole line
        os.set_blocking(owner.leader, False)
        sent = 0
        received = 0
        deadline = time.monotonic() + 60
        while received < total and time.monotonic() < deadline:
            writers = [owner.leader] if sent < total else []
            ready, writable, _ = select.select([owner.leader], writers, [], 5)
            if writable:
                sent += os.write(owner.leader, piece[: min(len(piece), total - sent)])
            if ready:
                received += len(os.read(owner.leader, 65536))
        assert received == total
        os.set_blocking(owner.leader, True)
        owner.type(b"\x1d")
        owner.read_until(b"relay-code=0")
        assert owner.process.wait(timeout=20) == 0
    finally:
        owner.close()


# --- without a terminal, and through `entrar` -----------------------------------------------------

SAYS = (
    "import os,sys;"
    r"os.write(1,b'a\x1b]52;c;ZXZpbA==\x07b\x1b[6n');"
    r"os.write(2,b'c\x1bPq\x1b\\d\n');"
    "sys.exit(7)"
)


def run_on_pipes(code: str) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


def test_without_a_terminal_the_output_is_filtered_too() -> None:
    """`docker exec -i`, no terminal in the middle: what it prints (stderr with it) goes through
    the same filter, so `backtide entrar < archivo` on a terminal is not a way around it."""
    done = run_on_pipes(
        "import sys;"
        "from backtide.service.terminal_relay import relay_pipes;"
        f"sys.exit(relay_pipes([sys.executable, '-c', {SAYS!r}], 1))"
    )
    assert done.returncode == 7
    assert done.stdout == b"abcd\n"


def test_without_a_terminal_a_reader_that_goes_away_ends_the_program(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    program = (
        f"import os,time;open({str(pid_file)!r},'w').write(str(os.getpid()));"
        "[(os.write(1,b'x'*65536),time.sleep(0.01)) for _ in range(100000)]"
    )
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    code = (
        "import sys;"
        "from backtide.service.terminal_relay import relay_pipes;"
        f"relay_pipes([sys.executable, '-c', {program!r}], 1)"
    )
    relay = subprocess.Popen(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
    )
    assert relay.stdout is not None and relay.stderr is not None
    relay.stdout.read(1024)
    relay.stdout.close()
    assert relay.wait(timeout=30) != 0
    relay.stderr.close()
    assert is_gone(int(pid_file.read_text()))


@pytest.fixture
def config(tmp_path: Path) -> ServiceConfig:
    return ServiceConfig.from_file(write_config(tmp_path))


def fake_docker(tmp_path: Path, code: str) -> Path:
    path = tmp_path / "docker"
    path.write_text(f"#!{sys.executable}\n{code}\n")
    path.chmod(0o755)
    return path


def test_entrar_goes_through_the_relay_by_default(
    config: ServiceConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """The default session of `entrar`: nothing of what docker prints gets out unfiltered."""
    monkeypatch.setattr(shell_cli, "ask_shell", lambda *a, **k: dict(READY))
    monkeypatch.setattr(docker, "PROGRAM", str(fake_docker(tmp_path, SAYS)))
    monkeypatch.setattr(
        docker, "run", lambda args, **k: subprocess.CompletedProcess(args, 0, "", "")
    )
    assert shell_cli.entrar(config) == shell_cli.EXIT_FAILED  # the fake docker exits with 7
    out = capfd.readouterr().out
    assert "ab" in out and "cd" in out
    assert "\x1b" not in out.replace(shell_cli.TERMINAL_RESET, "")


CLI_ON_A_TERMINAL = textwrap.dedent(
    r"""
    import sys
    from backtide import shell_cli
    shell_cli.docker.PROGRAM = sys.argv[1]
    code = shell_cli._interactive(["exec", "--interactive", "--tty", "x"])
    sys.stdout.write(f"\r\nrelay-code={code}\r\n")
    """
)


def test_the_session_on_a_terminal_goes_through_the_relay_too(tmp_path: Path) -> None:
    program = fake_docker(tmp_path, PROGRAM)
    owner = Owner([sys.executable, "-c", CLI_ON_A_TERMINAL, str(program)])
    try:
        owner.read_until(b"listo")
        assert b"]52" not in owner.output and b"ab\x1b[31mcd" in owner.output
        owner.type(b"\x1d")
        owner.read_until(b"relay-code=137")
    finally:
        owner.close()


# `backtide entrar`, whole, in a process of its own: only the service and the seed are fakes.
ENTRAR = textwrap.dedent(
    r"""
    import subprocess, sys
    from backtide import shell_cli
    from backtide.service.config import ServiceConfig
    reply = {
        "ok": True, "outcome": "ready", "message": "", "container": "c",
        "container_id": "ab12" * 16, "user": "61000:61000", "workdir": "/workspace/work",
    }
    shell_cli.ask_shell = lambda *a, **k: reply
    shell_cli.docker.PROGRAM = sys.argv[2]
    shell_cli.docker.run = lambda args, **k: subprocess.CompletedProcess(args, 0, "", "")
    code = shell_cli.entrar(ServiceConfig.from_file(sys.argv[1]))
    print(f"entrar-code={code}", flush=True)
    """
)
MODES_AND_CLIPBOARD = (
    "import os, sys, tty;"
    "os.isatty(0) and tty.setraw(0);"
    r"os.write(1, b'\x1b[?1000h\x1b[?25l\x1b]52;c;ZXZpbA==\x07listo\r\n')"
)


def test_entrar_on_a_terminal_leaves_it_as_it_was(tmp_path: Path) -> None:
    """The relay puts the terminal in raw mode: the guard, saved before it, has to bring it back."""
    program = fake_docker(tmp_path, MODES_AND_CLIPBOARD)
    argv = [sys.executable, "-c", ENTRAR, str(write_config(tmp_path)), str(program)]
    owner = Owner(argv)
    try:
        owner.read_until(b"entrar-code=0")
        after = termios.tcgetattr(owner.follower)[3]
        assert after & termios.ICANON and after & termios.ECHO and after & termios.ISIG
        assert shell_cli.TERMINAL_RESET.encode() in owner.output
        assert owner.output.rfind(shell_cli.TERMINAL_RESET.encode()) > owner.output.rfind(b"listo")
        assert b"]52" not in owner.output
    finally:
        owner.close()


def test_entrar_with_stdin_elsewhere_still_undoes_what_reached_the_terminal(tmp_path: Path) -> None:
    """`backtide entrar < archivo`: no terminal settings to bring back, but the program's modes
    did reach the terminal on stdout."""
    program = fake_docker(tmp_path, MODES_AND_CLIPBOARD)
    argv = [sys.executable, "-c", ENTRAR, str(write_config(tmp_path)), str(program)]
    with open(os.devnull, "rb") as nothing:
        owner = Owner(argv, stdin=nothing.fileno())
    try:
        owner.read_until(b"entrar-code=0")
        assert b"\x1b[?1000h" in owner.output and b"]52" not in owner.output
        assert owner.output.rfind(shell_cli.TERMINAL_RESET.encode()) > owner.output.rfind(b"listo")
    finally:
        owner.close()


def test_a_missing_docker_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(docker, "PROGRAM", str(tmp_path / "no-esta"))
    assert shell_cli._interactive(["exec", "x"]) == 127
    assert "no-esta" in capfd.readouterr().err


def test_a_failure_in_the_relay_ends_the_program_and_says_so(tmp_path: Path) -> None:
    """Writing to a closed stdout: the relay fails, stops the program, and the CLI reports it
    instead of leaving the session running unseen."""
    code = textwrap.dedent(
        """
        import os, sys
        from backtide import shell_cli
        shell_cli.docker.PROGRAM = sys.executable
        script = "import os,time;print(os.getpid(),file=open(os.environ['PIDS'],'w'),flush=True);"
        script += "[(os.write(1,b'x'),time.sleep(0.01)) for _ in range(100000)]"
        stdout = os.dup(1)
        rd, wr = os.pipe()
        os.dup2(wr, 1)
        os.close(rd)
        code = shell_cli._interactive(["-c", script])
        os.write(stdout, str(code).encode())
        """
    )
    pids = tmp_path / "pid"
    env = {**os.environ, "PYTHONPATH": str(REPO), "PIDS": str(pids)}
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env, timeout=60)
    assert done.stdout == b"127", done.stderr
    assert b"ERROR" in done.stderr
    assert is_gone(int(pids.read_text()))
