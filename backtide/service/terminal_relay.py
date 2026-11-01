"""The terminal relay (T26-5c, docs/47 section 7.2): nothing the agent prints reaches the owner's
terminal without going through here.

A terminal also obeys what it is told to print: an agent could write to the owner's clipboard
(OSC 52), make links (OSC 8), or ask the terminal a question whose answer arrives as if the owner
had typed it. So between the agent and the owner's terminal there is a pseudo-terminal of ours
(a "pty": two ends of a fake terminal, the program on one, us on the other), and each byte goes
through ``TerminalFilter``.

The filter keeps a list of what may pass and drops the rest, rather than a list of what to drop:

- Text, as valid UTF-8 (each bad byte becomes U+FFFD), and the C0 controls that only move the
  cursor or ring the bell (ENQ, the answerback, is not among them).
- CSI (``ESC [``) that moves the cursor, erases, scrolls, sets colours and styles (SGR), and the
  modes a full-screen program needs (the list below): what the end of the session undoes
  (``shell_cli.TERMINAL_RESET``). No CSI that asks for a report, no window operation (CSI t), no
  printing, no keyboard protocol.
- OSC 0 and 2, the window title, with its control characters taken out.
- A few two-byte escapes (save the cursor, the keypad, a reset, the line-drawing characters).

Everything else goes: every other OSC, DCS, APC, PM and SOS whole, and the 8-bit forms of all of
them (U+0080-U+009F, which some terminals obey). What is emitted is rebuilt from what was
understood, never copied, so the terminal cannot read a sequence differently from the filter: a
sequence is only written once it is complete and checked.

One known limit: on a terminal that is NOT in UTF-8 and honours 8-bit controls, a valid character
such as U+2FDD ends in the byte 0x9D. Modern terminals are in UTF-8; docs/guide says so.

Today's owner is `backtide entrar` (``relay_terminal``, ``relay_pipes``), in the CLI's own
process. The filter takes bytes and gives bytes, so the service can use it as it is for the
browser's terminal (T26-5d). The owner's keys are passed untouched and never kept.
"""

import codecs
import contextlib
import fcntl
import os
import re
import select
import signal
import subprocess
import termios
import tty
from collections.abc import Sequence
from enum import Enum, auto
from types import FrameType

MAX_SEQUENCE = 512  # characters of one CSI or one title; longer ones are dropped whole
CHUNK = 64 * 1024  # bytes read at once from either side (docs/47 section 7.3)
MAX_PENDING = 256 * 1024  # bytes held for a side that is not reading, before we stop reading more
OWNER_WRITE = 4096  # bytes written to the owner per turn, so input is not left waiting
STOP_TIMEOUT = 10.0

_ESC = "\x1b"
_CAN_SUB = "\x18\x1a"
_BEL = "\x07"
_ST = "\x9c"
_C1_FIRST, _C1_LAST = 0x80, 0x9F
# BEL, BS, HT, LF, VT, FF, CR, SO and SI (ncurses' sgr0 uses SI on some terminals).
_ALLOWED_C0 = frozenset("\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
_PLAIN = re.compile(r"[^\x00-\x1f\x7f-\x9f]+")
_CSI_BODY = re.compile(r"([<=>?]?)([0-9;:]*)([ -/]*)", re.ASCII)
# Cursor, erase, insert and delete, scroll, tabs, repeat, colours, margins, save and restore.
_CSI_FINALS = frozenset("@ABCDEFGHIJKLMPSTXZ`abdefgmrs")
# Insert. Never 2 (locks the keyboard), 12 (echo) or 20 (Enter would send CR LF: the LF stays queued
# after the session, and the next program that asks takes it as the owner's answer).
_MODES = frozenset({"4"})
# Keypad, origin, wrap, mouse, cursor, the alternate screen, focus, bracketed paste, synchronized
# output. Never 2031 (reports the colour scheme) nor any mode we do not know.
_PRIVATE_MODES = frozenset(
    {
        "1", "6", "7", "9", "12", "25", "47", "1000", "1002", "1003", "1004", "1005", "1006",
        "1015", "1016", "1047", "1048", "1049", "2004", "2026",
    }
)  # fmt: skip
_ESC_FINALS = frozenset("78=>MDEHc")  # never Z (it asks), N and O (shifts), n and o (locks)
_CHARSETS = frozenset({"(B", "(0", ")B", ")0"})  # never % (it can leave UTF-8)
_DROPPED_STRINGS = frozenset("PX^_")  # DCS, SOS, PM, APC


class _State(Enum):
    GROUND = auto()
    ESCAPE = auto()  # after ESC
    ESCAPE_MORE = auto()  # after ESC and an intermediate: ESC ( B
    CSI = auto()
    TITLE = auto()  # an OSC: only 0 and 2 are ever written
    DROPPED = auto()  # DCS, SOS, PM, APC
    STRING_ESCAPE = auto()  # ESC inside TITLE or DROPPED: the end, or the start of something else


def _csi_allowed(body: str, final: str) -> bool:
    match = _CSI_BODY.fullmatch(body)
    if match is None:
        return False
    prefix, params, more = match.groups()
    if prefix == "?":
        return final in "hl" and not more and set(params.split(";")) <= _PRIVATE_MODES
    if prefix:
        return False
    if more:
        # A soft reset (DECSTR) and the cursor's shape (DECSCUSR).
        return not params and (more, final) == ("!", "p") or (more, final) == (" ", "q")
    if ":" in params and final != "m":
        return False
    if final in "hl":
        return set(params.split(";")) <= _MODES
    if final == "u":  # restore the cursor; with anything else it is the keyboard protocol
        return not params
    return final in _CSI_FINALS


def _clean_title(body: str) -> str | None:
    """The sequence for an OSC body, or None when it is anything but a title that sets."""
    number, separator, title = body.partition(";")
    if number not in ("0", "2") or not separator:
        return None
    clean = "".join(c for c in title if c.isprintable())
    return None if clean == "?" else f"{_ESC}]{number};{clean}{_BEL}"  # "?": some terminals answer


class TerminalFilter:
    """What the agent prints, in pieces; what the owner's terminal may see. Reads may cut a
    sequence or a character anywhere: what is left waits for the next ``feed``, and what is held
    never passes MAX_SEQUENCE characters."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._state = _State.GROUND
        self._held = ""  # the sequence being read
        self._overflowed = False
        self._in_title = False  # what STRING_ESCAPE came from

    def feed(self, data: bytes) -> bytes:
        return self._filter(self._decoder.decode(data))

    def finish(self) -> bytes:
        """The end of the output: half a character becomes U+FFFD, half a sequence goes."""
        out = self._filter(self._decoder.decode(b"", final=True))
        self._to_ground()
        return out

    def buffered(self) -> int:
        """How many characters of an unfinished sequence are held."""
        return len(self._held)

    def _filter(self, text: str) -> bytes:
        out: list[str] = []
        position, end = 0, len(text)
        while position < end:
            if self._state is _State.GROUND:
                run = _PLAIN.match(text, position)
                if run is not None:
                    out.append(run.group())
                    position = run.end()
                    continue
            self._step(text[position], out)
            position += 1
        return "".join(out).encode()

    def _to_ground(self) -> None:
        self._state = _State.GROUND
        self._held = ""
        self._overflowed = False
        self._in_title = False

    def _hold(self, char: str) -> None:
        if len(self._held) >= MAX_SEQUENCE:
            self._held = ""
            self._overflowed = True
        elif not self._overflowed:
            self._held += char

    def _start_string(self, state: _State) -> None:
        self._to_ground()
        self._state = state
        self._in_title = state is _State.TITLE

    def _end_string(self, out: list[str]) -> None:
        if self._in_title and not self._overflowed:
            sequence = _clean_title(self._held)
            if sequence is not None:
                out.append(sequence)
        self._to_ground()

    def _introduce(self, final: str, out: list[str]) -> None:
        """What comes after ESC, or the 7-bit form of a C1."""
        if final == "[":
            self._to_ground()
            self._state = _State.CSI
        elif final == "]":
            self._start_string(_State.TITLE)
        elif final in _DROPPED_STRINGS:
            self._start_string(_State.DROPPED)
        else:
            if final in _ESC_FINALS:
                out.append(_ESC + final)
            self._to_ground()

    def _step(self, char: str, out: list[str]) -> None:
        code = ord(char)
        if char in _CAN_SUB:
            self._to_ground()
        elif char == _ESC:
            in_string = self._state in (_State.TITLE, _State.DROPPED)
            if in_string:
                self._state = _State.STRING_ESCAPE
            else:
                self._to_ground()
                self._state = _State.ESCAPE
        elif _C1_FIRST <= code <= _C1_LAST:
            if char == _ST:
                if self._state in (_State.TITLE, _State.DROPPED, _State.STRING_ESCAPE):
                    self._end_string(out)
                else:
                    self._to_ground()
            else:
                self._to_ground()
                self._introduce(chr(code - 0x40), [])  # the C1 alone writes nothing
        else:
            self._by_state(char, code, out)

    def _by_state(self, char: str, code: int, out: list[str]) -> None:
        state = self._state
        if state is _State.GROUND:
            if char in _ALLOWED_C0:
                out.append(char)
        elif state is _State.TITLE:
            if char == _BEL:
                self._end_string(out)
            else:
                self._hold(char)
        elif state is _State.DROPPED:
            pass
        elif state is _State.STRING_ESCAPE:
            if char == "\\":
                self._end_string(out)
            else:  # the string was cut: it is lost, and this goes on as what follows an ESC
                self._to_ground()
                self._state = _State.ESCAPE
                self._after_escape(char, code, out)
        elif state is _State.ESCAPE:
            self._after_escape(char, code, out)
        elif state is _State.ESCAPE_MORE:
            self._after_intermediate(char, code, out)
        else:
            self._in_csi(char, code, out)

    def _text_ends_it(self, char: str, code: int, out: list[str]) -> bool:
        """A control inside a sequence is dropped and the sequence goes on; text ends the
        sequence and is written. True when ``char`` was one of the two: nothing else to do."""
        if code < 0x20 or code == 0x7F:
            return True
        if code > 0x7F:
            self._to_ground()
            out.append(char)
            return True
        return False

    def _after_escape(self, char: str, code: int, out: list[str]) -> None:
        if self._text_ends_it(char, code, out):
            return
        if 0x20 <= code <= 0x2F:
            self._held = char
            self._state = _State.ESCAPE_MORE
        else:
            self._introduce(char, out)

    def _after_intermediate(self, char: str, code: int, out: list[str]) -> None:
        if self._text_ends_it(char, code, out):
            return
        if 0x20 <= code <= 0x2F:
            self._hold(char)
        else:
            if self._held + char in _CHARSETS:
                out.append(_ESC + self._held + char)
            self._to_ground()

    def _in_csi(self, char: str, code: int, out: list[str]) -> None:
        if self._text_ends_it(char, code, out):
            return
        if 0x20 <= code <= 0x3F:
            self._hold(char)
        else:
            if not self._overflowed and _csi_allowed(self._held, char):
                out.append(f"{_ESC}[{self._held}{char}")
            self._to_ground()


# -- the pump ------------------------------------------------------------------------------------


def _write_all(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data) :]


def _finish(process: subprocess.Popen[bytes], *, stop: bool) -> None:
    """Wait for the program; ``stop`` first asks it to end. The docker CLI never stays running
    behind us; what it started inside the container may, jailed and recorded like the rest."""
    if stop and process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _copy_size(source: int, target: int) -> None:
    """The window's size, from the owner's terminal to ours. A terminal that does not say (or is
    gone: the pump finds out right away) keeps the size it had."""
    with contextlib.suppress(OSError):
        size = fcntl.ioctl(source, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(target, termios.TIOCSWINSZ, size)


def relay_terminal(argv: Sequence[str], stdin_fd: int, stdout_fd: int) -> int:
    """``argv`` (the docker CLI with ``-it``) on a pty of its own and in a session of its own, so
    it never holds the owner's terminal, with what it prints filtered on its way to ``stdout_fd``
    and the keys of ``stdin_fd`` passed as they are. Puts the owner's terminal in raw mode: the
    caller puts it back (``shell_cli.terminal_guard``). Returns the program's exit code, also
    when the owner's terminal goes away or a SIGTERM or SIGHUP arrives (the program is stopped).
    Only from the main thread, for the signals."""
    wake_read, wake_write = os.pipe()
    leader = -1
    process: subprocess.Popen[bytes] | None = None
    signals: set[int] = set()

    def on_signal(signum: int, _frame: FrameType | None) -> None:
        signals.add(signum)
        with contextlib.suppress(BlockingIOError):  # the pipe is full: it will wake up anyway
            os.write(wake_write, b"\0")

    os.set_blocking(wake_write, False)
    os.set_blocking(wake_read, False)
    previous = {
        signum: signal.signal(signum, on_signal)
        for signum in (signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP)
    }
    stop = True
    try:
        leader, follower = os.openpty()
        try:
            _copy_size(stdout_fd, follower)
            process = subprocess.Popen(
                list(argv),
                stdin=follower,
                stdout=follower,
                stderr=follower,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            os.close(follower)
        os.set_blocking(leader, False)
        tty.setraw(stdin_fd, termios.TCSANOW)
        stop = _pump(leader, stdin_fd, stdout_fd, wake_read, signals, process)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if leader >= 0:
            os.close(leader)
        os.close(wake_read)
        os.close(wake_write)
        if process is not None:
            _finish(process, stop=stop)
    return process.returncode


def _pump(
    leader: int,
    stdin_fd: int,
    stdout_fd: int,
    wake: int,
    signals: set[int],
    process: subprocess.Popen[bytes],
) -> bool:
    """Bytes both ways until the program closes its terminal (returns False: it ended by itself)
    or the owner goes away or a signal asks to stop (returns True). Each side holds at most
    MAX_PENDING for the other, and neither direction waits for the other, so a big paste with a
    big output at once cannot block both. An error writing to the owner is raised."""
    relay = TerminalFilter()
    to_program = bytearray()
    to_owner = bytearray()
    while True:
        readers = [wake]
        if len(to_program) < MAX_PENDING:
            readers.append(stdin_fd)
        if len(to_owner) < MAX_PENDING:
            readers.append(leader)
        writers = []
        if to_program:
            writers.append(leader)
        if to_owner:
            writers.append(stdout_fd)
        readable, writable, _ = select.select(readers, writers, [])
        if wake in readable:
            os.read(wake, CHUNK)
            if signals & {signal.SIGTERM, signal.SIGHUP}:
                return True
            if signal.SIGWINCH in signals:
                signals.discard(signal.SIGWINCH)
                _copy_size(stdout_fd, leader)
                process.send_signal(signal.SIGWINCH)  # no controlling terminal: docker asks for it
        if stdout_fd in writable:
            sent = os.write(stdout_fd, to_owner[:OWNER_WRITE])
            del to_owner[:sent]
        if leader in writable:
            try:
                sent = os.write(leader, to_program[:CHUNK])
            except BlockingIOError:
                sent = 0
            except OSError:  # the program closed its terminal: the read below says so
                to_program.clear()
                sent = 0
            del to_program[:sent]
        if stdin_fd in readable:
            try:
                keys = os.read(stdin_fd, CHUNK)
            except OSError:  # the owner's terminal hung up
                keys = b""
            if not keys:
                return True
            to_program += keys
        if leader in readable:
            try:
                printed = os.read(leader, CHUNK)
            except BlockingIOError:
                continue
            except OSError:  # Linux: nobody has the other end any more (macOS: an empty read)
                printed = b""
            if not printed:
                _write_all(stdout_fd, bytes(to_owner) + relay.finish())
                return False
            to_owner += relay.feed(printed)


def relay_pipes(argv: Sequence[str], stdout_fd: int) -> int:
    """``argv`` (the docker CLI without a terminal: ``-i``) with stdin as it is, and what it
    prints, stderr too, filtered on its way to ``stdout_fd``. Without this, `backtide entrar <
    archivo` on a terminal would be a way around the filter. An error writing there stops the
    program and is raised. Returns the program's exit code."""
    process = subprocess.Popen(
        list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0, close_fds=True
    )
    relay = TerminalFilter()
    stop = True
    try:
        with process.stdout as printed:
            while chunk := printed.read(CHUNK):
                _write_all(stdout_fd, relay.feed(chunk))
            _write_all(stdout_fd, relay.finish())
        stop = False
    finally:
        _finish(process, stop=stop)
    return process.returncode
