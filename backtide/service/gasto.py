"""`backtide gasto` and `backtide tope`: the spending cap (T11) from the terminal, through the
running service.

Design: docs/33-diseno-t11-tope-de-gasto.md. The CLI reads the config and calls these; everything
else is here, so it is tested without the CLI.

- The spending lives in the running service (``Budget``: ``budget.json`` and the black box), and
  so does the right to change a cap, which is recorded there (``settings/budget_set``) before
  anything changes. So both commands ask the service over the control socket (``ask_budget``,
  ``ask_set_budget`` with ``via="cli"``): the very path the web's Settings page uses, with the
  same checks and the same black-box event. With no service there is nobody to count or to
  record, so this says so (exit 1) and lets go of the lock at once.
- The numbers are the ones ``Budget.status`` gives; the sentences are ``status_lines`` (the same
  ones Telegram's ``/estado`` shows). A reply that makes no sense is never shown.
- A cap typed here is checked first with ``check_cap`` (the service checks it again).
- Whatever comes back is printed redacted and with control characters escaped.

Exit codes: 0 done (the spending or the caps shown, or the caps changed); 1 not done (no service,
it cannot count now, the cap was not saved); 2 usage (a cap that does not fit, an unusable lock,
a socket that is not ours, a reply that makes no sense); 3 cannot tell whether it was done.
"""

import sys
from typing import Any, TextIO

from backtide.blackbox import redact
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_budget,
    ask_set_budget,
)
from backtide.service.prices import usd
from backtide.service.runner import ServiceLocked, ServiceRunning, take_lock
from backtide.service.spend import CAP_SHAPE, check_cap, status_lines

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_PROBLEM = 3

NO_SERVICE = (
    "no hay un `backtide vigilar` en marcha: el servicio es quien cuenta el gasto y quien apunta "
    "en la caja negra los cambios de tope. Arráncalo y vuelve a probar."
)
NOT_ANSWERING = (
    "hay un servicio de backtide que tiene el cerrojo, pero no contesta en el socket de control: "
    "está arrancando o se ha quedado a medias. Inténtalo de nuevo en un momento."
)
UNEXPECTED = "La respuesta del servicio no es la esperada."
HOW_TO_CHANGE = "Cámbialos con `backtide tope --dia <dólares> --mes <dólares>`."
MAX_MICRO = 10**15  # far above any cap the service accepts


def spending(config: ServiceConfig, *, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """`backtide gasto`: today's and this month's spending against the caps. Returns the exit
    code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    read = _read(config, err)
    if isinstance(read, int):
        return read
    lines = [_text(line) for line in status_lines(read)]
    if read.get("available") is not True:
        _error(err, lines[0])
        return EXIT_FAILED
    for line in lines:
        print(line, file=out)
    if read.get("blocked"):
        print(HOW_TO_CHANGE, file=out)
    return EXIT_OK


def caps(
    config: ServiceConfig,
    daily: str | None,
    monthly: str | None,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """`backtide tope`: show the caps, or change them (``daily``, ``monthly``: dollars as typed,
    ``None`` leaves that one as it is). Returns the exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    for value in (daily, monthly):
        if value is not None and check_cap(value) is None:
            _error(err, CAP_SHAPE)
            return EXIT_ERROR
    if daily is None and monthly is None:
        return _show_caps(config, out, err)
    refused = _service(config, err)
    if refused is not None:
        return refused
    try:
        reply = ask_set_budget(
            config.control_socket, daily_usd=daily, monthly_usd=monthly, via="cli"
        )
    except ControlUnavailable:
        _error(err, NOT_ANSWERING)
        return EXIT_FAILED
    except ControlOutcomeUnknown as error:  # the request went out: it may have been done
        _error(err, str(error))
        return EXIT_PROBLEM
    except ControlError as error:  # nothing was sent
        _error(err, str(error))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error(
            err,
            "interrumpido: no se sabe si el servicio llegó a cambiar el tope. "
            "Mira `backtide tope`.",
        )
        return EXIT_PROBLEM
    text = _text(reply["message"])
    if reply["ok"]:
        print(text, file=out)
        return EXIT_OK
    _error(err, text)
    return EXIT_ERROR if reply["outcome"] in ("invalid", "refused") else EXIT_FAILED


def _show_caps(config: ServiceConfig, out: TextIO, err: TextIO) -> int:
    read = _read(config, err)
    if isinstance(read, int):
        return read
    if read.get("available") is not True:
        _error(err, _text(status_lines(read)[0]))
        return EXIT_FAILED
    print(f"Tope diario: {_dollars(read['day']['cap_micro'])} $", file=out)
    print(f"Tope mensual: {_dollars(read['month']['cap_micro'])} $", file=out)
    print(HOW_TO_CHANGE, file=out)
    return EXIT_OK


def _read(config: ServiceConfig, err: TextIO) -> dict[str, Any] | int:
    """What the service says of the spending, checked; or the exit code if it cannot be had."""
    refused = _service(config, err)
    if refused is not None:
        return refused
    try:
        read = ask_budget(config.control_socket)
    except ControlUnavailable:
        _error(err, NOT_ANSWERING)
        return EXIT_FAILED
    except ControlError as error:
        _error(err, str(error))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error(err, "interrumpido.")
        return EXIT_PROBLEM
    if not _makes_sense(read):
        _error(err, UNEXPECTED)
        return EXIT_ERROR
    return read


def _makes_sense(read: object) -> bool:
    """The shape ``status_lines`` and ``_show_caps`` rely on, field by field."""
    if not isinstance(read, dict):
        return False
    if read.get("available") is not True:
        return read.get("available") is False
    try:
        amounts = [read[w][k] for w in ("day", "month") for k in ("spent_micro", "cap_micro")]
        prices = read["prices"]
        defaults_on = prices["defaults_on"]
    except (KeyError, TypeError):
        return False
    if not all(type(a) is int and 0 <= a <= MAX_MICRO for a in amounts):
        return False
    if read.get("blocked") not in (None, "day", "month"):
        return False
    return isinstance(defaults_on, str) and isinstance(prices.get("updated_on", ""), str | None)


def _service(config: ServiceConfig, err: TextIO) -> int | None:
    """None if a service holds the lock (ask it); else the exit code."""
    try:
        lock = take_lock(config.lock_file)
    except ServiceRunning:
        return None
    except ServiceLocked as error:  # the lock file itself is unusable: not "a service"
        _error(err, str(error))
        return EXIT_ERROR
    lock.close()  # nobody owns the agent: let a `backtide vigilar` take it
    _error(err, NO_SERVICE)
    return EXIT_FAILED


def _dollars(micro: int) -> str:
    return usd(micro).replace(".", ",")


def _text(value: object) -> str:
    return _printable(redact(value if isinstance(value, str) else ""))


def _error(err: TextIO, message: str) -> None:
    print(f"ERROR: {_printable(redact(message))}", file=err)


def _printable(text: str) -> str:
    """``text`` with control characters escaped, as `backtide/cli.py` prints everything that comes
    from outside: an escape sequence could rewrite what the terminal shows."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)
