"""`backtide aprobar`, `backtide rechazar` and `backtide retenidas`: decide on the requests the
gate holds, from the terminal, through the running service (T10-2).

Design: docs/32-diseno-t10-puerta.md, section 11 ("Desde la terminal"). The CLI reads the config
and calls these; everything else is here, so it is tested without the CLI.

- The holds live in the running service's memory (and what happened, in the black box): with
  no service there is nothing held (the proxy refuses everything without its channel), so this
  says so (exit 1) and lets go of the lock at once.
- The request goes over the control socket (``ask_decide``, ``ask_holds``): only the service's
  own user may talk to it, and the agent never sees it, so the agent cannot approve itself.
- Whatever comes back (the agent wrote the paths and hosts) is printed redacted and with control
  characters escaped.

Exit codes: 0 decided (approved, preapproved or rejected; the listing printed); 1 not done (no
such open hold, nothing recorded, no service); 2 usage (an id that is not one, an unusable lock,
a socket that is not ours, a refused request); 3 cannot tell whether it was done.
"""

import sys
from collections.abc import Mapping
from typing import Any, TextIO

from backtide.blackbox import redact
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    HOLD_EXIT_CODES,
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_decide,
    ask_holds,
)
from backtide.service.holds import HOLD_ID_RE
from backtide.service.runner import ServiceLocked, ServiceRunning, take_lock

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_PROBLEM = 3

NO_SERVICE = (
    "no hay un `backtide vigilar` en marcha, así que no hay ninguna petición retenida: sin el "
    "servicio, el proxy no deja salir nada."
)
NOT_ANSWERING = (
    "hay un servicio de backtide que tiene el cerrojo, pero no contesta en el socket de control: "
    "está arrancando o se ha quedado a medias. Inténtalo de nuevo en un momento."
)
NONE_HELD = "No hay ninguna petición retenida esperando."
RISK_NAMES = {0: "riesgo 0", 1: "riesgo 1", 2: "riesgo 2", 3: "riesgo 3"}
MAX_SHOWN = 160  # characters of the request's target shown per line


def decide(
    config: ServiceConfig,
    hold_id: str,
    verdict: str,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """`backtide aprobar` (``verdict="approve"``) or `backtide rechazar` (``"reject"``) of
    ``hold_id``. Returns the exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    if not HOLD_ID_RE.fullmatch(hold_id):
        _error(
            err,
            "eso no es el identificador de una petición retenida (h-… en `backtide retenidas`).",
        )
        return EXIT_ERROR
    status = _service(config, err)
    if status is not None:
        return status
    try:
        reply = ask_decide(config.control_socket, hold_id, verdict)
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
            "interrumpido: no se sabe si el servicio llegó a decidir. Mira `backtide retenidas`.",
        )
        return EXIT_PROBLEM
    code = HOLD_EXIT_CODES.get(reply["outcome"], EXIT_PROBLEM)
    text = _printable(redact(reply["message"]))
    if code == EXIT_OK:
        print(text, file=out)
    else:
        _error(err, text)
    return code


def listing(config: ServiceConfig, *, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """`backtide retenidas`: the held requests waiting for the person, oldest first."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    status = _service(config, err)
    if status is not None:
        return status
    try:
        holds = ask_holds(config.control_socket)
    except ControlUnavailable:
        _error(err, NOT_ANSWERING)
        return EXIT_FAILED
    except ControlError as error:
        _error(err, str(error))
        return EXIT_ERROR
    if not holds:
        print(NONE_HELD, file=out)
        return EXIT_OK
    for hold in holds:
        print(hold_line(hold), file=out)
    print(
        "\nApruébalas con `backtide aprobar <id>` o recházalas con `backtide rechazar <id>`. "
        "Sin respuesta, se rechazan solas a los 5 minutos.",
        file=out,
    )
    return EXIT_OK


def hold_line(hold: Mapping[str, Any]) -> str:
    """One line per hold: its id, its risk, the request (struck, cut, escaped) and its time."""
    risk = RISK_NAMES.get(hold.get("risk"), "riesgo ?")  # type: ignore[arg-type]
    method = _text(hold.get("method"), 16) or "?"
    target = _text(hold.get("target") or hold.get("host"), MAX_SHOWN) or "?"
    seconds = hold.get("expires_in_s")
    left = f"caduca en {seconds // 60} min {seconds % 60:02d} s" if type(seconds) is int else ""
    waiting = "esperando conectada" if hold.get("waiting") is True else "el agente reintentará"
    return f"{hold['hold_id']}  {risk}  {method} {target}  ({left}; {waiting})"


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


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = _printable(redact(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _error(err: TextIO, message: str) -> None:
    print(f"ERROR: {_printable(redact(message))}", file=err)


def _printable(text: str) -> str:
    """``text`` with control characters escaped, as `backtide/cli.py` prints everything that comes
    from outside: an escape sequence could rewrite what the terminal shows."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)
