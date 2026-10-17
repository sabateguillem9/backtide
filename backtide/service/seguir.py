"""`backtide seguir`: resume the agent after a pause by space, through the running service.

Design: docs/19-diseno-t04.md, sections 4 ("La CLI") and 5 ("Pausar, matar y seguir"). The CLI
reads the config and calls ``seguir``; everything else is here, so it is tested without the CLI.

- The service owns the agent and the pause: if ``backtide.lock`` is held by a live process, the
  request goes over the control socket (``ask_resume``), and the Guardian refuses while any
  condition stands.
- Without a service there is nothing to resume: no agent runs, and the open pause lives in the
  black box. ``backtide vigilar`` reads it back at boot and waits with the agent stopped; then
  ``backtide seguir`` resumes it. So without a service this only says so (exit 1) and lets go of
  the lock at once.
- Whatever comes back is printed redacted and with control characters escaped.

Exit codes: 0 resumed (or nothing to resume); 1 not resumed (a condition stands, another
reason keeps it paused, no service); 2 usage (an unusable lock, a socket that is not ours, a
refused request); 3 cannot tell, or resumed with a problem.
"""

import sys
from typing import TextIO

from backtide.blackbox import redact
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    OUTCOME_EXIT_CODES,
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_resume,
)
from backtide.service.runner import ServiceLocked, ServiceRunning, take_lock

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_PROBLEM = 3

NO_SERVICE = (
    "no hay un `backtide vigilar` en marcha, así que no hay nada que reanudar: arráncalo. Si la "
    "pausa por espacio sigue abierta, el agente se queda parado al arrancar y entonces "
    "`backtide seguir` lo reanuda."
)


def seguir(config: ServiceConfig, *, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """`backtide seguir` with ``config``: ask the running service to resume and say what it did.
    Returns the exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    try:
        lock = take_lock(config.lock_file)
    except ServiceRunning:
        return _through_service(config, out, err)
    except ServiceLocked as error:  # the lock file itself is unusable: not "a service"
        _error(err, str(error))
        return EXIT_ERROR
    lock.close()  # nobody owns the agent: let a `backtide vigilar` take it
    _error(err, NO_SERVICE)
    return EXIT_FAILED


def _through_service(config: ServiceConfig, out: TextIO, err: TextIO) -> int:
    try:
        reply = ask_resume(config.control_socket)
    except ControlUnavailable:
        _error(
            err,
            "hay un servicio de backtide que tiene el cerrojo, pero no contesta en el socket de "
            "control: está arrancando o se ha quedado a medias. Inténtalo de nuevo en un momento.",
        )
        return EXIT_FAILED
    except ControlOutcomeUnknown as error:  # the request went out: it may have been done
        _error(err, str(error))
        return EXIT_PROBLEM
    except ControlError as error:  # nothing was sent
        _error(err, str(error))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error(err, "interrumpido: no se sabe si el servicio llegó a reanudar al agente.")
        return EXIT_PROBLEM
    code = OUTCOME_EXIT_CODES.get(reply["outcome"], EXIT_PROBLEM)
    text = _printable(redact(reply["message"]))
    if code == EXIT_OK:
        print(text, file=out)
    elif code == EXIT_PROBLEM:
        print(f"AVISO: {text}", file=err)
    else:
        _error(err, text)
    return code


def _error(err: TextIO, message: str) -> None:
    print(f"ERROR: {_printable(redact(message))}", file=err)


def _printable(text: str) -> str:
    """``text`` with control characters escaped, as `backtide/cli.py` prints everything that comes
    from outside: an escape sequence could rewrite what the terminal shows."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)
