"""`backtide agentes`: which agents there are, from the terminal, through the running service.

Design: docs/47-diseno-t26-web-agentes.md, section 8. The CLI reads the config and calls these; what
is done, and everything checked, is the service's (``backtide.service.fleet``): this says it. With
no service there is nobody to do it: creating an agent needs its mounts, its black box and its
watch, all of which are the service's.

Exit codes: 0 done; 1 not done (refused, or no service); 2 usage or an order outside its shape; 3
cannot tell whether it was done.
"""

import sys
from typing import Any, TextIO

from backtide.blackbox import redact
from backtide.service.config import ServiceConfig
from backtide.service.control import (
    ControlError,
    ControlOutcomeUnknown,
    ControlUnavailable,
    ask_agent_order,
    ask_agents,
    ask_deleted,
)
from backtide.service.roster import STOPPED_BY_OWNER

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_PROBLEM = 3

NO_SERVICE = (
    "no hay un `backtide vigilar` en marcha: es el servicio quien crea, arranca y para a los "
    "agentes, y quien lo apunta en la caja negra. Arráncalo y vuelve a probar."
)
RESTART_HINT = "Si te va bien, repítelo con --reiniciar."


def order(
    config: ServiceConfig,
    request: dict[str, Any],
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """One order, as the service answers it. Returns the exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    try:
        reply = ask_agent_order(config.control_socket, request)
    except ControlUnavailable:
        print(f"backtide: {NO_SERVICE}", file=err)
        return EXIT_FAILED
    except ControlOutcomeUnknown as error:
        print(f"backtide: {_text(str(error))}", file=err)
        return EXIT_PROBLEM
    except ControlError as error:
        print(f"backtide: {_text(str(error))}", file=err)
        return EXIT_ERROR
    message = _text(reply["message"])
    if reply["ok"]:
        print(message, file=out)
        return EXIT_OK
    print(f"backtide: {message}", file=err)
    if reply["outcome"] == "needs_restart":
        print(RESTART_HINT, file=err)
    return EXIT_ERROR if reply["outcome"] == "invalid" else EXIT_FAILED


def listing(config: ServiceConfig, *, out: TextIO | None = None, err: TextIO | None = None) -> int:
    """`backtide agentes lista`. Returns the exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    try:
        agents = ask_agents(config.control_socket)
        deleted = ask_deleted(config.control_socket)
    except ControlUnavailable:
        print(f"backtide: {NO_SERVICE}", file=err)
        return EXIT_FAILED
    except ControlError as error:
        print(f"backtide: {_text(str(error))}", file=err)
        return EXIT_ERROR
    for agent in agents:
        print(_line(agent), file=out)
    for agent in deleted:
        print(_deleted_line(agent), file=out)
    return EXIT_OK


def _line(agent: dict[str, Any]) -> str:
    name = f" («{_text(agent['name'])}»)" if agent["name"] else ""
    if agent["state"] == STOPPED_BY_OWNER:
        state = "parado por ti"
    elif agent["watched"]:
        state = _text(agent["state"] or "vigilado")
    else:
        state = "sin vigilar: no ha arrancado o ha fallado"
    return f"{agent['slug']}{name}: {state}"


def _deleted_line(agent: dict[str, Any]) -> str:
    slug = agent["slug"]
    if agent["purged"]:
        return f"{slug}: borrado y vaciado; queda su caja negra"
    if agent["state"] != "retired":
        return f"{slug}: a medio borrar; repite `backtide agentes borrar {slug}`"
    day = _text(agent["purge_after"])[:10]
    return f"{slug}: en la papelera hasta el {day}; `backtide agentes recuperar {slug}` lo devuelve"


def _text(text: str) -> str:
    """Redacted, and nothing that moves a terminal around."""
    return "".join(c if c.isprintable() else "?" for c in str(redact(text)))
