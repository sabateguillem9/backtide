"""The fixed notice of a rewind: what it brings back and what it cannot (docs/19, section 7).

One source for every place that asks a person to confirm a rewind: `vigia rebobinar` today,
Telegram (T09) and the web (T12b) later. The generic part lives here; the lines about the
agent's channels come from its profile (``vigia.jail.openclaw.REWIND_NOTICE_LINES``). Only the
time of the snapshot changes from one notice to another: nothing in it comes from the agent.

The text is a tuple of paragraphs in Spanish, so each place lays them out its own way (the CLI
wraps them at 88 columns, the web gives each one its own paragraph).
"""

from collections.abc import Sequence
from datetime import datetime, timedelta, tzinfo

from vigia.jail.openclaw import REWIND_NOTICE_LINES

TIME_FORMAT = "%H:%M:%S del %Y-%m-%d"

COMES_BACK = (
    "Se deshace: los archivos de trabajo del agente y lo que recuerda (memoria y conversaciones) "
    "desde esa hora. Todo lo que guarda en su carpeta vuelve a como estaba."
)
DOES_NOT_COME_BACK = (
    "No se deshace: lo que el agente ya ha enviado fuera (mensajes, correos, publicaciones, "
    "cambios en servicios); lo que ya salió de la máquina no vuelve. Tampoco cambian la "
    "configuración del agente, las claves que le da Vigía ni quién puede hablar con él (eso está "
    "fuera de su carpeta), ni la caja negra, que sigue grabando. Pero las sesiones que el "
    "agente haya iniciado él mismo en sus herramientas (por ejemplo, `gh` o `claude`) están en "
    "su carpeta: vuelven atrás y puede que haya que iniciarlas de nuevo."
)
AFTERWARDS = (
    "Después, el agente no recordará nada posterior a esa hora aunque tus chats sí lo muestren, "
    "y puede reenviar algún mensaje que estuviera en cola en ese momento."
)
UNDO = "Se guarda un punto para deshacer el rebobinado."


def rewind_notice(
    taken_at: datetime,
    *,
    now: datetime,
    tz: tzinfo,
    agent_lines: Sequence[str] = REWIND_NOTICE_LINES,
) -> tuple[str, ...]:
    """The notice for a rewind to a snapshot taken at ``taken_at`` (aware), as paragraphs:
    when, what comes back, what does not, the agent's own lines, and the undo point."""
    when = (
        f"Vas a volver a las {taken_at.astimezone(tz).strftime(TIME_FORMAT)} "
        f"({ago(now - taken_at)})."
    )
    return (when, COMES_BACK, DOES_NOT_COME_BACK, AFTERWARDS, *agent_lines, UNDO)


def ago(elapsed: timedelta) -> str:
    """How long ago, in words: "hace 10 min", "hace 5 h", "hace 3 días"."""
    seconds = elapsed.total_seconds()
    if seconds < -5:
        return "en el futuro (¿reloj mal?)"
    if seconds < 60:
        return "hace unos segundos"
    if seconds < 3600:
        return f"hace {int(seconds // 60)} min"
    if seconds < 48 * 3600:
        return f"hace {int(seconds // 3600)} h"
    return f"hace {int(seconds // 86400)} días"


__all__ = ["ago", "rewind_notice"]
