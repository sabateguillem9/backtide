"""The notice of a refusal toward a local model (T20-5, docs/35 decision 9).

A local provider is a program on the owner's own machine (Ollama on the Mac, or on the tower), so
what the proxy refuses on the way there is worth a notice even at risk 2: the agent tried a
route, a body, a credential or a destination that the exception does not open. Risk 3 (one of
Ollama's administration routes) is not this notice's: the ``RiskResponder`` already tells it,
with its evidence snapshot.

- **The first of each reason at once**, then at most one every ``EVERY`` (10 min) per local
  provider and reason (two providers are counted apart, so a notice names the right one).
- **Nothing counted is lost.** The refusals in between are counted, and one notice with how many
  goes out as soon as the 10 minutes are over (``send_due``, from the channel's tick and the
  proxy's watch) or when the service stops (``flush``). Otherwise one decoy refusal would buy ten
  quiet minutes.
- **Whether a refusal is toward a local provider is backtide's own reading**: the channel asks
  its config (the event's host is exactly a local provider's virtual name), never the proxy's
  ``local: true`` alone (``ProxyChannel._local_refusal``).
- ``note`` never blocks and never raises: the channel's reader calls it. What the agent chose
  (the method, the path, the target, the tools' names) is cut and quoted through ``agent_text``,
  like the hold notice (review of T10-4, B2): no domain, mail address, mention or phone number in
  it can be tapped, and the agent cannot draw the notice's own brackets. The alert door (the
  Guardian's ``_alert``) strikes secrets again.
"""

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from backtide.blackbox import Event
from backtide.notify import AlertLevel
from backtide.notify.text import agent_text, printable

logger = logging.getLogger(__name__)

EVERY = 600.0  # seconds between two notices of the same provider and reason (decision 9)
MAX_KEYS = 64  # (provider, reason) pairs remembered; past them a provider's fold into "other"
EXCERPT_CHARS = 120
OTHER = "other"
MARKERS = "()"  # the notice's own frame around the agent's text (agent_text escapes them)
REDIRECT = "local_redirect"
# What each reason means, said to the owner (the reasons of risk 2 a local refusal can carry).
MEANING = {
    "provider_endpoint": "una ruta que no es una llamada al modelo",
    "provider_body": "un cuerpo que no es el JSON de una llamada al modelo",
    "provider_side_tool": "campos, modelos o herramientas que la excepción no abre",
    "foreign_credential": "una credencial que no es su clave falsa",
    "host_mismatch": "un Host o un SNI que no son los del destino",
    # local_redirect has its own wording in ``_tell`` (the response did reach the model).
}

Tell = Callable[[AlertLevel, str, str, Event | None], None]


@dataclass
class _Held:
    """Refusals of one provider and reason counted since their last notice."""

    first: Event
    provider: str
    reason: str
    count: int = 1
    last: Event | None = None

    @property
    def newest(self) -> Event:
        return self.last if self.last is not None else self.first


class LocalRefusals:
    """``alert(level, title, body, event)`` is the Guardian's alert door (``EgressHooks.alert``
    through the Egress). One for the service: a proxy restart does not reset its count."""

    def __init__(
        self, alert: Tell, *, clock: Callable[[], float] = time.monotonic, every: float = EVERY
    ) -> None:
        self._alert = alert
        self._clock = clock
        self._every = every
        self._lock = threading.Lock()
        self._sent: dict[tuple[str, str], float] = {}  # when its last notice went out
        self._held: dict[tuple[str, str], _Held] = {}

    def note(self, event: Event, provider: str) -> None:
        """A refusal toward the local provider ``provider`` was recorded. Only risk 2 is told
        here. Never blocks, never raises."""
        try:
            if event.source != "net" or event.action != "blocked" or event.risk != 2:
                return
            key = (provider, str(event.details.get("reason") or OTHER))
            now = self._clock()
            with self._lock:
                if key not in self._sent and len(self._sent) >= MAX_KEYS:
                    key = (provider, OTHER)
                last = self._sent.get(key)
                held = self._held.get(key)
                if last is not None and now - last < self._every:
                    if held is None:
                        self._held[key] = _Held(event, *key)
                    else:
                        held.count += 1
                        held.last = event
                    return
                self._sent[key] = now
                self._held.pop(key, None)
            if held is None:
                self._tell(_Held(event, *key))
            else:  # its 10 minutes ended with no tick: those held go out with this one
                self._tell(_Held(held.first, *key, held.count + 1, event))
        except Exception:
            logger.exception("could not tell of a refusal toward a local model")

    def send_due(self) -> None:
        """Send the notices held back whose 10 minutes are over. Never raises."""
        self._send_held(force=False)

    def flush(self) -> None:
        """Send every notice held back, now (the service stops). Never raises."""
        self._send_held(force=True)

    def _send_held(self, *, force: bool) -> None:
        try:
            now = self._clock()
            with self._lock:
                due = [
                    key
                    for key in self._held
                    if force or now - self._sent.get(key, float("-inf")) >= self._every
                ]
                sending = [self._held.pop(key) for key in due]
                for key in due:
                    self._sent[key] = now
            for held in sending:
                self._tell(held)
        except Exception:
            logger.exception("could not send the notices of refusals toward a local model")

    def _tell(self, held: _Held) -> None:
        first, newest, reason = held.first, held.newest, held.reason
        provider = _plain(held.provider)
        meaning = MEANING.get(reason, "algo que la excepción del modelo local no abre")
        if reason == REDIRECT:
            lines = [
                "Llegó al modelo local, pero su respuesta (una redirección o un cambio de "
                "protocolo) no ha llegado al agente.",
                f"{_request(first)}",
            ]
        else:
            lines = [
                f"El proxy no ha dejado pasar una petición del agente hacia el modelo local "
                f"{provider}: {meaning} ({_plain(reason)}).",
                f"{_request(first)} No ha llegado a esa máquina.",
            ]
        if held.count > 1:
            lines.append(
                f"Son {held.count} así desde el último aviso; el último: {_request(newest)}"
            )
        lines.append("Si no lo esperabas, mira qué hacía el agente en la caja negra.")
        try:
            self._alert(
                AlertLevel.WARNING,
                f"Rechazado hacia el modelo local {provider}",
                " ".join(lines),
                first,
            )
        except Exception:
            logger.exception("could not tell of a refusal toward a local model")


def _request(event: Event) -> str:
    """What was asked (method and path, or the destination of a ``CONNECT``), and the refused
    tools' names: the agent's choices, cut and made untappable."""
    details = event.details
    method, path = details.get("method"), details.get("path")
    asked = f"{method} {path}" if method and path else event.target
    tools = details.get("tools")
    named = ""
    if isinstance(tools, list) and tools:
        named = f" ({', '.join(_agent(str(t)) for t in tools[:4])})"
    return f"Pidió {_agent(str(asked))}{named}."


def _agent(text: str) -> str:
    """Text the agent chose: cut, on one line and through ``agent_text``."""
    cut = text[:EXCERPT_CHARS] + ("…" if len(text) > EXCERPT_CHARS else "")
    return agent_text(cut.replace("\n", " ").replace("\r", " "), MARKERS)


def _plain(text: str) -> str:
    """Text of the owner's config or of backtide's (a provider's name, a reason): cut and
    escaped."""
    return printable(text[:EXCERPT_CHARS].replace("\n", " "))
