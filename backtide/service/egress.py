"""The egress proxy in the service (T06-4): its container, the channel to it, and its watch.

Design: docs/21-diseno-t06-proxy.md, section 9. The Guardian owns one ``Egress`` and calls it at
a few points of its life; the watch runs on this module's own thread.

- **Start** (``start``), after the agent's jail is prepared and before the agent: the egress
  network, the channel folder (its tmpfs) and the container (made if missing, killed first if
  a dead service left it running: its channel and config are ours to give), nobody but the
  agent and the proxy on the agent's network, ``docker start``, the ready line, and then the
  channel: connect (``open_channel``), check who is there (``check_peer``), read the ``hello``
  and send the config. ``system/proxy_start {version, ...}`` only then. Anything short of that
  is ``system/proxy_start_failed`` (risk 2) and an alert, and ``allows_agent()`` stays False:
  **without the proxy's hello the agent does not start**.
- **Down** (the watch, every ``WATCH_EVERY`` s): the container does not run, the channel closed,
  or nothing came from the proxy for ``SILENCE_LIMIT`` s, is ``system/proxy_down`` (risk 2) and
  an alert. The agent keeps running with no way out (it fails closed by the network). A channel
  that closed while the container runs is reconnected (``system/proxy_up {how: reconnect}``),
  unless the proxy broke the protocol (it may be compromised); anything else restarts the
  proxy, at most ``RESTARTS_PER_HOUR`` times an hour, each attempt recorded
  (``system/proxy_restart``). Once it is up again the Guardian's ``back`` hook runs (it
  starts an agent that was held for want of a proxy).
- **Stop** (``stop``): the Guardian stops the agent first; then the proxy (``docker stop``,
  killed if that fails), then the channel, and ``system/proxy_stop``.
- **Held requests** (T10-2, docs/32 section 6): ``decide``, ``pending`` and ``reject_holds`` go to
  the channel of the moment (its ``HoldBook``), and so do the batches (T10-4: ``create_batch``,
  ``batches``, ``end_batch``); every channel tells ``watch`` (the Telegram notice) of its
  holds; with no channel there is nothing held. At the first ``start``, the holds a backtide
  that died left open in the black box (``gate/held`` of the last 15 min with no end) are
  closed with ``gate/expired {why: restart}``: the proxy that held them refused them when it
  lost its channel.
- **Providers waiting for their key** (docs/21, section 6): at the start, and each time the
  Settings page hands new keys (``reload``), a provider that waits is recorded once as
  ``system/provider_waiting {provider, problem}`` (``missing``, risk 1; ``unusable``, risk 2,
  with a warning in the log and an alert; ``not_applied``, a new key a failed reload could not
  hand over, risk 2, with its own warning and alert), and one that gets its key back as
  ``system/provider_ready``. ``waiting()`` says which wait now (Settings, /estado, the panel).
- **Local providers** (T20, docs/35 section 6.4): where each one is (resolved by the service) is
  recorded at the start as ``system/provider_local {provider, name, address, port}`` and, when a
  reload finds it elsewhere, as ``system/provider_local_changed {applied: false}`` (risk 2, with an
  alert): the old address stays until the owner restarts the service (review of T20-2/3, L2).
  Before the proxy starts, no local provider may be on the agent's own network (the start fails
  at step ``local_provider``); those subnets are kept, and a reload that would break the rule is
  not taken. Each time one is recorded somewhere new, the service asks that Ollama its version
  (``ask_version``, on a thread of its own; T20-4): ``system/provider_local_ready {provider,
  version, minimum, old}``, risk 2 with an alert when it is older than the minimum, or
  ``system/provider_local_unanswered {provider, address, port, why}`` (risk 1) when it does not
  answer (Ollama closed on the Mac, a wrong port). On the same thread it then asks how much
  context that Ollama gave the provider's models (``ask_context``, ``GET /api/ps``): once one of
  them is loaded, ``system/provider_local_context {provider, contexts, needed, agent, low}``,
  risk 2 with an alert when a model has less than the agent needs (``ContextNeed``: Claude Code
  64,000, OpenClaw 32,768). A model is only loaded at its first call, so it asks again every
  ``CONTEXT_RETRY`` s, ``CONTEXT_TRIES`` times at most (then ``{known: false}``, risk 0). It never
  holds the start. A refusal of risk 2 toward a local provider
  is told (``local_refusals``, one for the service, docs/35 decision 9): the first of each reason
  at once, then at most one every 10 min; what is held is sent by the watch and at the stop.
- Nothing raises out of here into the Guardian: failures are recorded and alerted.
"""

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from backtide.blackbox import Event
from backtide.jail import docker
from backtide.jail.docker import JailError
from backtide.jail.proxy import ProxyJail
from backtide.jail.proxy_config import MITMPROXY_VERSION
from backtide.notify import AlertLevel
from backtide.notify.local_refusals import LocalRefusals
from backtide.service.holds import (
    STALE_WINDOW,
    BatchOutcome,
    BatchStatus,
    HoldOutcome,
    HoldStatus,
    HoldTimings,
    HoldWatch,
    TrustOutcome,
    TrustStatus,
    stale_holds,
)
from backtide.service.local_models import (
    MIN_OLLAMA_VERSION,
    ContextNeed,
    LocalModelError,
    context_of,
    older_than,
    outside,
)
from backtide.service.pause import Ticker
from backtide.service.price_update import PriceUpdater
from backtide.service.proxy_channel import (
    KEY_NOT_APPLIED,
    Budgets,
    ChannelError,
    Peer,
    Policy,
    ProxyChannel,
    Record,
    check_peer,
    open_channel,
)
from backtide.service.read_budget import ReadBudget
from backtide.service.spend import Budget
from backtide.service.trust import TrustError, TrustStore
from backtide.snapshots import utc_now

logger = logging.getLogger(__name__)

HELLO_TIMEOUT = 30.0  # docs/21, section 9: "30 s como mucho"
RECONNECT_TIMEOUT = 5.0
WATCH_EVERY = 5.0
SILENCE_LIMIT = 15.0  # three pings missed
RESTARTS_PER_HOUR = 3
RESTART_WINDOW = 3600.0
CONNECT_RETRY = 0.25
# How often, and how many times, the service asks a local Ollama how much context it gave the
# provider's models, until one of them is loaded (Ollama loads a model at its first call, which
# may come long after the start: OpenClaw waits for a message). 30 s for an hour.
CONTEXT_RETRY = 30.0
CONTEXT_TRIES = 120
MAX_CONTEXT_MODELS = 8  # the models of one provider that are looked at
_ERROR_CHARS = 300


@dataclass(frozen=True)
class EgressHooks:
    """The Guardian's side: its own ``_record`` and ``_alert`` (one door for every event and
    alert), and ``back``, called once the proxy is up again after a fall."""

    record: Callable[..., Event | None]
    alert: Callable[..., None]
    back: Callable[[], None] = lambda: None
    # Whether the agent is paused or being rewound: then no batch rule lets anything pass, as
    # no approval is given (security review of T10-4, B4).
    frozen: Callable[[], bool] = lambda: False


Connect = Callable[[ProxyJail, float], ProxyChannel]
# The gate events of the black box since a moment (``BlackBox.events(source=, since_ts=)``).
History = Callable[..., list[Event]]


class Egress:
    """The proxy's container, its channel and its watch, for the Guardian. ``record`` is where
    the channel appends what the proxy says (the black box, rated). ``thread=False`` (tests)
    leaves the watch to whoever calls ``check()``."""

    def __init__(
        self,
        jail: ProxyJail,
        *,
        agent_name: str,
        policy: Policy,
        record: Record,
        limits: Mapping[str, int] | None = None,
        hello_timeout: float = HELLO_TIMEOUT,
        thread: bool = True,
        connect: Connect | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        timings: HoldTimings | None = None,
        history: History | None = None,
        watch: HoldWatch | None = None,
        trust: TrustStore | None = None,
        budget: Budget | None = None,
        prices: PriceUpdater | None = None,
        ask_version: Callable[[str, int], str] | None = None,
        ask_context: Callable[[str, int], Mapping[str, int]] | None = None,
        context_need: ContextNeed | None = None,
    ) -> None:
        self._jail = jail
        # T20-4: how the service asks a local Ollama its version (local_models.ollama_version);
        # None asks nothing (the tests' fake worlds).
        self._ask_version = ask_version
        # And how much context it gave each model (local_models.ollama_contexts), against what
        # the agent needs (None: recorded, never "low"). None asks nothing.
        self._ask_context = ask_context
        self._context_need = context_need
        self._context_rounds: dict[str, int] = {}  # a newer ask for a provider ends the older
        self._closing = threading.Event()  # the stop ends the asking
        # The spending cap (T11): one for the service, handed to every channel. It reads its
        # totals (or rebuilds them from the black box) at the first start, once the box is open;
        # ``prices`` keeps its price table up to date on a thread of its own.
        self.budget = budget
        self._prices = prices
        self._budget_opened = False
        self._watch = watch
        # The recipients trusted from the web (T10-5): one list for the service, handed to every
        # channel, so a proxy restart keeps them (they live in <state_dir>/trusted.json).
        self._trust = trust
        self._agent_name = agent_name
        self._policy = policy
        self._box = record
        self._limits = dict(limits or {})
        self._hello_timeout = hello_timeout
        self._thread = thread
        self._connect = connect or self._open
        self._mono = monotonic
        self._sleep = sleep
        self._lock = threading.Lock()
        self._hooks: EgressHooks | None = None
        self._channel: ProxyChannel | None = None
        self._ticker: Ticker | None = None
        self._up = False
        self._down_since: float | None = None
        self._restarts: deque[float] = deque()
        self._out_of_restarts_told: float | None = None
        self._budget_alert_due = True
        self._timings = timings
        self._history = history
        self._stale_closed = False
        # One for the service, not one per connection: a proxy restart never refills what the
        # reads to unknown hosts may still carry out this hour (review of T10-3, M5).
        self._read_budget = ReadBudget(policy.read_budget_host, policy.read_budget_total)
        self._key_states: dict[str, str] = {}  # the providers that wait, as last recorded
        self._local_states: dict[str, tuple[str, int]] = {}  # local providers, as last recorded
        self._moves_told: dict[str, tuple[str, int]] = {}  # moves a reload did not apply, told
        self._agent_subnets: list[str] | None = None  # read at the start, checked at each reload
        # T20-5 (docs/35, decision 9): the notices of refusals of risk 2 toward a local provider.
        # One for the service, handed to every channel, so a proxy restart keeps its count.
        self.local_refusals = LocalRefusals(self._alert, clock=monotonic)

    def waiting(self) -> dict[str, str]:
        """The providers that wait for their key now, and why ("missing", "unusable" or
        "not_applied")."""
        return self._policy.waiting()

    @property
    def policy(self) -> Policy:
        """What every connection to the proxy hands it now (``reload`` changes it)."""
        return self._policy

    # The Guardian's calls

    @property
    def up(self) -> bool:
        return self._up

    def allows_agent(self) -> bool:
        """The agent may start only while the proxy is up and configured."""
        return self._up

    def start(self, hooks: EgressHooks) -> bool:
        """Bring the proxy up and start its watch. False (recorded, alerted) if it is not up."""
        with self._lock:
            self._hooks = hooks
            self._closing.clear()
            self._close_stale_holds()
            self._note_keys()
            self._note_locals()
            if self.budget is not None and not self._budget_opened:
                self._budget_opened = True
                self.budget.open()  # never raises: without a count, model calls are refused
                if self._prices is not None:
                    self._prices.start()
            ok = self._bring_up("boot")
            if not ok:
                self._down_since = self._mono()  # recorded as start_failed: the watch retries
        if self._thread and self._ticker is None:
            self._ticker = Ticker("backtide-egress", WATCH_EVERY, self.check)
            self._ticker.start()
        return ok

    def stop(self, reason: str = "service_stop") -> None:
        """The watch, the open holds, then the proxy, then the channel (the agent is stopped
        already)."""
        self._closing.set()  # the asking of a local Ollama's context ends
        if self._ticker is not None:
            self._ticker.close()
            self._ticker = None
        if self._prices is not None:
            self._prices.close()
        with self._lock:
            self._up = False
            # The holds end first, as a clean stop (gate/expired {why: restart}): with the proxy
            # stopped first, the reader would see the channel lost. Nothing goes out meanwhile:
            # what the proxy holds waits for a decision that never comes, and dies with it.
            if self._channel is not None:
                self._channel.end_holds("stop")
            error = self._stop_container()
            self._close_channel("stop")
            details: dict[str, Any] = {"reason": reason, "stopped": error is None}
            if error is not None:
                details["error"] = _short(error)
            self._record("proxy_stop", details, risk=0 if error is None else 2)
        self.local_refusals.flush()  # nothing counted is lost (decision 9)

    def check(self) -> None:
        """One look of the watch (WATCH_EVERY s on its thread). Never raises."""
        back = False
        with self._lock:
            if self._hooks is None:
                return
            try:
                back = self._check_locked()
            except Exception as error:
                logger.exception("the proxy's watch failed")
                self._record("proxy_watch_failed", {"error": _short(error)}, risk=2)
        self.local_refusals.send_due()  # also while no channel ticks (the proxy is down)
        if back and self._hooks is not None:
            try:
                self._hooks.back()
            except Exception:
                logger.exception("the Guardian's hook for a proxy that is back failed")

    # Held requests (T10-2)

    def decide(
        self,
        hold_id: str,
        verdict: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> HoldOutcome:
        """Approve or reject a held request (``ProxyChannel.decide``; ``frozen``: the agent is
        paused or being rewound, so nothing is approved). Without a channel there is no hold:
        UNKNOWN. Never raises for a hold that is not there."""
        channel = self._channel
        if channel is None or channel.closed:
            return HoldOutcome(HoldStatus.UNKNOWN, hold_id)
        return channel.decide(hold_id, verdict, by=by, requested_by=requested_by, frozen=frozen)

    def pending(self) -> list[dict[str, Any]]:
        channel = self._channel
        return [] if channel is None or channel.closed else channel.pending()

    def create_batch(
        self,
        hold_id: str,
        kind: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> BatchOutcome:
        """Make a batch rule from an open hold and approve it (``ProxyChannel.create_batch``,
        T10-4). Without a channel there is no hold: UNKNOWN."""
        channel = self._channel
        if channel is None or channel.closed:
            return BatchOutcome(BatchStatus.UNKNOWN, hold_id)
        return channel.create_batch(hold_id, kind, by=by, requested_by=requested_by, frozen=frozen)

    def batches(self) -> list[dict[str, Any]]:
        channel = self._channel
        return [] if channel is None or channel.closed else channel.batches()

    def end_batch(self, rule_id: str, *, by: str) -> bool:
        channel = self._channel
        return False if channel is None or channel.closed else channel.end_batch(rule_id, by=by)

    # Trusted recipients from the web (T10-5, decision 9)

    def trust(
        self,
        hold_id: str,
        *,
        by: str,
        requested_by: str,
        frozen: Callable[[], bool] | None = None,
    ) -> TrustOutcome:
        """Trust the recipient of an open hold and approve it (``ProxyChannel.trust``). Without
        a channel there is no hold: UNKNOWN."""
        channel = self._channel
        if channel is None or channel.closed:
            return TrustOutcome(TrustStatus.UNKNOWN, hold_id)
        return channel.trust(hold_id, by=by, requested_by=requested_by, frozen=frozen)

    def trusted(self) -> list[dict[str, Any]]:
        """The recipients trusted from the web, oldest first."""
        return [] if self._trust is None else self._trust.listing()

    def untrust(self, trust_id: str, *, by: str, requested_by: str) -> bool | None:
        """Stop trusting ``trust_id``: True when removed (and ``gate/trust_removed`` recorded),
        False when there is no such entry, None when the list could not be saved (it is still
        trusted). Never raises."""
        if self._trust is None:
            return False
        try:
            entry = self._trust.remove(trust_id)
        except TrustError:
            return None
        if entry is None:
            return False
        if self._hooks is not None:
            details = {"trust_id": entry.trust_id, "translator": entry.translator,
                       "recipient": entry.recipient, "by": by,
                       "requested_by": str(requested_by)[:120]}  # fmt: skip
            self._hooks.record("gate", "trust_removed", entry.recipient, details=details, risk=1)
        return True

    def reject_holds(self, by: str) -> int:
        """A pause or a rewind rejects every open hold (decision 7). Never raises."""
        channel = self._channel
        if channel is None or channel.closed:
            return 0
        try:
            return channel.reject_open(by)
        except Exception:
            logger.exception("rejecting the held requests failed")
            self.end_batches(by)  # all the same (reject_open ends them in a finally, too)
            return 0

    def end_batches(self, by: str) -> int:
        """End every batch rule (a pause or a rewind whose rejection failed). Never raises."""
        channel = self._channel
        if channel is None or channel.closed:
            return 0
        try:
            return channel.end_batches(by)
        except Exception:
            logger.exception("ending the batch rules failed")
            return 0

    def _frozen(self) -> bool:
        """The Guardian's ``frozen`` (False before ``start``): read by the channel under its
        gate lock, so it never blocks."""
        hooks = self._hooks
        return hooks is not None and hooks.frozen()

    # New keys (T12e)

    def reload(self, policy: Policy) -> bool:
        """The providers' keys changed (the web's Settings page): from now on every connection
        to the proxy hands it ``policy``, and the live one is replaced at once by a new one (the
        proxy takes the newer connection and its ``config``, as on a reconnect), so the proxy
        uses the new key without a restart. True if it took it now; False if the proxy is down
        or did not answer, and then the watch brings it back with ``policy``. Requests held at
        that moment end with their connection (refused, recorded as expired: fail closed).
        Records ``system/proxy_reconfigured``, with the providers' names only. Never raises."""
        with self._lock:
            try:
                self._outside(policy, self._agent_subnets)
            except LocalModelError as error:
                # Review of T20-2/3 (L2): never a local provider on the agent's own network,
                # also after a reload. The policy is not taken: the proxy keeps the one it has.
                logger.error("a reload would put a local provider on the agent's network")
                names = [p.name for p in policy.providers.items]
                self._record("proxy_reconfigured", {"providers": names, "now": False,
                                                    "error": str(error)}, risk=2)  # fmt: skip
                return False
            self._policy = policy
            self._read_budget.host_bytes = policy.read_budget_host
            self._read_budget.total_bytes = policy.read_budget_total
            self._note_keys()
            self._note_locals()
            names = [p.name for p in policy.providers.items]
            if not self._up or self._channel is None or self._channel.closed:
                # Down for the watch (silent, out of restarts) but maybe still serving: its
                # channel goes, and with it the config it had (a removed key, say), so the proxy
                # refuses until it connects again and gets ``policy`` (review of 40dfd53).
                self._close_channel("reload")
                self._record("proxy_reconfigured", {"providers": names, "now": False}, risk=1)
                return False
            try:
                ok = self._reconnect()
            except Exception as error:  # _reconnect should not raise; the watch takes over
                logger.exception("handing the new keys to the proxy failed")
                self._record("proxy_reconfigured", {"providers": names, "now": False,
                                                    "error": _short(error)}, risk=2)  # fmt: skip
                return False
            self._record("proxy_reconfigured", {"providers": names, "now": ok}, risk=0 if ok else 2)
            return ok

    def _note_keys(self) -> None:
        """Record (and log once) each provider that starts waiting for its key, and each that
        gets it back. Never raises. Before ``start`` (no hooks yet) it waits for ``start``."""
        if self._hooks is None:
            return
        try:
            now = self._policy.waiting()
            for name, problem in sorted(now.items()):
                if self._key_states.get(name) == problem:
                    continue
                note = self._policy.key_note(name)
                if problem == "unusable":
                    logger.warning(
                        "the key of provider %s cannot be used, so its model calls are refused "
                        "until it is set again: %s", name, note,
                    )  # fmt: skip
                elif problem == KEY_NOT_APPLIED:
                    logger.warning(
                        "the new key of provider %s could not be handed to the proxy, so its "
                        "model calls are refused until the keys are reloaded or the service "
                        "restarts", name,
                    )  # fmt: skip
                else:
                    logger.warning(
                        "provider %s has no key yet: its model calls are refused until the "
                        "owner sets it in the Settings page", name,
                    )  # fmt: skip
                details = {"provider": name, "problem": problem}
                event = self._record(
                    "provider_waiting", details, risk=1 if problem == "missing" else 2
                )
                if problem == KEY_NOT_APPLIED:
                    self._alert(
                        AlertLevel.WARNING,
                        f"La clave nueva de {name} no ha llegado al proxy",
                        "Se ha guardado, pero no se ha podido entregar al proxy (mira el registro "
                        "del servicio). El agente no puede usar ese modelo hasta que se recarguen "
                        "las claves (guárdala otra vez en Ajustes) o se reinicie el servicio.",
                        event,
                    )
                elif problem == "unusable":
                    self._alert(
                        AlertLevel.WARNING,
                        f"La clave de {name} no se puede usar",
                        "Hay un archivo de clave, pero no se puede usar (mira el registro del "
                        "servicio). El agente no puede usar ese modelo hasta que la pongas otra "
                        "vez en Ajustes.",
                        event,
                    )
            for name in sorted(set(self._key_states) - set(now)):
                if self._policy.providers.by_name(name) is not None:
                    self._record("provider_ready", {"provider": name}, risk=0)
            self._key_states = dict(now)
        except Exception:
            logger.exception("recording which providers wait for their key failed")

    def _note_locals(self) -> None:
        """Record where each local provider is, once, and each time it moves (T20). Never
        raises. Before ``start`` (no hooks yet) it waits for ``start``."""
        if self._hooks is None:
            return
        try:
            for provider in self._policy.providers.items:
                if not provider.local or provider.upstream is None:
                    continue
                address, port = provider.upstream
                details: dict[str, Any] = {
                    "provider": provider.name, "name": provider.host, "address": address,
                    "port": port,
                }  # fmt: skip
                before = self._local_states.get(provider.name)
                if before == provider.upstream:
                    continue
                if before is None:
                    self._record("provider_local", details)
                    self._check_version(provider.name, address, port, provider.models)
                else:
                    logger.warning(
                        "local provider %s moved from %s:%d to %s:%d", provider.name, *before,
                        address, port,
                    )  # fmt: skip
                    details["before"] = f"{before[0]}:{before[1]}"
                    details["applied"] = True
                    self._record("provider_local_changed", details, risk=1)
                    self._check_version(provider.name, address, port, provider.models)
                self._local_states[provider.name] = provider.upstream
            self._note_moves()
        except Exception:
            logger.exception("recording where the local providers are failed")

    def _check_version(
        self, name: str, address: str, port: int, models: tuple[str, ...] = ()
    ) -> None:
        """Ask the Ollama of the local provider ``name`` its version and then the context of
        its ``models``, on a thread of its own (the start never waits for it), and record what
        it says. A newer ask for the same provider (it moved) ends the older one."""
        if self._ask_version is None and self._ask_context is None:
            return
        round_ = self._context_rounds.get(name, 0) + 1
        self._context_rounds[name] = round_
        if not self._thread:
            self._ask_local(name, address, port, models, round_)
            return
        threading.Thread(
            target=self._ask_local,
            args=(name, address, port, models, round_),
            name=f"ollama-version-{name}",
            daemon=True,
        ).start()

    def _ask_local(
        self, name: str, address: str, port: int, models: tuple[str, ...], round_: int
    ) -> None:
        self._tell_version(name, address, port)
        self._tell_context(name, address, port, models, round_)

    def _tell_context(
        self, name: str, address: str, port: int, models: tuple[str, ...], round_: int
    ) -> None:
        """Ask until one of ``models`` is loaded (CONTEXT_RETRY s apart, CONTEXT_TRIES times),
        then ``system/provider_local_context`` (risk 2 and an alert when one has less context
        than the agent needs). Gives up with ``{known: false}``; ends at the stop or when a newer
        ask for the provider began. Never raises."""
        ask = self._ask_context
        models = tuple(dict.fromkeys(models))[:MAX_CONTEXT_MODELS]
        if ask is None or not models:
            return
        try:
            for attempt in range(CONTEXT_TRIES):
                if attempt and self._wait_closing(CONTEXT_RETRY):
                    return
                if self._context_rounds.get(name) != round_:
                    return  # it moved: the newer ask says it
                try:
                    loaded = ask(address, port)
                except LocalModelError as error:
                    logger.info("local provider %s: %s", name, error)
                    continue
                found = {m: c for m in models if (c := context_of(loaded, m)) is not None}
                if found:
                    self._say_context(name, found)
                    return
            self._record(
                "provider_local_context",
                {"provider": name, "models": list(models), "known": False},
            )
        except Exception:
            logger.exception("asking the local provider %s its context failed", name)

    def _wait_closing(self, seconds: float) -> bool:
        """Wait ``seconds`` (the injected sleep without a thread: the tests); True if the
        Egress is stopping."""
        if self._thread:
            return self._closing.wait(seconds)
        self._sleep(seconds)
        return self._closing.is_set()

    def _say_context(self, name: str, found: Mapping[str, int]) -> None:
        need = self._context_need
        low = {m: c for m, c in sorted(found.items()) if need is not None and c < need.tokens}
        details: dict[str, Any] = {
            "provider": name, "contexts": dict(sorted(found.items())), "known": True,
            "low": bool(low),
        }  # fmt: skip
        if need is not None:
            details["needed"] = need.tokens
            details["agent"] = need.agent
        event = self._record("provider_local_context", details, risk=2 if low else 0)
        if not low or need is None:
            return
        model, context = min(low.items(), key=lambda item: item[1])
        logger.warning(
            "local provider %s: Ollama gives %s a context of %d tokens; %s needs %d. Set "
            "OLLAMA_CONTEXT_LENGTH=%d and restart Ollama", name, model, context, need.agent,
            need.tokens, need.setting,
        )  # fmt: skip
        self._alert(
            AlertLevel.WARNING,
            f"El Ollama de {name} tiene poco contexto",
            f"Tu Ollama tiene {_thousands(context)} de contexto para {model}; {need.agent} "
            f"necesita {_thousands(need.tokens)}: el modelo no verá sus herramientas ni sus "
            "instrucciones, porque Ollama corta en silencio lo que no cabe. Pon "
            f"OLLAMA_CONTEXT_LENGTH={need.setting} y reinicia Ollama (en el Mac: `launchctl "
            f"setenv OLLAMA_CONTEXT_LENGTH {need.setting}`, y cierra y abre Ollama). Más "
            "contexto pide más memoria.",
            event,
        )

    def _tell_version(self, name: str, address: str, port: int) -> None:
        """``system/provider_local_ready`` (risk 2 and an alert when it is older than the
        minimum) or ``system/provider_local_unanswered`` (risk 1). Never raises."""
        ask = self._ask_version
        if ask is None:
            return
        try:
            try:
                version = ask(address, port)
            except LocalModelError as error:
                logger.warning("local provider %s: %s", name, error)
                self._record(
                    "provider_local_unanswered",
                    {"provider": name, "address": address, "port": port, "why": str(error)},
                    risk=1,
                )
                return
            old = older_than(version)
            details = {
                "provider": name, "version": version, "minimum": MIN_OLLAMA_VERSION, "old": old,
            }  # fmt: skip
            event = self._record("provider_local_ready", details, risk=2 if old else 0)
            if old:
                logger.warning(
                    "local provider %s: Ollama %s is older than %s", name, version,
                    MIN_OLLAMA_VERSION,
                )  # fmt: skip
                self._alert(
                    AlertLevel.WARNING,
                    f"El Ollama de {name} es antiguo",
                    f"Dice ser la versión {version}, y backtide pide la {MIN_OLLAMA_VERSION} o "
                    "una más nueva (las viejas no tienen la API que usa Claude Code y han tenido "
                    "fallos de seguridad). Actualiza Ollama en esa máquina.",
                    event,
                )
        except Exception:
            logger.exception("asking the local provider %s its version failed", name)

    def _note_moves(self) -> None:
        """A local provider whose name resolved elsewhere at a reload keeps its old address
        until the service restarts (review of T20-2/3, L2): recorded once per new place
        (``provider_local_changed {applied: false}``, risk 2) with an alert, so the owner
        decides."""
        moved = self._policy.local_moved
        for name in [n for n in self._moves_told if n not in moved]:
            del self._moves_told[name]
        for name, (address, port) in sorted(moved.items()):
            provider = self._policy.providers.by_name(name)
            if provider is None or provider.upstream is None:
                continue
            if self._moves_told.get(name) == (address, port):
                continue
            before = provider.upstream
            details = {
                "provider": name, "name": provider.host, "address": address, "port": port,
                "before": f"{before[0]}:{before[1]}", "applied": False,
            }  # fmt: skip
            event = self._record("provider_local_changed", details, risk=2)
            self._alert(
                AlertLevel.WARNING,
                f"El modelo local {name} ha cambiado de dirección",
                f"Su nombre apunta ahora a {address}:{port}, pero backtide sigue usando "
                f"{before[0]}:{before[1]}. Si el cambio es tuyo (la IP de la torre, por ejemplo), "
                "reinicia el servicio para usar la nueva; si no, revisa quién ha cambiado ese "
                "nombre.",
                event,
            )
            self._moves_told[name] = (address, port)

    def _check_locals(self) -> None:
        """T20: no local provider on the agent's own network (JailError: the start fails). The
        subnets are kept for the reloads (``reload``)."""
        if not _upstreams(self._policy):
            return
        self._agent_subnets = self._jail.agent_subnets()
        try:
            self._outside(self._policy, self._agent_subnets)
        except LocalModelError as error:
            raise JailError(str(error)) from None

    @staticmethod
    def _outside(policy: Policy, subnets: list[str] | None) -> None:
        """LocalModelError if a local provider of ``policy`` is in one of ``subnets`` (None: not
        read yet, the start checks it)."""
        upstreams = _upstreams(policy)
        if upstreams and subnets is not None:
            outside(upstreams, subnets)

    def _close_stale_holds(self) -> None:
        """Once per service: the holds a dead backtide left open in the black box are ended
        (``gate/expired {why: restart}``). The proxy refused them when its channel went."""
        if self._stale_closed or self._history is None:
            return
        self._stale_closed = True
        now = utc_now()
        try:
            events = self._history(source="gate", since_ts=now - STALE_WINDOW)
        except Exception as error:
            logger.exception("cannot read the black box for held requests left open")
            self._record("gate_restart_check_failed", {"error": _short(error)}, risk=2)
            return
        seen = []
        held: dict[str, Event] = {}
        for event in events:
            hold_id, moment = event.details.get("hold_id"), _parse_ts(event.ts)
            if isinstance(hold_id, str) and moment is not None:
                seen.append((event.action, hold_id, moment))
                if event.action == "held":
                    held.setdefault(hold_id, event)
        for hold_id in stale_holds(seen, now=now):
            details: dict[str, Any] = {"hold_id": hold_id, "why": "restart"}
            fp = held[hold_id].details.get("fp")
            if isinstance(fp, str):
                details["fp"] = fp
            if self._hooks is not None:
                self._hooks.record("gate", "expired", held[hold_id].target, details=details, risk=2)

    # Watch

    def _problem(self) -> str | None:
        channel = self._channel
        try:
            running = self._jail.is_running()
        except JailError:
            running = False
        if not running:
            return "not_running"
        if channel is None:
            return "no_channel"
        if channel.closed:
            return f"channel_{channel.close_reason or 'closed'}"
        if channel.silent_for() > SILENCE_LIMIT:
            return "silent"
        return None

    def _check_locked(self) -> bool:
        problem = self._problem()
        if problem is None:
            return False
        if self._up or self._down_since is None:
            self._up = False
            self._down_since = self._mono()
            event = self._record("proxy_down", {"problem": problem}, risk=2)
            self._alert(
                AlertLevel.ERROR,
                "El proxy de salida se ha caído",
                "El agente sigue en marcha, pero sin salida a internet: nada sale sin grabarse. "
                "backtide intenta volver a levantar el proxy.",
                event,
            )
        # A proxy that broke the protocol may be a compromised one: it is restarted (killed
        # first), never just given its config again.
        suspect = problem in ("channel_protocol", "channel_crash")
        if (problem.startswith("channel") or problem == "no_channel") and not suspect:
            if self._reconnect():
                self._came_back("reconnect")
                return True
        if not self._may_restart():
            return False
        attempt = len(self._restarts)
        self._record("proxy_restart", {"attempt": attempt, "problem": problem}, risk=1)
        if self._bring_up("restart"):
            self._came_back("restart")
            return True
        return False

    def _came_back(self, how: str) -> None:
        down = self._down_since
        self._down_since = None
        seconds = None if down is None else round(self._mono() - down, 1)
        event = self._record("proxy_up", {"how": how, "down_s": seconds})
        self._alert(
            AlertLevel.INFO,
            "El proxy de salida ha vuelto",
            "El agente vuelve a tener salida a internet, grabada como siempre.",
            event,
        )

    def _may_restart(self) -> bool:
        now = self._mono()
        while self._restarts and now - self._restarts[0] >= RESTART_WINDOW:
            self._restarts.popleft()
        if len(self._restarts) >= RESTARTS_PER_HOUR:
            if self._out_of_restarts_told is None or now - self._out_of_restarts_told >= 3600:
                self._out_of_restarts_told = now
                event = self._record(
                    "proxy_restart_skipped", {"reason": "too_many", "per_hour": RESTARTS_PER_HOUR},
                    risk=2,
                )  # fmt: skip
                self._alert(
                    AlertLevel.ERROR,
                    "El proxy de salida no se levanta",
                    f"Se ha intentado {RESTARTS_PER_HOUR} veces en una hora. El agente sigue sin "
                    "salida a internet; se volverá a intentar dentro de un rato.",
                    event,
                )
            return False
        self._restarts.append(now)
        return True

    def _reconnect(self) -> bool:
        """Only the channel was lost and the container runs: connect again."""
        self._close_channel("reconnect")
        try:
            self._channel = self._connect(self._jail, RECONNECT_TIMEOUT)
        except (ChannelError, JailError) as error:
            logger.warning("cannot reconnect to the proxy's channel: %s", error)
            return False
        self._up = True
        return True

    # Start and stop

    def _bring_up(self, reason: str) -> bool:
        """Everything from the network to the config. Records proxy_start or its failure."""
        self._up = False
        self._close_channel("restart")
        step = "prepare"
        try:
            self._jail.ensure_network()
            self._jail.prepare_channel()
            if not self._jail.exists():
                self._jail.create()
            if self._jail.is_running():
                step = "kill_stale"
                self._jail.kill()  # its channel and config are ours to give: a fresh start
            if self.budget is not None:
                self.budget.forget_all()  # a new proxy: the old one's calls in flight are gone
            step = "agent_network"
            self._jail.check_agent_network(self._agent_name)
            step = "local_provider"
            self._check_locals()
            step = "start"
            self._jail.start()
            self._jail.wait_ready()
            step = "channel"
            self._channel = self._connect(self._jail, self._hello_timeout)
        except (JailError, ChannelError) as error:
            self._close_channel("failed")
            event = self._record(
                "proxy_start_failed", {"reason": reason, "step": step, "error": _short(error)},
                risk=2,
            )  # fmt: skip
            self._alert(
                AlertLevel.ERROR,
                "El proxy de salida no arranca",
                "Sin el proxy no se graba lo que sale, así que el agente no tiene salida a "
                "internet (y no arranca si estaba parado). Detalles en el evento.",
                event,
            )
            return False
        hello = self._channel.hello or {}
        self._record(
            "proxy_start",
            {
                "reason": reason,
                "version": hello.get("version"),
                "mitmproxy": MITMPROXY_VERSION,
                "image": self._jail.config.image,
                "providers": [p.name for p in self._policy.providers.items],
                "allow_hosts": len(self._policy.allow_hosts),
            },
        )
        self._up = True
        return True

    def _open(self, jail: ProxyJail, timeout: float) -> ProxyChannel:
        """Connect, check the peer, hello and config, within ``timeout`` (the proxy creates its
        socket before it prints its ready line, but a restart may race with us)."""
        deadline = self._mono() + timeout
        container_id = jail.container_id()
        while True:
            try:
                sock = open_channel(jail.config.channel_dir, proxy_uid=jail.config.uid)
                try:
                    self._check_peer(sock, container_id)
                    channel = ProxyChannel(
                        sock,
                        record=self._box,
                        policy=self._policy,
                        limits=self._limits,
                        budgets=Budgets(self._mono()),
                        on_budget=self._daily_budget_spent,
                        timings=self._timings,
                        read_budget=self._read_budget,
                        watch=self._watch,
                        frozen=self._frozen,
                        trust=self._trust,
                        budget=self.budget,
                        local_refusals=self.local_refusals,
                    )
                    channel.handshake(max(0.5, deadline - self._mono()))
                except BaseException:
                    sock.close()
                    raise
                channel.start()
                return channel
            except ChannelError:
                if self._mono() >= deadline:
                    raise
                self._sleep(CONNECT_RETRY)

    def _check_peer(self, sock: Any, container_id: str) -> Peer:
        return check_peer(sock, proxy_uid=self._jail.config.uid, container_id=container_id)

    def _stop_container(self) -> JailError | None:
        try:
            if not self._jail.is_running():
                return None
        except JailError:
            pass  # cannot tell: stop it anyway
        try:
            self._jail.stop()
            return None
        except JailError as error:
            logger.error("cannot stop the proxy, so it is killed: %s", error)
        try:
            self._jail.kill()
        except JailError as error:
            return error
        return None

    def _close_channel(self, reason: str) -> None:
        channel, self._channel = self._channel, None
        if channel is not None:
            channel.close(reason)

    def _daily_budget_spent(self) -> None:
        event = self._record("proxy_budget", {"reason": "daily"}, risk=2)
        self._alert(
            AlertLevel.WARNING,
            "El agente ha agotado sus peticiones del día",
            "El agente ha hecho el máximo de peticiones a internet de un día: lo que pida ahora "
            "se rechaza (y se cuenta) hasta que acabe el día.",
            event,
        )

    # Records

    def _record(self, action: str, details: dict[str, Any], *, risk: int = 0) -> Event | None:
        if self._hooks is None:
            logger.error("a proxy event (%s) came before the Guardian's hooks", action)
            return None
        return self._hooks.record("system", action, details=details, risk=risk)

    def _alert(self, level: AlertLevel, title: str, body: str, event: Event | None) -> None:
        if self._hooks is not None:
            self._hooks.alert(level, title, body, event)


def _thousands(number: int) -> str:
    """4096 as "4.096", as the owner reads numbers."""
    return f"{number:,}".replace(",", ".")


def _upstreams(policy: Policy) -> dict[str, tuple[str, int]]:
    return {p.name: p.upstream for p in policy.providers.items if p.local and p.upstream}


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _short(error: BaseException) -> str:
    text = docker.sanitize(str(error))
    return text[:_ERROR_CHARS]
