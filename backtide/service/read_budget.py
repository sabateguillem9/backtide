"""How much the reads to unknown hosts may carry out (docs/32, section 13; security review of
T10-3, M5). Pure: the caller gives the time.

A read to a host off ``[proxy] allow_hosts`` passes without asking (decision 1), and its URL
and headers are a way out: up to 2 KiB of URL and 2 KiB of headers per request, at the
request budget's pace. This budget bounds that channel: the bytes of URL and of the headers
that are not credentials, per host and per hour, and all hosts together per hour. Over either,
the read is held (``read_budget``, risk 2): the person sees it and may approve it.

Windows are fixed hours that start with a host's first read (as ``DailyBudget``). The hosts
seen are bounded (MAX_HOSTS): past it, the expired windows are dropped, and if all are live the
read counts as over the budget (fails closed). A host's subdomains each have their own window,
so an agent that spreads over many names meets only the total.
"""

from dataclasses import dataclass

WINDOW_S = 3600.0
DEFAULT_HOST_BYTES = 256 * 1024  # [gate] read_budget_host_kib = 256
DEFAULT_TOTAL_BYTES = 2 * 1024 * 1024  # [gate] read_budget_total_kib = 2048
MAX_HOSTS = 65_536


@dataclass
class _Window:
    start: float
    used: int = 0


class ReadBudget:
    """Bytes of reads to unknown hosts, per host and in total, per hour. ``take`` spends only
    when both have room; else it spends nothing and says no."""

    def __init__(
        self,
        host_bytes: int = DEFAULT_HOST_BYTES,
        total_bytes: int = DEFAULT_TOTAL_BYTES,
        *,
        max_hosts: int = MAX_HOSTS,
    ) -> None:
        if host_bytes < 0 or total_bytes < 0 or max_hosts < 1:
            raise ValueError("a read budget is zero or more bytes")
        self.host_bytes = host_bytes
        self.total_bytes = total_bytes
        self._max_hosts = max_hosts
        self._hosts: dict[str, _Window] = {}
        self._total: _Window | None = None

    def take(self, host: str, size: int, now: float) -> bool:
        """Spend ``size`` bytes of ``host``'s hour and of the total hour, if both have room."""
        size = max(0, size)
        total = self._total
        if total is None or now - total.start >= WINDOW_S or now < total.start:
            total = self._total = _Window(now)
        window = self._hosts.get(host)
        if window is None or now - window.start >= WINDOW_S or now < window.start:
            if window is None and len(self._hosts) >= self._max_hosts:
                self._forget_expired(now)
                if len(self._hosts) >= self._max_hosts:
                    return False
            window = _Window(now)
        if window.used + size > self.host_bytes or total.used + size > self.total_bytes:
            return False
        window.used += size
        total.used += size
        self._hosts[host] = window
        return True

    def used(self, host: str) -> int:
        window = self._hosts.get(host)
        return 0 if window is None else window.used

    def _forget_expired(self, now: float) -> None:
        self._hosts = {
            host: window for host, window in self._hosts.items() if now - window.start < WINDOW_S
        }
