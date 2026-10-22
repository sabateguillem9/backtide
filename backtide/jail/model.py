"""A model provider as the agent sees it: any profile's (T06-5, T17a-3). Pure.

The agent only ever gets the FAKE key of a provider (``backtide-fake-<name>-...``); the proxy
holds the real one and swaps it on the way out (docs/21, section 6). Where the fake key reaches
the agent is its profile's business: OpenClaw reads it from openclaw.json, other agents from
a variable (``AgentProfile.fake_key_env``). What a profile needs on top of this (OpenClaw needs
the model ids of a provider it has no catalog of) is its ``check_providers``.
"""

import re
from dataclasses import dataclass, field

from backtide.gate.providers import is_fake_key

# The kinds the proxy knows (how the key travels): Anthropic's x-api-key, OpenAI's Bearer.
KINDS = ("anthropic", "openai")
_PROVIDER_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", re.ASCII)
_HOST_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", re.ASCII)
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", re.ASCII)


@dataclass(frozen=True)
class ModelProvider:
    """A model provider as the agent sees it: its name (the one of ``[[proxy.providers]]``),
    how it takes its key (``kind``), its host and the FAKE key. Never the real one: the proxy
    holds that. ``models`` are the model ids of ``[[proxy.providers]] models``, for profiles
    that must name them (OpenClaw: the first of the first provider that has them is the
    agent's default model)."""

    name: str
    kind: str
    host: str
    fake_key: str = field(repr=False)
    models: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _PROVIDER_NAME.fullmatch(self.name):
            raise ValueError(f"invalid provider name {self.name!r}")
        if self.kind not in KINDS:
            raise ValueError(f"provider {self.name}: unknown kind {self.kind!r}")
        if not isinstance(self.host, str) or not _HOST_NAME.fullmatch(self.host):
            raise ValueError(f"provider {self.name}: the host must be a lower-case host name")
        if not is_fake_key(self.fake_key, self.name):
            raise ValueError(f"provider {self.name}: the agent only ever gets its fake key")
        if not isinstance(self.models, tuple) or not all(
            isinstance(model, str) and MODEL_ID.fullmatch(model) for model in self.models
        ):
            raise ValueError(f"provider {self.name}: models must be a tuple of model ids")
