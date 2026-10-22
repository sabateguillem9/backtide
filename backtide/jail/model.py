"""A model provider as the agent sees it: any profile's (T06-5, T17a-3). Pure.

The agent only ever gets the FAKE key of a provider (``backtide-fake-<name>-...``); the proxy
holds the real one and swaps it on the way out (docs/21, section 6). Where the fake key reaches
the agent is its profile's business: OpenClaw reads it from openclaw.json, other agents from
a variable (``AgentProfile.fake_key_env``). What a profile needs on top of this (OpenClaw needs
the model ids of a provider it has no catalog of) is its ``check_providers``.

A local provider (T20, docs/35 section 6.6: an Ollama on the owner's Mac or LAN) is one more
provider for the agent: its host is its virtual name, ``<name>.backtide.internal``, which only the
proxy understands, and ``local`` says so, so a profile can set what a local model needs (OpenClaw:
no ``options.num_ctx`` and no paid fallback; Claude Code: its base URL and model ids). Where it
really is never reaches the agent.
"""

import re
from dataclasses import dataclass, field

from backtide.gate.providers import LOCAL_SUFFIX, is_fake_key, virtual_host

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
        agent's default model). ``local``: a local provider (T20), whose host is exactly its virtual
    name; no other provider may have a host under ``.backtide.internal``."""

    name: str
    kind: str
    host: str
    fake_key: str = field(repr=False)
    models: tuple[str, ...] = ()
    local: bool = False

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
        if not isinstance(self.local, bool):
            raise ValueError(f"provider {self.name}: local must be true or false")
        if self.local and self.host != virtual_host(self.name):
            raise ValueError(
                f"provider {self.name}: a local provider's host is its virtual name, "
                f"{virtual_host(self.name)}"
            )
        if not self.local and self.host.endswith(LOCAL_SUFFIX):
            raise ValueError(
                f"provider {self.name}: only a local provider has a host under {LOCAL_SUFFIX}"
            )
