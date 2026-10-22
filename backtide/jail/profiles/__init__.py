"""The agent profiles (docs/34, section 7): the named ones, in code, and ``custom``, put together
from ``[agent]`` of backtide.toml (profiles/custom.py). OpenClaw is the default.

A named profile is one more entry of ``NAMED``: ``[agent] profile`` looks it up by its name.
Claude Code's (T17a-4) is the first of the ``shell`` mode.
"""

from collections.abc import Mapping
from types import MappingProxyType

from backtide.jail.profile import AgentProfile
from backtide.jail.profiles.claude_code import CLAUDE_CODE
from backtide.jail.profiles.custom import CUSTOM
from backtide.jail.profiles.openclaw import OPENCLAW

DEFAULT_PROFILE = OPENCLAW
NAMED: Mapping[str, AgentProfile] = MappingProxyType(
    {OPENCLAW.name: OPENCLAW, CLAUDE_CODE.name: CLAUDE_CODE}
)


def profile_names() -> tuple[str, ...]:
    """Every name ``[agent] profile`` takes: the named profiles and ``custom``."""
    return (*NAMED, CUSTOM)


__all__ = ["CLAUDE_CODE", "CUSTOM", "DEFAULT_PROFILE", "NAMED", "OPENCLAW", "profile_names"]
