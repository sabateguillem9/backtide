"""The agent's jail: OpenClaw in a locked-down Docker container.

Design and rationale: docs/13-diseno-t03-jaula.md. The container is the boundary, not
OpenClaw: its own approvals and hooks run inside the agent's process.
"""

from backtide.jail.agent import AgentJail
from backtide.jail.config import IMAGE, OPENCLAW_VERSION, AgentJailConfig
from backtide.jail.docker import JailError

__all__ = ["IMAGE", "OPENCLAW_VERSION", "AgentJail", "AgentJailConfig", "JailError"]
