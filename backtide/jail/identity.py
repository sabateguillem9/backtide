"""Who an agent is on the machine: its slug, its number, its Docker names and its ids. Pure.

Design: docs/47-diseno-t26-web-agentes.md, section 6.8.

- The **slug** is what an agent is called for good: its address in the web, the name of its folder
  (``<state_dir>/agents/<slug>``) and of its file (``/etc/backtide/agents/<slug>.toml``), and part
  of its Docker names. It never changes. ``[a-z0-9-]``, 1 to 32 characters, no ``-`` at either end:
  so never ``..`` nor ``/``, whatever path or command it ends up in.
- ``principal`` is the installation's first agent, the one of every installation made before
  T26-2. It has no file: it is ``backtide.toml``, with the names, ids and paths it always had
  (61000 and 61001, ``backtide-agente``...). Nothing of it moves or changes owner.
- The **number** (1 to 99, in the agent's file) gives every other agent ids of its own: 61100 + n
  and, for its proxy, 61200 + n. If an agent got out of its jail, the files of the others would be
  someone else's. The number outlives the agent's deletion (T26-6c) so its ids are not reused,
  which is why it can pass ``MAX_AGENTS``. The web's narrow socket refuses the whole range, and
  ``backtide comprobar`` warns if an account already uses part of it.
"""

import re

MAIN_SLUG = "principal"
SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
MAX_NAME = 48  # the name to show (the web's limit), never a Docker name nor a path
MAX_AGENTS = 8  # the main one included (decision 15 of docs/47)
MAX_NUMBER = 99

# Names no agent may take, now that a slug is for good:
RESERVED_SLUGS = frozenset(
    {
        MAIN_SLUG,  # the installation's first agent, which has no file
        "agente",  # backtide-agente-net, the main agent's network
        "salida",  # backtide-salida-net, its proxy's way out
        "instalacion",  # the installation's own black box, in the web and the CLI
        "installation",
        "nuevo",  # /agentes/nuevo, where the web creates one (T26-6b)
        "new",
        "todos",  # --agente todos, in the CLI (T26-2c)
        "all",
    }
)

AGENT_ID_BASE = 61100
PROXY_ID_BASE = 61200
# Everything the other agents and their proxies may ever run as, uids and gids alike.
AGENT_ID_RANGE = range(AGENT_ID_BASE, PROXY_ID_BASE + MAX_NUMBER + 1)


class SlugError(ValueError):
    """Not a slug an agent may have. The message says why."""


def check_slug(slug: object) -> str:
    """``slug`` if an agent other than the main one may have it; SlugError otherwise."""
    if not isinstance(slug, str) or not SLUG.fullmatch(slug):
        raise SlugError(f"an agent's slug must match {SLUG.pattern}, got {slug!r}")
    if slug in RESERVED_SLUGS:
        raise SlugError(f"the slug {slug!r} is reserved")
    return slug


def agent_id(number: int) -> int:
    """The uid and gid of agent number ``number``."""
    return AGENT_ID_BASE + number


def proxy_id(number: int) -> int:
    """The uid and gid of its proxy."""
    return PROXY_ID_BASE + number


def agent_container(slug: str) -> str:
    return f"backtide-{slug}-agente"


def proxy_container(slug: str) -> str:
    return f"backtide-{slug}-egress"


def agent_network(slug: str) -> str:
    """The internal network the agent and its proxy share."""
    return f"backtide-{slug}-net"


def egress_network(slug: str) -> str:
    """The proxy's way out."""
    return f"backtide-{slug}-salida"
