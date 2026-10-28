"""The images an installed backtide runs, pulled by digest (docs/25, section 4, step 4).

Each version of backtide pins its own: the agent's (OpenClaw by default, or Claude Code with
``backtide instalar --perfil claude-code``: D27), the proxy's (mitmproxy) and the process
sensor's (Tetragon), each ``name[:tag]@sha256:<digest>`` in the module that uses it. This is the
only list of them (``backtide imagenes`` prints it), so no script copies a digest. An install
pulls the proxy's, the sensor's and the one agent its profile runs (``pinned``).

``pull`` asks Docker for the image by its digest and then checks that what Docker holds answers
to that digest (``RepoDigests``). An image that is already there is not pulled again.
"""

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from backtide.jail import IMAGE as OPENCLAW_IMAGE
from backtide.jail import proxy_config
from backtide.jail import sensor as sensor_jail
from backtide.jail.docker import sanitize
from backtide.jail.profiles import CLAUDE_CODE, OPENCLAW
from backtide.setup.host import Ran, Runner

PULL_ATTEMPTS = 3
PULL_PAUSE = 15.0  # seconds before trying again: Docker Hub limits anonymous pulls
_PINNED = re.compile(
    r"(?P<repo>[a-z0-9./_-]+)(?::[A-Za-z0-9._-]+)?@(?P<digest>sha256:[0-9a-f]{64})"
)


class ImageError(Exception):
    """An image could not be pulled or is not the pinned one (in Spanish)."""


@dataclass(frozen=True)
class Image:
    role: str  # who runs it, for the person
    ref: str  # name[:tag]@sha256:...
    approx_mib: int  # unpacked, measured (T13-1; Claude Code's in T17a-1, docs/34)

    @property
    def repo(self) -> str:
        return _parse(self.ref)[0]

    @property
    def digest(self) -> str:
        return _parse(self.ref)[1]

    @property
    def approx_size(self) -> str:
        return size_text(self.approx_mib)


# The agents an install can run, by their [agent] profile (D27): OpenClaw is the default.
AGENTS = {
    OPENCLAW.name: Image("el agente (OpenClaw)", OPENCLAW_IMAGE, 4813),
    CLAUDE_CODE.name: Image("el agente (Claude Code)", CLAUDE_CODE.image, 2729),
}
DEFAULT_AGENT = OPENCLAW.name
_SERVICES = (
    Image("el proxy de salida (mitmproxy)", proxy_config.IMAGE, 382),
    Image("el sensor de procesos (Tetragon)", sensor_jail.IMAGE, 351),
)


def pinned(profile: str = DEFAULT_AGENT) -> tuple[Image, ...]:
    """What an install with ``profile`` pulls: its agent's image (none for a profile the
    installer does not know, such as ``custom``), the proxy's and the sensor's."""
    agent = AGENTS.get(profile)
    return ((agent,) if agent is not None else ()) + _SERVICES


def every() -> tuple[Image, ...]:
    """Every image this version pins: each agent's, the proxy's and the sensor's."""
    return (*AGENTS.values(), *_SERVICES)


def listing() -> str:
    """What `backtide imagenes` prints: one image a line."""
    return "\n".join(f"{image.ref}  # {image.role}, {image.approx_size}" for image in every())


def size_text(mib: int) -> str:
    """``4,7 GiB`` or ``382 MiB``, as the person reads it (a decimal comma)."""
    if mib < 1024:
        return f"{mib} MiB"
    return f"{mib / 1024:.1f} GiB".replace(".", ",")


def approx_total(refs: list[str]) -> str:
    """About how much ``refs`` hold on disk, from the pinned images among them."""
    known = {image.ref: image.approx_mib for image in every()}
    return size_text(sum(known.get(ref, 0) for ref in refs))


def inspect_argv(image: Image) -> tuple[str, ...]:
    return ("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image.ref)


def pull_argv(image: Image) -> tuple[str, ...]:
    return ("docker", "pull", "--quiet", image.ref)


def is_present(image: Image, *, run: Runner) -> bool:
    """Docker holds this image AND it answers to the pinned digest."""
    return _holds_digest(image, run(inspect_argv(image)))


def pull(
    image: Image,
    *,
    run: Runner,
    run_long: Runner,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Make sure Docker has ``image``; True if it had to pull it. Tries PULL_ATTEMPTS times."""
    if is_present(image, run=run):
        return False
    last: Ran | None = None
    for attempt in range(PULL_ATTEMPTS):
        if attempt:
            sleep(PULL_PAUSE * attempt)
        last = run_long(pull_argv(image))
        if last is not None and last.returncode == 0:
            break
    else:
        detail = "" if last is None else sanitize((last.stderr or last.stdout).strip(), 300)
        raise ImageError(
            f"no se pudo descargar la imagen de {image.role} ({image.ref}) tras "
            f"{PULL_ATTEMPTS} intentos: {detail or 'docker no está instalado'}"
        )
    if not is_present(image, run=run):
        raise ImageError(
            f"Docker descargó {image.ref} pero no responde a su digest: no se usa. Bórrala "
            f"(`docker image rm {image.ref}`) y vuelve a instalar."
        )
    return True


def by_digest(ref: str) -> str:
    """``repo:tag@sha256:...`` as ``repo@sha256:...``: how Docker names a pulled digest."""
    repo, digest = _parse(ref)
    return f"{repo}@{digest}"


def _holds_digest(image: Image, ran: Ran | None) -> bool:
    if ran is None or ran.returncode != 0:
        return False
    try:
        digests = json.loads(ran.stdout)
    except ValueError:
        return False
    if not isinstance(digests, list):
        return False
    return f"{image.repo}@{image.digest}" in {str(item) for item in digests}


def _parse(ref: str) -> tuple[str, str]:
    match = _PINNED.fullmatch(ref)
    if match is None:
        raise ValueError(f"{ref!r} is not pinned by digest")
    return match["repo"], match["digest"]
