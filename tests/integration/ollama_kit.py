"""The fake Ollama of a VM test service (T20-3, docs/35 section 7): ``fake_ollama.py`` of
``proxy_fixtures``, in a hardened container on the service's own egress network, beside the
fake internet. Its address is private and is never granted as public (``test_public_addresses``):
the proxy may only reach it as a local provider, at the fixed address backtide resolved.
Nothing real is contacted (invariant 8): it is ours, it answers like Ollama and it records what
reaches it.

    internet = start_fake_internet(service, root)       # makes the egress network
    ollama = start_fake_ollama(service.config, root)    # its neighbour there
    point_local_provider(service, PLACEHOLDER, ollama.ip)
    service.main_args = with_neighbour(internet, ollama, root)
    ...
    ollama.remove()                                     # before the service's cleanup

T20-5's scenario (``modelo-local-como-trampolin``) reuses it: the decoy ports (22, 8080) and the
requests it saw are what says whether the local provider was a springboard.
"""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from backtide.jail import docker as jail_docker
from backtide.jail import proxy_config
from backtide.service.config import ServiceConfig
from tests.integration.internet_kit import GRANTS_OPTION, FakeInternet
from tests.integration.service_kit import Service
from tests.integration.test_proxy_assumptions import (
    FIXTURES,
    hardened,
    ip_on,
    unique,
    wait_for_line,
)

OLLAMA_UID = 61003
CONTAINER_PREFIX = "backtide-test-agent-"  # under the cleanup's prefixes (conftest)
READY_LINE = "t20-ollama-ready"  # proxy_fixtures/fake_ollama.py
REPLY_TEXT = "T20 PONG FROM THE FAKE OLLAMA"
MODEL = "t20-fake-coder:7b"
PORT = 11434
DECOYS = (22, 8080)
# A private address no test network uses: written in the config first, then replaced by the fake
# Ollama's own (known only once it runs on the egress network that the service's config names).
PLACEHOLDER = "10.255.255.20"
STATS = (
    "import sys, urllib.request; "
    "sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:9000/stats', timeout=10)"
    ".read().decode())"
)


@dataclass
class FakeOllama:
    name: str
    ip: str

    def stats(self) -> dict:
        done = jail_docker.run(["exec", self.name, "python3", "-c", STATS], timeout=30)
        return json.loads(done.stdout)

    def requests(self, path_prefix: str = "") -> list[dict]:
        return [r for r in self.stats()["requests"] if r["path"].startswith(path_prefix)]

    def accepts(self) -> dict[str, int]:
        return self.stats()["accepts"]

    def remove(self) -> None:
        jail_docker.run(["rm", "--force", "--volumes", self.name], check=False)


def local_provider_toml(name: str, address: str = PLACEHOLDER, kind: str = "openai") -> str:
    """A ``[[proxy.providers]]`` table for a local provider at ``address``."""
    return (
        f'[[proxy.providers]]\nname = "{name}"\nkind = "{kind}"\n'
        f'local = "http://{address}:{PORT}"\nmodels = ["{MODEL}"]\n'
    )


def start_fake_ollama(config: ServiceConfig, root: Path) -> FakeOllama:
    """Start the fake Ollama on the egress network of ``config``, which the fake internet's kit
    made already (``start_fake_internet``)."""
    files = root / "t20"
    files.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / "fake_ollama.py", files / "fake_ollama.py")
    (files / "fake_ollama.py").chmod(0o444)
    files.chmod(0o555)
    network = config.proxy_jail_config().network  # made by the fake internet's kit
    name = unique(CONTAINER_PREFIX)
    argv = hardened(name, OLLAMA_UID) + ["--network", network]
    argv += [
        "--volume", f"{files}:/opt/t20:ro,z",
        "--entrypoint", "python3", proxy_config.IMAGE, "/opt/t20/fake_ollama.py",
    ]  # fmt: skip
    jail_docker.run(argv)
    fake = FakeOllama(name, "")
    try:
        jail_docker.run(["start", name])
        wait_for_line(name, READY_LINE)
        fake.ip = ip_on(name, network)
    except BaseException:
        fake.remove()
        raise
    return fake


def point_local_provider(service: Service, placeholder: str, address: str) -> None:
    """Write the fake Ollama's address where the config had ``placeholder``, and read it again."""
    text = service.config_path.read_text()
    assert placeholder in text, "the local provider's placeholder is not in the config"
    service.config_path.write_text(text.replace(placeholder, address))
    service.config = ServiceConfig.from_file(service.config_path)


def with_neighbour(internet: FakeInternet, ollama: FakeOllama, root: Path) -> tuple[str, ...]:
    """The fake internet's grants with the fake Ollama as one more neighbour on the egress
    network. Its address is NOT added to the ones counted as public."""
    grants = json.loads(internet.grants_file.read_text())
    grants["egress_neighbours"] = [*grants["egress_neighbours"], ollama.name]
    assert ollama.ip not in grants["test_public_addresses"]
    path = root / "grants-t20.json"
    path.write_text(json.dumps(grants))
    path.chmod(0o600)
    return (GRANTS_OPTION, str(path))
