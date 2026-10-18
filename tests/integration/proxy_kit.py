"""The egress proxy of a VM test service, with the concessions only the tests get (docs/21, "En
la VM"): the test user's ids (no root), an internal egress network (nothing reaches the
internet), the channel folder on the disk (mounting its tmpfs needs root) and a copy of
backtide's package (the repository is a Lima mount, which SELinux's ``:z`` cannot relabel).

Every launcher of a test service (service_main, pause_main, rewind_main, guardian_in_process)
hands ``test_proxy(config)`` to the real ``serve``/``build_guardian``.
"""

import json
import shutil
from dataclasses import replace
from pathlib import Path

from backtide.jail import JailError, proxy_config
from backtide.jail.proxy import ProxyJail
from backtide.service.config import ServiceConfig


def package_copy(config: ServiceConfig) -> Path:
    """A copy of backtide's package next to the state folder, made once per state folder."""
    package = config.state_dir.parent / f"{config.state_dir.name}-code" / "backtide"
    if not package.exists():
        package.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copytree(
            proxy_config.PACKAGE_DIR,
            package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    return package


def test_proxy(config: ServiceConfig, **grants: object) -> ProxyJail:
    """The production proxy of ``config``, with the tests' concessions (and ``grants``)."""
    settings = replace(
        config.proxy_jail_config(),
        package_dir=package_copy(config),
        internal_egress=True,
        allow_shared_ids=True,
        channel_tmpfs=False,
        **grants,  # type: ignore[arg-type]
    )
    return ProxyJail(settings)


test_proxy.__test__ = False  # type: ignore[attr-defined] - a helper, whatever its name says


def remove_proxy(config: ServiceConfig) -> list[JailError]:
    """Remove the proxy's container and its egress network; the errors, not raised."""
    jail = ProxyJail(config.proxy_jail_config())
    errors = []
    for step in (jail.remove, jail.remove_network):
        try:
            step()
        except JailError as error:
            errors.append(error)
    return errors


def read_grants(path: Path) -> dict[str, object]:
    """The proxy's test grants written by internet_kit (``--egress-grants``): the fake internet
    as the one neighbour on the egress network, its address counted as public, and its CA."""
    data = json.loads(path.read_text())
    return {
        "egress_neighbours": tuple(data["egress_neighbours"]),
        "test_public_addresses": tuple(data["test_public_addresses"]),
        "test_upstream_ca": data["test_upstream_ca"],
    }
