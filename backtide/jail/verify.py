"""Is an existing container exactly the jail its config describes? Pure: no Docker, no disk.

Docker reads every option, the seccomp profile included, when it creates a container, and
``docker start`` runs whatever was created. A container left by an older backtide (another image,
an older seccomp profile) or made by hand under the same name (a ``--privileged`` debug shell,
a ``docker.sock`` mount) would otherwise be started as if it were the jail. So AgentJail.start()
compares ``docker container inspect`` with what docker_create_argv asks for, field by field,
and refuses any difference: such a container must be removed and created again.
"""

import json
from typing import Any

from backtide.jail.config import (
    COMMAND,
    ENTRYPOINT,
    LOG_DRIVER,
    LOG_OPTIONS,
    NO_NEW_PRIVILEGES,
    TOKEN_ENV,
    AgentJailConfig,
    container_env,
    memory_bytes,
    nano_cpus,
    tmpfs_mounts,
    volume_binds,
)

_SECCOMP_PREFIX = "seccomp="
# Docker's own isolation for these namespaces: anything else shares one with the host or with
# another container.
_ISOLATED_IPC = {"private", "shareable"}
# Options that would open a hole when set at all. Each must be empty, false or missing.
_MUST_BE_EMPTY = (
    "Privileged",
    "CapAdd",
    "Mounts",
    "VolumesFrom",
    "VolumeDriver",
    "PortBindings",
    "PublishAllPorts",
    "ExtraHosts",
    "Links",
    "Devices",
    "DeviceCgroupRules",
    "DeviceRequests",
    "GroupAdd",
    "Sysctls",
    "OomKillDisable",
    "PidMode",
    "UTSMode",
    "UsernsMode",
    "Cgroup",
)


def container_problems(
    config: AgentJailConfig,
    info: dict[str, Any],
    *,
    seccomp_profile: object,
    image_env: list[str],
) -> list[str]:
    """What differs between ``info`` (``docker container inspect``) and the jail of ``config``;
    empty when they match. ``seccomp_profile`` is the parsed JSON of config.seccomp_profile and
    ``image_env`` the image's own environment. Never quotes an environment value: the token is
    one of them."""
    created = _section(info, "Config")
    host = _section(info, "HostConfig")
    problems = _config_problems(config, created)
    problems += _host_problems(config, host, seccomp_profile)
    problems += _env_problems(config, created.get("Env"), image_env)
    networks = _section(info, "NetworkSettings").get("Networks") or {}
    if host.get("NetworkMode") != config.network or list(networks) != [config.network]:
        problems.append(
            f"its networks are {host.get('NetworkMode')!r} / {sorted(networks)}, "
            f"not only {config.network!r}"
        )
    return problems


def _config_problems(config: AgentJailConfig, created: dict[str, Any]) -> list[str]:
    expected = {
        "Image": config.image,
        "User": f"{config.uid}:{config.gid}",
        "Hostname": config.hostname,
        "Entrypoint": [ENTRYPOINT],
        "Cmd": list(COMMAND),
        "StopTimeout": config.stop_timeout,
    }
    return _differences("", created, expected)


def _host_problems(
    config: AgentJailConfig, host: dict[str, Any], seccomp_profile: object
) -> list[str]:
    memory = memory_bytes(config.memory)
    expected = {
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Tmpfs": tmpfs_mounts(config),  # /tmp and the /sys masks, exactly
        "RestartPolicy.Name": "no",
        "Memory": memory,
        "MemorySwap": memory,
        "PidsLimit": config.pids_limit,
        "NanoCpus": nano_cpus(config.cpus),
        "LogConfig": {"Type": LOG_DRIVER, "Config": LOG_OPTIONS},
        "CgroupnsMode": "private",
    }
    actual = dict(host)
    actual["RestartPolicy.Name"] = (host.get("RestartPolicy") or {}).get("Name")
    problems = _differences("HostConfig.", actual, expected)
    problems += [
        f"HostConfig.{name} is set: {host[name]!r}" for name in _MUST_BE_EMPTY if host.get(name)
    ]
    if host.get("IpcMode") not in _ISOLATED_IPC:
        problems.append(f"HostConfig.IpcMode is {host.get('IpcMode')!r}, not private")
    if sorted(host.get("Binds") or []) != sorted(volume_binds(config)):
        problems.append(f"its mounts are {host.get('Binds')!r}, not {volume_binds(config)!r}")
    problems += _security_opt_problems(host.get("SecurityOpt") or [], seccomp_profile)
    return problems


def _security_opt_problems(options: list[str], seccomp_profile: object) -> list[str]:
    """Exactly no-new-privileges and the current seccomp profile: nothing else (no
    ``seccomp=unconfined``, ``label=disable``, ``apparmor=unconfined`` or ``systempaths``)."""
    seccomp = [option for option in options if option.startswith(_SECCOMP_PREFIX)]
    others = sorted(option for option in options if not option.startswith(_SECCOMP_PREFIX))
    problems = []
    if others != [NO_NEW_PRIVILEGES]:
        problems.append(f"its security options are {others!r}, not [{NO_NEW_PRIVILEGES!r}]")
    if len(seccomp) != 1 or _json_or_none(seccomp[0].removeprefix(_SECCOMP_PREFIX)) != (
        seccomp_profile
    ):
        problems.append("its seccomp profile is not the current one")
    return problems


def _env_problems(config: AgentJailConfig, env: object, image_env: list[str]) -> list[str]:
    """The image's variables, overridden by the jail's and the token: nothing more or less.
    Only names are reported."""
    expected = _env_dict(image_env) | dict(container_env(config))
    expected[TOKEN_ENV] = config.gateway_token
    actual = _env_dict(env if isinstance(env, list) else [])
    differing = sorted(
        name for name in expected.keys() | actual.keys() if expected.get(name) != actual.get(name)
    )
    return [f"its environment differs in {differing}"] if differing else []


def _differences(prefix: str, actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    return [
        f"{prefix}{name} is {actual.get(name)!r}, not {value!r}"
        for name, value in expected.items()
        if actual.get(name) != value
    ]


def _section(info: dict[str, Any], name: str) -> dict[str, Any]:
    value = info.get(name)
    return value if isinstance(value, dict) else {}


def _env_dict(entries: list[object]) -> dict[str, str]:
    pairs = (entry.split("=", 1) for entry in entries if isinstance(entry, str))
    return {pair[0]: pair[1] if len(pair) == 2 else "" for pair in pairs}


def _json_or_none(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None
