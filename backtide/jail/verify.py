"""Is an existing container exactly the jail its config describes? Pure: no Docker, no disk.

Docker reads every option, the seccomp profile included, when it creates a container, and
``docker start`` runs whatever was created. A container left by an older backtide (another image,
an older seccomp profile) or made by hand under the same name (a ``--privileged`` debug shell,
a ``docker.sock`` mount) would otherwise be started as if it were the jail. So AgentJail.start()
compares ``docker container inspect`` with what docker_create_argv asks for, field by field,
and refuses any difference: such a container must be removed and created again. What it
expects of the image, the command and the variables comes from the config's agent profile;
every other rule here is the same for every agent (docs/34, section 6).

The egress proxy (proxy.py) gets the same treatment from proxy_container_problems. Neither
container may have a DNS server of its own: with ``--dns``, Docker forwards outside names even
from an internal network (docs/21, T06-1 P5), which would be a way out for the agent.

The process sensor (sensor.py) gets it from sensor_container_problems: it is privileged on
purpose, so what is checked there is that it has nothing else (docs/23, section 2).
"""

import json
from pathlib import PurePosixPath
from typing import Any

from backtide.jail import proxy_config
from backtide.jail import sensor as sensor_jail
from backtide.jail.config import (
    LOG_DRIVER,
    LOG_OPTIONS,
    NO_NEW_PRIVILEGES,
    PROXY_ALIAS,
    AgentJailConfig,
    container_env,
    memory_bytes,
    nano_cpus,
    tmpfs_mounts,
    token_env,
    volume_binds,
)
from backtide.jail.proxy_config import ProxyJailConfig
from backtide.jail.sensor import SensorJailConfig

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
    one of them (and the profile's fake keys)."""
    created = _section(info, "Config")
    host = _section(info, "HostConfig")
    problems = _config_problems(config, created)
    problems += _host_problems(config, host, seccomp_profile)
    problems += _env_problems(config, created.get("Env"), image_env)
    problems += _dns_problems(host)
    networks = _section(info, "NetworkSettings").get("Networks") or {}
    if host.get("NetworkMode") != config.network or list(networks) != [config.network]:
        problems.append(
            f"its networks are {host.get('NetworkMode')!r} / {sorted(networks)}, "
            f"not only {config.network!r}"
        )
    return problems


def proxy_container_problems(
    config: ProxyJailConfig, info: dict[str, Any], *, image_env: list[str]
) -> list[str]:
    """What differs between ``info`` (``docker container inspect``) and the egress proxy of
    ``config`` (proxy_config.proxy_create_argv); empty when they match. ``image_env`` is the
    image's own environment."""
    created = _section(info, "Config")
    host = _section(info, "HostConfig")
    expected = {
        "Image": config.image,
        "User": f"{config.uid}:{config.gid}",
        "Entrypoint": [proxy_config.ENTRYPOINT],
        "Cmd": list(proxy_config.COMMAND),
        "StopTimeout": config.stop_timeout,
    }
    problems = _differences("", created, expected)
    problems += _proxy_host_problems(config, host)
    problems += _proxy_env_problems(config, created.get("Env"), image_env)
    if config.test_dns:
        # The VM tests' fake resolver (T06-7): exactly the granted one, and nothing else.
        if list(host.get("Dns") or []) != list(config.test_dns):
            problems.append(f"HostConfig.Dns is {host.get('Dns')!r}, not the test resolver")
        problems += _dns_problems({**host, "Dns": None})
    else:
        problems += _dns_problems(host)
    problems += _volume_problems(info)
    problems += _proxy_runtime_problems(created, host)
    problems += _proxy_network_problems(config, info)
    return problems


def _proxy_runtime_problems(created: dict[str, Any], host: dict[str, Any]) -> list[str]:
    """Docker's own runtime and cgroup, no healthcheck command run inside it, and Docker's
    masks of /proc and /sys left in place (the API can empty them without any SecurityOpt)."""
    problems = []
    if host.get("Runtime") not in (None, "", "runc"):
        problems.append(f"HostConfig.Runtime is {host.get('Runtime')!r}, not runc")
    if host.get("CgroupParent"):
        problems.append(f"HostConfig.CgroupParent is set: {host['CgroupParent']!r}")
    if created.get("Healthcheck"):
        problems.append("Config.Healthcheck is set: nothing may run in the proxy but the gate")
    for name in ("MaskedPaths", "ReadonlyPaths"):
        if not host.get(name):
            problems.append(f"HostConfig.{name} is empty: Docker's masks of /proc are gone")
    return problems


def _volume_problems(info: dict[str, Any]) -> list[str]:
    """No Docker volume at all: an image's ``VOLUME`` would add a writable, lasting one that no
    option asked for (the mitmproxy image declares one; proxy_config covers it with a tmpfs)."""
    mounts = info.get("Mounts") or []
    volumes = sorted(
        str(mount.get("Destination"))
        for mount in (mounts if isinstance(mounts, list) else [])
        if isinstance(mount, dict) and mount.get("Type") == "volume"
    )
    return [f"it has Docker volumes at {volumes}"] if volumes else []


def _dns_problems(host: dict[str, Any]) -> list[str]:
    """No DNS server, search domain or option of its own: Docker's embedded resolver only."""
    return [
        f"HostConfig.{name} is set: {host[name]!r}"
        for name in ("Dns", "DnsOptions", "DnsSearch")
        if host.get(name)
    ]


def _proxy_host_problems(config: ProxyJailConfig, host: dict[str, Any]) -> list[str]:
    memory = memory_bytes(config.memory)
    expected = {
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Tmpfs": proxy_config.tmpfs_mounts(config),
        "RestartPolicy.Name": "no",
        "Memory": memory,
        "MemorySwap": memory,
        "PidsLimit": config.pids_limit,
        "NanoCpus": nano_cpus(config.cpus),
        "LogConfig": {"Type": LOG_DRIVER, "Config": LOG_OPTIONS},
        "CgroupnsMode": "private",
        "Sysctls": proxy_config.SYSCTLS,  # forwarding off, and nothing else
        "Ulimits": proxy_config.ulimits(config),
    }
    actual = dict(host)
    actual["RestartPolicy.Name"] = (host.get("RestartPolicy") or {}).get("Name")
    problems = _differences("HostConfig.", actual, expected)
    problems += [
        f"HostConfig.{name} is set: {host[name]!r}"
        for name in _MUST_BE_EMPTY
        if name != "Sysctls" and host.get(name)
    ]
    if host.get("IpcMode") not in _ISOLATED_IPC:
        problems.append(f"HostConfig.IpcMode is {host.get('IpcMode')!r}, not private")
    binds = proxy_config.volume_binds(config)
    if sorted(host.get("Binds") or []) != sorted(binds):
        problems.append(f"its mounts are {host.get('Binds')!r}, not {binds!r}")
    # Docker's default seccomp profile: no seccomp= option at all, and nothing else either.
    options = sorted(host.get("SecurityOpt") or [])
    if options != [NO_NEW_PRIVILEGES]:
        problems.append(f"its security options are {options!r}, not [{NO_NEW_PRIVILEGES!r}]")
    return problems


def _proxy_env_problems(config: ProxyJailConfig, env: object, image_env: list[str]) -> list[str]:
    """The image's variables, overridden by the proxy's: nothing more or less (no key ever).
    Only names are reported."""
    expected = _env_dict(image_env) | dict(proxy_config.proxy_env(config))
    actual = _env_dict(env if isinstance(env, list) else [])
    differing = sorted(
        name for name in expected.keys() | actual.keys() if expected.get(name) != actual.get(name)
    )
    return [f"its environment differs in {differing}"] if differing else []


def _proxy_network_problems(config: ProxyJailConfig, info: dict[str, Any]) -> list[str]:
    """On exactly the agent's network (with the alias the agent looks for) and the egress one."""
    networks = _section(info, "NetworkSettings").get("Networks") or {}
    wanted = {config.agent_network, config.network}
    mode = _section(info, "HostConfig").get("NetworkMode")
    if not isinstance(networks, dict) or set(networks) != wanted or mode not in wanted:
        return [f"its networks are {mode!r} / {sorted(networks)}, not {sorted(wanted)}"]
    agent_side = networks[config.agent_network] or {}
    if PROXY_ALIAS not in (agent_side.get("Aliases") or []):
        return [f"it has no alias {PROXY_ALIAS!r} on {config.agent_network!r}"]
    return []


def _config_problems(config: AgentJailConfig, created: dict[str, Any]) -> list[str]:
    profile = config.profile
    expected = {
        "Image": config.image,
        "User": f"{config.uid}:{config.gid}",
        "Hostname": config.hostname,
        "Entrypoint": [profile.entrypoint],
        "Cmd": list(profile.command),
        "StopTimeout": config.stop_timeout,
    }
    if profile.workdir is not None:
        expected["WorkingDir"] = str(profile.workdir)
    # An entrypoint without a command: docker keeps no Cmd at all (null), the same as [].
    problems = [
        f"{name} is {created.get(name)!r}, not {value!r}"
        for name, value in expected.items()
        if (created.get(name) or [] if name == "Cmd" else created.get(name)) != value
    ]
    healthcheck = created.get("Healthcheck")
    if healthcheck and not (isinstance(healthcheck, dict) and healthcheck.get("Test") == ["NONE"]):
        # The image's HEALTHCHECK runs a command of its own in the agent's container every few
        # seconds; docker_create_argv turns it off (--no-healthcheck).
        problems.append("Config.Healthcheck is set: only the agent runs in its container")
    if profile.workdir is None:
        problems += _working_dir_problems(created.get("WorkingDir"))
    return problems


# ``--no-healthcheck`` leaves ``Config.Healthcheck.Test`` as ["NONE"] (and keeps the image's
# intervals beside it, which then mean nothing: measured in the VM with OpenClaw's image).
# Where an image's WORKDIR may never put the agent: the kernel's views, not a folder of files.
_KERNEL_TREES = ("proc", "sys", "dev")


def _working_dir_problems(working_dir: object) -> list[str]:
    """The image's own WORKDIR (a profile without ``workdir`` keeps it): a plain absolute path
    outside /proc, /sys and /dev (``/proc/self/root``, ``/proc/1/cwd`` are other trees). Empty
    or missing: Docker's ``/``."""
    if working_dir in (None, ""):
        return []
    path = PurePosixPath(str(working_dir))
    if (
        not isinstance(working_dir, str)
        or not path.is_absolute()
        or ".." in path.parts
        or (len(path.parts) > 1 and path.parts[1] in _KERNEL_TREES)
    ):
        return [f"Config.WorkingDir is {str(working_dir)[:200]!r}: not a plain folder"]
    return []


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
    # Docker's own runtime and cgroup, as for the proxy (_proxy_runtime_problems). The masks of
    # /proc and /sys are mounts.py's (exposure_problems).
    if host.get("Runtime") not in (None, "", "runc"):
        problems.append(f"HostConfig.Runtime is {host.get('Runtime')!r}, not runc")
    if host.get("CgroupParent"):
        problems.append(f"HostConfig.CgroupParent is set: {host['CgroupParent']!r}")
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
    """The image's variables, overridden by the jail's and those of token_env (the token, the
    profile's fake keys): nothing more or less. Only names are reported."""
    expected = _env_dict(image_env) | dict(container_env(config)) | token_env(config)
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


# --- the process sensor (docs/23, section 2) ------------------------------------------------

# The daemon adds this one by itself to a privileged container on an SELinux host (and nothing
# on other hosts): it changes nothing for a container that already runs unconfined.
_SENSOR_SECURITY_OPTIONS = ([], ["label=disable"])
# The agent's list minus what the sensor needs on purpose: privileged, the host's PID space.
_SENSOR_MUST_BE_EMPTY = tuple(
    name for name in _MUST_BE_EMPTY if name not in ("Privileged", "PidMode")
)


def sensor_container_problems(
    config: SensorJailConfig, info: dict[str, Any], *, image_env: list[str]
) -> list[str]:
    """What differs between ``info`` (``docker container inspect``) and the sensor of
    ``config`` (sensor.sensor_create_argv); empty when they match. ``image_env`` is the image's
    own environment: backtide adds none. Never quotes an environment value."""
    created = _section(info, "Config")
    host = _section(info, "HostConfig")
    expected_config = {
        "Image": config.image,
        "User": "",  # Tetragon runs as root, as the image says
        "Entrypoint": [sensor_jail.ENTRYPOINT],
        "StopTimeout": config.stop_timeout,
    }
    problems = _differences("", created, expected_config)
    if created.get("Cmd"):
        problems.append(f"Cmd is {created.get('Cmd')!r}, not empty")
    if created.get("Healthcheck"):  # it would run a command inside a privileged container
        problems.append(f"Healthcheck is {created.get('Healthcheck')!r}, not none")
    problems += _sensor_host_problems(config, host)
    # The binds and nothing more: no anonymous volume (an image's VOLUME) or other mount.
    mounts = info.get("Mounts")
    if (
        not isinstance(mounts, list)
        or len(mounts) != len(sensor_jail.volume_binds(config))
        or any(not isinstance(m, dict) or m.get("Type") != "bind" for m in mounts)
    ):
        problems.append(f"its mounts are {mounts!r:.300}, not only its binds")
    actual_env = _env_dict(created.get("Env") if isinstance(created.get("Env"), list) else [])
    expected_env = _env_dict(list(image_env))
    differing = sorted(
        name
        for name in expected_env.keys() | actual_env.keys()
        if expected_env.get(name) != actual_env.get(name)
    )
    if differing:
        problems.append(f"its environment differs in {differing}")
    problems += _dns_problems(host)
    networks = _section(info, "NetworkSettings").get("Networks") or {}
    if host.get("NetworkMode") != sensor_jail.NETWORK or list(networks) != [sensor_jail.NETWORK]:
        problems.append(
            f"its networks are {host.get('NetworkMode')!r} / {sorted(networks)}, "
            f"not only {sensor_jail.NETWORK!r}"
        )
    return problems


def _sensor_host_problems(config: SensorJailConfig, host: dict[str, Any]) -> list[str]:
    memory = memory_bytes(config.memory)
    expected = {
        "Privileged": True,
        "PidMode": "host",
        "CgroupnsMode": "host",
        "RestartPolicy.Name": "no",
        "Memory": memory,
        "MemorySwap": memory,
        "NanoCpus": nano_cpus(config.cpus),
        "LogConfig": {"Type": sensor_jail.LOG_DRIVER, "Config": sensor_jail.LOG_OPTIONS},
    }
    actual = dict(host)
    actual["RestartPolicy.Name"] = (host.get("RestartPolicy") or {}).get("Name")
    problems = _differences("HostConfig.", actual, expected)
    problems += [
        f"HostConfig.{name} is set: {host[name]!r}"
        for name in (*_SENSOR_MUST_BE_EMPTY, "CapDrop", "Tmpfs")
        if host.get(name)
    ]
    if host.get("IpcMode") not in _ISOLATED_IPC:
        problems.append(f"HostConfig.IpcMode is {host.get('IpcMode')!r}, not private")
    binds = sensor_jail.volume_binds(config)
    if sorted(host.get("Binds") or []) != sorted(binds):
        problems.append(f"its mounts are {host.get('Binds')!r}, not {binds!r}")
    options = sorted(host.get("SecurityOpt") or [])
    if options not in _SENSOR_SECURITY_OPTIONS:
        problems.append(f"its security options are {options!r}, not none")
    if host.get("Runtime") not in (None, "", "runc"):
        problems.append(f"HostConfig.Runtime is {host.get('Runtime')!r}, not runc")
    if host.get("CgroupParent"):
        problems.append(f"HostConfig.CgroupParent is set: {host.get('CgroupParent')!r}")
    return problems
