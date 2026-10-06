"""The agent's seccomp profile: Docker's default plus a block on the Btrfs ioctls (type 0x94).

Why: an unprivileged owner can create Btrfs subvolumes with an ioctl, and a nested subvolume
inside the workspace breaks snapshots and rewinds (docs/10, "Notas para tareas posteriores").
FICLONE, FICLONERANGE and FIDEDUPERANGE share the 0x94 type, so they are blocked too; callers
like ``cp --reflink=auto``, libuv and OpenClaw's plugin loader fall back to a plain copy.

How, and why not the obvious way: Docker's default profile allows ``ioctl`` with no condition.
libseccomp drops a conditional rule for a syscall that already has an unconditional one (and
the other way round, the unconditional rule wipes the conditional ones), so simply appending
an ERRNO rule for 0x94 would be silently ignored. Instead ``ioctl`` is taken out of the
unconditional list and replaced by rules that never overlap:

- 8 ALLOW rules, one per bit of the type byte (bits 8 to 15 of the request): "this bit differs
  from the same bit of 0x94". Any type other than 0x94 differs in at least one bit.
- 1 ERRNO rule: "the type byte is 0x94", returning ``BLOCKED_ERRNO``.

Exactly one rule matches any request, so the order libseccomp evaluates them in cannot change
the result. The upper 32 bits of the request are masked out, as the kernel ignores them too.

Regenerate ``deploy/seccomp/agent.json`` with ``deploy/seccomp/regenerate.sh``.
"""

import argparse
import copy
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

IOCTL = "ioctl"
IOCTL_REQUEST_ARG = 1  # ioctl(fd, request, argp)
BTRFS_IOCTL_TYPE = 0x94  # BTRFS_IOCTL_MAGIC, also used by FICLONE/FICLONERANGE/FIDEDUPERANGE
IOCTL_TYPE_SHIFT = 8  # _IOC: dir << 30 | size << 16 | type << 8 | nr
IOCTL_TYPE_MASK = 0xFF << IOCTL_TYPE_SHIFT
# EOPNOTSUPP, "Operation not supported": what the kernel returns for FICLONE on a filesystem
# that cannot clone, so every copier that supports such filesystems falls back (checked in the
# VM: cp --reflink=auto and libuv's copyfile). A Linux number, written out: Python's errno
# module gives the HOST's value, and on macOS EOPNOTSUPP is 102 (ENETRESET on Linux).
BLOCKED_ERRNO = 95
ALLOW = "SCMP_ACT_ALLOW"
ERRNO = "SCMP_ACT_ERRNO"
MASKED_EQ = "SCMP_CMP_MASKED_EQ"

Profile = dict[str, Any]
Rule = dict[str, Any]


class SeccompProfileError(ValueError):
    """Docker's default profile does not have the shape this transformation expects."""


def agent_profile(docker_default: Profile) -> Profile:
    """Return Docker's default profile with the Btrfs ioctls blocked. Never changes the input.

    Raises SeccompProfileError if ``ioctl`` is not allowed exactly once and unconditionally,
    which is what Docker's default has done for years: a new shape needs a human to look."""
    profile = copy.deepcopy(docker_default)
    syscalls = profile.get("syscalls")
    if not isinstance(syscalls, list):
        raise SeccompProfileError("the profile has no 'syscalls' list")
    _remove_unconditional_ioctl(syscalls)
    syscalls.extend(ioctl_rules())
    return profile


def ioctl_rules() -> list[Rule]:
    """The 9 disjoint ioctl rules described in the module docstring."""
    blocked = BTRFS_IOCTL_TYPE << IOCTL_TYPE_SHIFT
    rules = [
        _ioctl_rule(
            ALLOW,
            mask=bit,
            value=~blocked & bit,
            comment=f"ioctl: request bit {bit:#06x} differs from type {BTRFS_IOCTL_TYPE:#04x}",
        )
        for bit in _type_bits()
    ]
    rules.append(
        _ioctl_rule(
            ERRNO,
            mask=IOCTL_TYPE_MASK,
            value=blocked,
            comment=f"ioctl: Btrfs, FICLONE and FIDEDUPERANGE (type {BTRFS_IOCTL_TYPE:#04x})",
            errno_ret=BLOCKED_ERRNO,
        )
    )
    return rules


def evaluate_ioctl(profile: Profile, request: int) -> tuple[str, int | None]:
    """What ``profile`` does with ``ioctl(fd, request, ...)``: (action, errno or None).

    A small model of libseccomp for the unit tests: it only understands the rule shapes this
    module writes (MASKED_EQ on the request) and unconditional rules, and fails otherwise.
    Raises SeccompProfileError when two matching rules disagree, since libseccomp would then
    pick one by an order we do not control."""
    outcomes = set()
    for rule in profile["syscalls"]:
        if IOCTL not in rule["names"] or rule.get("includes") or rule.get("excludes"):
            continue
        if all(_matches(arg, request) for arg in rule.get("args") or []):
            errno_ret = rule.get("errnoRet") if rule["action"] == ERRNO else None
            outcomes.add((rule["action"], errno_ret))
    if len(outcomes) > 1:
        raise SeccompProfileError(f"overlapping ioctl rules for {request:#x}: {outcomes}")
    if outcomes:
        return outcomes.pop()
    return profile["defaultAction"], profile.get("defaultErrnoRet")


def render(profile: Profile) -> str:
    """Serialise like Docker's own default.json: tab indents and a final newline."""
    return json.dumps(profile, indent="\t") + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("docker_default", type=Path, help="Docker's default.json")
    parser.add_argument("output", type=Path, help="where to write the agent profile")
    args = parser.parse_args(argv)
    docker_default = json.loads(args.docker_default.read_text(encoding="utf-8"))
    args.output.write_text(render(agent_profile(docker_default)), encoding="utf-8")
    return 0


def _remove_unconditional_ioctl(syscalls: list[Rule]) -> None:
    holders = [rule for rule in syscalls if IOCTL in rule.get("names", [])]
    if len(holders) != 1:
        raise SeccompProfileError(f"expected exactly one rule naming ioctl, found {len(holders)}")
    rule = holders[0]
    conditions = {key: rule.get(key) for key in ("args", "includes", "excludes") if rule.get(key)}
    if rule.get("action") != ALLOW or conditions:
        raise SeccompProfileError(
            f"expected ioctl to be allowed unconditionally, found {rule.get('action')} "
            f"with {conditions}"
        )
    rule["names"] = [name for name in rule["names"] if name != IOCTL]


def _ioctl_rule(
    action: str, *, mask: int, value: int, comment: str, errno_ret: int | None = None
) -> Rule:
    # In Docker's (and the OCI) format, MASKED_EQ compares (arg & value) == valueTwo.
    rule: Rule = {
        "names": [IOCTL],
        "action": action,
        "args": [{"index": IOCTL_REQUEST_ARG, "value": mask, "valueTwo": value, "op": MASKED_EQ}],
        "comment": comment,
    }
    if errno_ret is not None:
        rule["errnoRet"] = errno_ret
    return rule


def _type_bits() -> Iterator[int]:
    for shift in range(IOCTL_TYPE_SHIFT, IOCTL_TYPE_SHIFT + 8):
        yield 1 << shift


def _matches(arg: dict[str, Any], request: int) -> bool:
    if arg.get("index") != IOCTL_REQUEST_ARG or arg.get("op") != MASKED_EQ:
        raise SeccompProfileError(f"evaluate_ioctl does not understand {arg}")
    return request & arg["value"] == arg.get("valueTwo", 0)


if __name__ == "__main__":
    sys.exit(main())
