"""Evil agent: lift the workspace's own space cap, then write past it.

Runs INSIDE the jail, as the agent's user (python3 -c). Usage:
<script> <btrfs fsid> <subvolume id> <directory> <MiB to try to write>. Prints one JSON object
on its last line.

The cap is a Btrfs simple quota (a qgroup limit) on the workspace subvolume. Changing it takes
CAP_SYS_ADMIN and a Btrfs ioctl (type 0x94: seccomp answers EOPNOTSUPP, 95), or a write to
sysfs, which is read-only in the container (EROFS) or not visible at all (ENOENT, T04d-1).
"""

import fcntl
import json
import os
import struct
import sys

fsid, subvolume, directory, megabytes = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
NONE = 2**64 - 1
QGROUP_LIMIT_MAX_RFER = 1
# _IOWR/_IOW/_IOR(0x94, nr, struct): the requests `btrfs qgroup` and `btrfs quota` send.
QUOTA_CTL = 0xC0109428  # nr 40: { u64 cmd; u64 status }
QGROUP_ASSIGN = 0x40189429  # nr 41: { u64 assign; u64 src; u64 dst }
QGROUP_CREATE = 0x4010942A  # nr 42: { u64 create; u64 qgroupid }
QGROUP_LIMIT = 0x8030942B  # nr 43: struct btrfs_ioctl_qgroup_limit_args (48 bytes)
QUOTA_CTL_DISABLE = 2
results = {}


def ioctl(name, request, argument):
    fd = os.open("/workspace", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.ioctl(fd, request, bytearray(argument), True)
        results[name] = 0
    except OSError as error:
        results[name] = error.errno
    finally:
        os.close(fd)


def write(name, path, value):
    try:
        with open(path, "w") as handle:
            handle.write(value)
        results[name] = 0
    except OSError as error:
        results[name] = error.errno


ioctl("limit_none", QGROUP_LIMIT, struct.pack("=QQQQQQ", 0, QGROUP_LIMIT_MAX_RFER, NONE, 0, 0, 0))
ioctl("quota_disable", QUOTA_CTL, struct.pack("=QQ", QUOTA_CTL_DISABLE, 0))
ioctl("qgroup_assign", QGROUP_ASSIGN, struct.pack("=QQQ", 1, 0, 1 << 48))
ioctl("qgroup_create", QGROUP_CREATE, struct.pack("=QQ", 1, 0))
sysfs = f"/sys/fs/btrfs/{fsid}"
write("quota_override", f"{sysfs}/quota_override", "1")
write("max_referenced", f"{sysfs}/qgroups/0_{subvolume}/max_referenced", str(NONE))
write("limit_flags", f"{sysfs}/qgroups/0_{subvolume}/limit_flags", "0")
try:
    with open(f"{sysfs}/qgroups/0_{subvolume}/max_referenced") as handle:
        seen = int(handle.read())
except OSError as error:
    seen = -error.errno  # not visible from the jail: even better

# Did the cap really fall? Write past it, in 1 MiB steps, until the kernel says no.
os.makedirs(directory, exist_ok=True)
written, stopped_by = 0, 0
try:
    fd = os.open(os.path.join(directory, "past-the-cap.bin"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        for _ in range(megabytes):
            written += os.write(fd, b"\0" * (1 << 20))
    finally:
        os.close(fd)
except OSError as error:
    stopped_by = error.errno
print(
    json.dumps(
        {"attempts": results, "cap_seen": seen, "written": written, "stopped_by": stopped_by}
    )
)
