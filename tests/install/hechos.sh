#!/bin/bash
# What a clean VM is made of, for the installer's report (T13-1, T13-5; docs/25): kernel,
# distribution, btrfs-progs, BTF, cgroup v2, loop devices, SELinux or AppArmor, systemd, time
# sync, Docker. Read-only: it changes nothing. Run it as root inside a backtide-limpia-* VM:
#   make vm-limpia-ejecutar DISTRO=fedora CMD="sudo bash ~/backtide-src/tests/install/hechos.sh"
set -u

fact() { printf 'FACT %-22s %s\n' "$1" "$2"; }

. /etc/os-release
fact distro "$PRETTY_NAME"
fact kernel "$(uname -r)"
fact arch "$(uname -m)"
fact btrfs_progs "$(btrfs --version 2>/dev/null | head -1 || echo missing)"
fact btrfs_module "$(grep -qw btrfs /proc/filesystems && echo loaded || (modprobe btrfs 2>/dev/null && echo loadable || echo missing))"
fact btf "$(test -r /sys/kernel/btf/vmlinux && echo present || echo missing)"
fact cgroup "$(stat -fc %T /sys/fs/cgroup)"
fact loop_control "$(test -c /dev/loop-control && echo present || echo missing)"
fact root_fs "$(findmnt -no FSTYPE /) ($(findmnt -no FSTYPE /var/lib 2>/dev/null || findmnt -no FSTYPE /))"
fact free_var_lib "$(df -BG --output=avail /var/lib | tail -1 | tr -d ' ')"
if command -v getenforce >/dev/null 2>&1; then fact selinux "$(getenforce)"; else fact selinux none; fi
if [ -d /sys/kernel/security/apparmor ]; then
  fact apparmor "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) ($(aa-status --profiled 2>/dev/null || echo '?') profiles)"
else
  fact apparmor none
fi
fact systemd "$(systemctl --version | head -1)"
fact time_sync "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
fact uid_61000 "$(getent passwd 61000 >/dev/null && echo taken || echo free) / gid $(getent group 61000 >/dev/null && echo taken || echo free)"
fact openssl "$(openssl version 2>/dev/null || echo missing)"
if command -v docker >/dev/null 2>&1; then
  fact docker "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'not running')"
  fact docker_security "$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null)"
  fact docker_cgroup "$(docker info --format '{{.CgroupDriver}} v{{.CgroupVersion}}' 2>/dev/null)"
  fact docker_storage "$(docker info --format '{{.Driver}}' 2>/dev/null)"
else
  fact docker missing
fi
fact python3 "$(python3 --version 2>/dev/null || echo missing)"
fact uv "$(uv --version 2>/dev/null || echo missing)"
fact firewall "$(systemctl is-active firewalld 2>/dev/null | head -1)/firewalld $(ufw status 2>/dev/null | head -1 || echo 'no ufw')"
