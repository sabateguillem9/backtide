#!/bin/bash
# The installation in a clean VM, end to end (T13-3; T13-5 and the Mac's lab, T13b, reuse it).
# Inside a backtide-limpia-* or backtide-prueba-* VM only, as root, never on the Mac or in vigia-dev:
#
#   sudo bash instalar_lab.sh bloquear            # nothing of the agent's leaves the VM
#   sudo bash instalar_lab.sh instalar SRC.tar    # install.sh --desde SRC.tar, made-up key,
#                                                 # watching `ps` the whole time
#   sudo bash instalar_lab.sh fugas               # the made-up key in ps, journal, logs, files?
#   sudo bash instalar_lab.sh estado              # what is there: units, mounts, containers
#   sudo bash instalar_lab.sh bateria SRC.tar     # the T13 scenarios of the battery, as root
#
# Invariant 8: no real key and no real service. The key is made up here (it has the shape of an
# Anthropic key and is nobody's). `bloquear` drops, before Docker exists, everything Docker's
# bridges would forward out of the VM (the proxy's way out), and backtide's own calls to the model
# providers and the pricing page: the agent runs, nothing it says reaches anyone. The images and
# the packages still come in (dockerd and dnf/apt are the host's, not forwarded).
set -euo pipefail

LAB=/var/lib/backtide-lab
KEY_FILE=$LAB/made-up.key
PS_LOG=$LAB/ps.log

require_clean_vm_root() {
  case "$(hostname)" in lima-backtide-limpia-* | lima-backtide-prueba-*) ;;
    *) echo "only inside a backtide-limpia-* or backtide-prueba-* VM" >&2; exit 2 ;; esac
  [ "$(id -u)" = 0 ] || { echo "run it as root" >&2; exit 2; }
}

# Everything but making the cut needs it there: a VM named like ours without the cut is not a lab.
require_lab_mark() {
  nft list table inet backtide_lab >/dev/null 2>&1 \
    || { echo "no lab network cut here: run \`instalar_lab.sh bloquear\` first" >&2; exit 2; }
}

result() { printf 'RESULT %s=%s\n' "$1" "$2"; }

cortar() {
  nft delete table inet backtide_lab 2>/dev/null || true
  nft add table inet backtide_lab
  # Priority -50: before Docker's own rules (filter, 0); a drop anywhere is final.
  nft add chain inet backtide_lab forward '{ type filter hook forward priority -50; policy accept; }'
  nft add rule inet backtide_lab forward iifname '{ "br-*", "docker0" }' oifname != '{ "br-*", "docker0" }' counter drop
  nft add chain inet backtide_lab output '{ type filter hook output priority -50; policy accept; }'
  for name in api.anthropic.com api.openai.com platform.claude.com clawhub.ai; do
    for ip in $(getent ahostsv4 "$name" | awk '{print $1}' | sort -u); do
      nft add rule inet backtide_lab output ip daddr "$ip" counter drop
    done
  done
  result blocked "$(nft list table inet backtide_lab | grep -c drop) drop rules"
}

bloquear() {
  cortar
  # And again at every boot, before Docker: a reboot test must not open the way out.
  mkdir -p "$LAB" && cp "$0" "$LAB/instalar_lab.sh"
  cat > /etc/systemd/system/backtide-lab-bloquear.service <<UNIT
[Unit]
Description=backtide lab: nothing of the agent's leaves this VM (tests/install/instalar_lab.sh)
Before=docker.service backtide.service
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $LAB/instalar_lab.sh cortar
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable backtide-lab-bloquear.service >/dev/null 2>&1
}

instalar() {
  local src=$1 sha
  mkdir -p "$LAB" && chmod 0700 "$LAB"
  if [ ! -s "$KEY_FILE" ]; then
    # Made up here: the shape of an Anthropic key (the installer checks it), nobody's.
    printf 'sk-ant-api03-%s\n' "$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 80)" > "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
  fi
  sha=$(sha256sum "$src" | cut -d' ' -f1)
  tar -xOf "$src" install.sh > "$LAB/install.sh"
  ( while :; do ps -eww -o pid=,args= >> "$PS_LOG"; sleep 0.2; done ) &
  local watcher=$!
  local start=$SECONDS code=0
  sh "$LAB/install.sh" --desde "$src" --sha256 "$sha" --si --clave-archivo "$KEY_FILE" \
    > >(tee -a "$LAB/install.log") 2>&1 || code=$?
  kill "$watcher" 2>/dev/null || true
  result install_exit "$code"
  result install_seconds "$((SECONDS - start))"
  return "$code"
}

fugas() {
  # The key is read from its file by grep (-f), never put in grep's arguments: a ps sampler that is
  # still running (the Mac's lab keeps one for the whole session) would record it there.
  local found="" match=(grep -qF -f "$KEY_FILE")
  "${match[@]}" "$PS_LOG" && found="$found ps"
  journalctl -b --no-pager -o cat 2>/dev/null | "${match[@]}" && found="$found journal"
  grep -rqF -f "$KEY_FILE" /var/log 2>/dev/null && found="$found /var/log"
  [ ! -e "$LAB/install.log" ] || ! "${match[@]}" "$LAB/install.log" || found="$found install.log"
  for c in $(docker ps -aq); do docker logs "$c" 2>&1 | "${match[@]}" && found="$found docker-logs:$c"; done
  # Files: everywhere backtide writes, but its one place for the key and the lab's own copy.
  while IFS= read -r file; do
    case "$file" in /var/lib/backtide/keys/anthropic.key | "$KEY_FILE") ;; *) found="$found $file" ;; esac
  done < <(grep -rlF -f "$KEY_FILE" /etc /var/lib/backtide /opt/backtide /run /tmp /root 2>/dev/null || true)
  result ps_samples "$(grep -c . "$PS_LOG")"
  result key_leaks "[${found# }]"
  result key_file "$(stat -c '%U:%G %a' /var/lib/backtide/keys/anthropic.key)"
}

estado() {
  . /etc/os-release
  result distro "$PRETTY_NAME $(uname -r)"
  for unit in var-lib-backtide\\x2dagent.mount var-lib-backtide-proxy\\x2dchannel.mount backtide.service backtide-web.service docker.service; do
    result "unit:$unit" "$(systemctl is-active "$unit") $(systemctl is-enabled "$unit" 2>/dev/null)"
  done
  result volume "$(findmnt -n -o FSTYPE,OPTIONS --mountpoint /var/lib/backtide-agent)"
  result channel "$(findmnt -n -o SOURCE,FSTYPE,OPTIONS --mountpoint /var/lib/backtide/proxy-channel)"
  result containers "$(docker ps --format '{{.Names}}:{{.Status}}' | tr '\n' ' ')"
  result networks "$(docker network inspect --format '{{.Name}}={{range .IPAM.Config}}{{.Subnet}}{{end}}' backtide-agente-net backtide-salida-net | tr '\n' ' ')"
  result docker_security "$(docker info --format '{{json .SecurityOptions}}')"
  result state_dir "$(stat -c '%U:%G %a' /var/lib/backtide)"
  result blackbox_db "$(stat -c '%U:%G %a' /var/lib/backtide/blackbox.db)"
  result web_toml "$(stat -c '%U:%G %a' /etc/backtide/web.toml)"
  result config "$(stat -c '%U:%G %a' /etc/backtide/backtide.toml)"
  result volume_root "$(stat -c '%U:%G %a' /var/lib/backtide-agent)"
  result web_link "$(stat -c '%U:%G %a' /run/backtide-web/enlace 2>/dev/null || echo missing)"
  for unit in backtide.service backtide-web.service; do
    result "security:$unit" "$(systemd-analyze security --no-pager "$unit" 2>/dev/null | tail -1)"
  done
  result journal_has_web_link "$(journalctl -u backtide-web --no-pager -o cat | grep -c '?t=' || true)"
  result manifest_steps "$(python3 -c 'import json; print(len(json.load(open("/var/lib/backtide/install-manifest.json"))["steps"]))')"
}

bateria() {
  # The T13 scenarios of the evil-agent battery, against this installation, as root.
  local src=$1 dir=/root/backtide-tests
  shift
  rm -rf "$dir" && mkdir -p "$dir" && tar -xf "$src" -C "$dir" --no-same-owner
  ( cd "$dir" && UV_PYTHON_INSTALL_DIR=/opt/backtide/python UV_PYTHON_PREFERENCE=only-managed \
      UV_CACHE_DIR=/root/.cache/uv /opt/backtide/uv/*/uv run --quiet --locked --python 3.12 \
      pytest -m ataques -p no:cacheprovider -rs tests/attacks/test_install_attacks.py "$@" )
}

require_clean_vm_root
case "${1:-}" in
  bloquear) bloquear ;;
  cortar) cortar ;;
  instalar) require_lab_mark; instalar "${2:?the source archive}" ;;
  fugas) require_lab_mark; fugas ;;
  estado) require_lab_mark; estado ;;
  bateria) require_lab_mark; shift; bateria "${1:?the source archive}" "${@:2}" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
