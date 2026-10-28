#!/bin/bash
# The installation in a clean VM, end to end (T13-3; T13-5 and the Mac's lab, T13b, reuse it).
# Inside a backtide-limpia-* or backtide-prueba-* VM only, as root, never on the Mac or in vigia-dev:
#
#   sudo bash instalar_lab.sh bloquear            # nothing of the agent's leaves the VM
#   sudo bash instalar_lab.sh instalar REL.tar    # install.sh --desde REL.tar (a `make release`
#                                                 # archive), made-up key, watching `ps`
#   sudo bash instalar_lab.sh fugas               # the made-up key in ps, journal, logs, files?
#   sudo bash instalar_lab.sh estado              # what is there: units, mounts, containers
#   sudo bash instalar_lab.sh bateria SRC.tar     # the T13 scenarios of the battery, as root
#   sudo bash instalar_lab.sh senuelos            # a user, folders and a container that are not
#                                                 # ours, for the uninstall to leave alone (T13-4)
#   sudo bash instalar_lab.sh huella FILE         # the machine as the uninstall must leave it
#   sudo bash instalar_lab.sh desinstalar REL.tar [flags]  # `backtide desinstalar` from REL.tar,
#                                                 # also once /opt/backtide is gone (a second run)
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

senuelos() {
  # Someone else's things, made after Docker is there: none may change in an uninstall.
  getent passwd vecino >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin vecino
  mkdir -p /etc/vecino /var/lib/vecino /opt/vecino
  echo "de otro" > /etc/vecino/ajustes; echo "de otro" > /var/lib/vecino/datos; echo "de otro" > /opt/vecino/programa
  docker image inspect busybox:1.37 >/dev/null 2>&1 || docker pull --quiet busybox:1.37 >/dev/null
  docker network inspect vecino-net >/dev/null 2>&1 || docker network create --internal vecino-net >/dev/null
  docker container inspect vecino-web >/dev/null 2>&1 \
    || docker run -d --name vecino-web --network vecino-net --restart unless-stopped busybox:1.37 sleep infinity >/dev/null
  # A setting of the person's own in Docker's daemon.json, added after the install.
  python3 - <<'PY'
import json, pathlib
p = pathlib.Path("/etc/docker/daemon.json")
d = json.loads(p.read_text()) if p.exists() else {}
d["max-concurrent-downloads"] = 2
p.write_text(json.dumps(d, indent=2) + "\n")
PY
  # And one with the name of backtide's own sensor but not its label (review of T13-4): it must
  # survive the uninstall. The name is free only with backtide stopped (its sensor goes with the
  # service; a labelled one left behind is the lab's own to remove), so this goes right before
  # `desinstalar`.
  systemctl stop backtide.service 2>/dev/null || true
  if [ "$(docker container inspect --format '{{index .Config.Labels "backtide.role"}}' backtide-sensor 2>/dev/null)" = sensor ]; then
    docker rm --force backtide-sensor >/dev/null
  fi
  docker container inspect backtide-sensor >/dev/null 2>&1 \
    || docker run -d --name backtide-sensor --network none busybox:1.37 sleep infinity >/dev/null
  result decoys "$(docker inspect --format '{{.Name}} {{.State.StartedAt}}' vecino-web backtide-sensor | tr '\n' ' ')"
}

huella() {
  # What an uninstall must leave as it found it, one sorted line each, to diff before and after.
  local out=$1
  {
    set +e +o pipefail  # a missing user or file is an answer here, not a failure
    systemctl list-unit-files --no-legend 'backtide*' 'var-lib-backtide*' 2>/dev/null | sed 's/^/unit /'
    findmnt -rn -o TARGET,FSTYPE | awk '$1 ~ /backtide/ {print "mount " $0}'
    losetup -n -O NAME,BACK-FILE 2>/dev/null | awk '{print "loop " $2}'
    for name in backtide-web vecino; do getent passwd "$name" | cut -d: -f1,6,7 | sed 's/^/user /'; getent group "$name" | cut -d: -f1 | sed 's/^/group /'; done
    for path in /etc/backtide /opt/backtide /var/lib/backtide /var/lib/backtide-agent /usr/local/bin/backtide \
                /etc/vecino /var/lib/vecino /opt/vecino \
                /etc/yum.repos.d/docker-ce.repo /etc/pki/rpm-gpg/backtide-docker-ce.asc \
                /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc; do
      [ -e "$path" ] || [ -L "$path" ] && echo "path $path $(stat -c '%U:%G %a' "$path")"
    done
    for file in /etc/vecino/ajustes /var/lib/vecino/datos /opt/vecino/programa /etc/docker/daemon.json; do
      [ -e "$file" ] && echo "sha $file $(sha256sum "$file" | cut -d' ' -f1)"
    done
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      docker ps -a --format 'container {{.Names}} {{.Image}}'
      docker network ls --format 'network {{.Name}}'
      docker image ls --format 'image {{.Repository}}' | sort -u
      docker inspect --format 'decoy-started {{.Name}} {{.State.StartedAt}}' vecino-web backtide-sensor 2>/dev/null || true
    else
      echo "docker absent"
    fi
    { rpm -qa 'docker-ce*' 'containerd*' 2>/dev/null || dpkg-query -W -f '${Package}\n' 'docker-ce*' 'containerd*' 2>/dev/null; } | sed 's/^/package /'
    rpmkeys --list 2>/dev/null | grep -i docker | sed 's/^/rpmkey /' || true
  } | sort > "$out"
  result fingerprint "$out $(wc -l < "$out") lines"
}

desinstalar() {
  # From the installed program if it is there; else from REL.tar (a `make release` archive) with a
  # copy of uv kept aside, as a second run after the first one removed /opt/backtide. Nothing is
  # built there either: the archive's own install.sh function makes its venv (wheels by hash,
  # --no-build) and its launcher.
  local src=$1 dir=/root/backtide-desinstalar
  shift
  [ -x /opt/backtide/uv/0.12.17/uv ] && cp /opt/backtide/uv/0.12.17/uv "$LAB/uv"
  if [ -x /usr/local/bin/backtide ]; then
    /usr/local/bin/backtide desinstalar "$@"
  else
    rm -rf "$dir" && mkdir -p "$dir" && tar -xf "$src" -C "$dir" --no-same-owner
    [ -f "$dir/requirements.txt" ] || { echo "$src is not a release archive (make release)" >&2; return 2; }
    sed -n '/^install_release() {/,/^}/p' "$dir/install.sh" > "$LAB/install_release.sh"
    ( . "$LAB/install_release.sh" && cd / && UV=$LAB/uv UV_CACHE_DIR=$LAB/uv-cache \
        UV_PYTHON_INSTALL_DIR=$LAB/python UV_PYTHON_PREFERENCE=only-managed UV_NO_CONFIG=1 \
        install_release "$dir" ) || { echo "could not make the uninstaller's venv" >&2; return 1; }
    "$dir/.venv/bin/backtide" desinstalar "$@"
  fi
}

require_clean_vm_root
case "${1:-}" in
  bloquear) bloquear ;;
  cortar) cortar ;;
  instalar) require_lab_mark; instalar "${2:?the source archive}" ;;
  fugas) require_lab_mark; fugas ;;
  estado) require_lab_mark; estado ;;
  bateria) require_lab_mark; shift; bateria "${1:?the source archive}" "${@:2}" ;;
  senuelos) require_lab_mark; senuelos ;;
  huella) huella "${2:?a file for the fingerprint}" ;;
  desinstalar) require_lab_mark; shift; desinstalar "${1:?the source archive}" "${@:2}" ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
