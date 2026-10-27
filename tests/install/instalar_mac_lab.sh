#!/bin/sh
# The Mac installer, end to end, on this Mac but as a clean one (T13b; docs/25, «Resultados de
# T13b»). Everything lives in one throwaway folder, $LAB, in your home because Lima's sockets must
# fit in 104 characters with their real path (/private/var/folders/... does not): its own HOME, its own LIMA_HOME (no VM of yours is seen or touched), a PATH with
# no limactl (so install-mac.sh fetches its pinned Lima) and the test VM backtide-prueba-m.
# Never sudo on the Mac, never ~/.lima, vigia-dev or Homebrew.
#
#   LAB=$(mktemp -d "$HOME/.btm.XXXX") sh instalar_mac_lab.sh preparar   # archive, key, lab yaml
#   LAB=... sh instalar_mac_lab.sh instalar      # install-mac.sh, watching ps on the Mac
#   LAB=... sh instalar_mac_lab.sh mac CMD...    # a command with the lab's HOME, PATH, LIMA_HOME
#   LAB=... sh instalar_mac_lab.sh vm 'CMD'      # bash -c CMD in the test VM, as its Lima user
#   LAB=... sh instalar_mac_lab.sh bateria [ARGS] # the T13 and Mac scenarios, as root
#   LAB=... sh instalar_mac_lab.sh alcance       # what of the VM's listeners shows on the Mac
#   LAB=... [ATK_PATH=...] sh instalar_mac_lab.sh bateria-dev [ARGS] # the whole battery as in
#                                   vigia-dev (make ataques), as the Lima user, backtide stopped
#   LAB=... sh instalar_mac_lab.sh fugas         # the made-up key on the Mac side and in the VM
#   LAB=... sh instalar_mac_lab.sh borrar        # deletes the test VM and $LAB
#
# Invariant 8: the key is made up here and is nobody's. The VM gets the lab's network cut
# (instalar_lab.sh bloquear) at its first boot, before Docker exists, and at every boot after.
set -eu

: "${LAB:?LAB=<a short scratch folder>}"
VM=backtide-prueba-m  # short: Lima's ssh socket path must stay under 104 characters
REPO=$(cd "$(dirname "$0")/../.." && pwd)
LIMACTL=$LAB/home/.backtide/lima/2.2.1/bin/limactl

lab_env() {
  env -i HOME="$LAB/home" LIMA_HOME="$LAB/l" TMPDIR="$LAB/tmp" TERM="${TERM:-dumb}" \
    PATH="$LAB/home/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    BACKTIDE_MAC_LAB_YAML="$LAB/lab.yaml" BACKTIDE_MAC_LAB_PORT="$(cat "$LAB/port")" "$@"
}
result() { printf 'RESULT %s=%s\n' "$1" "$2"; }

preparar() {
  mkdir -p "$LAB/home" "$LAB/tmp" "$LAB/stage"
  # The code as it is in this tree (tracked and new files; not the landing page), as install.sh
  # gets it: one tar, checked by its sha256.
  (cd "$REPO" && git ls-files -co --exclude-standard | grep -v '^site/' \
    | while IFS= read -r f; do [ -e "$f" ] && printf '%s\n' "$f"; done \
    | COPYFILE_DISABLE=1 tar --no-xattrs --no-fflags --no-acls -cf "$LAB/src.tar" -T -)
  shasum -a 256 "$LAB/src.tar" | cut -d' ' -f1 > "$LAB/src.sha256"
  # The lab runs the install-mac.sh of that archive, as a user would (and not the tree's, which
  # may change while it runs).
  tar -xOf "$LAB/src.tar" install-mac.sh > "$LAB/install-mac.sh"
  # Made up here: the shape of an Anthropic key (the installer checks it), nobody's.
  [ -s "$LAB/made-up.key" ] || (umask 077 && printf 'sk-ant-api03-%s\n' \
    "$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 80)" > "$LAB/made-up.key")
  # A free port of the Mac for the test VM's web (8765 may be in use by `make web-demo`).
  port=$(cat "$LAB/port" 2>/dev/null || echo 18765)
  while [ ! -s "$LAB/port" ] && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; do port=$((port + 1)); done
  echo "$port" > "$LAB/port"
  # The lab's cut, at every boot of the test VM, before Docker (instalar_lab.sh bloquear).
  {
    echo 'provision:'
    echo '- mode: system'
    echo '  script: |'
    echo '    #!/bin/bash'
    echo '    set -eu'
    echo '    mkdir -p /var/lib/backtide-lab/src && chmod 0700 /var/lib/backtide-lab'
    echo "    base64 -d > /var/lib/backtide-lab/src/instalar_lab.sh <<'B64'"
    base64 < "$REPO/tests/install/instalar_lab.sh" | fold -w 76 | sed 's/^/    /'
    echo '    B64'
    echo '    bash /var/lib/backtide-lab/src/instalar_lab.sh bloquear'
    echo '    systemctl is-active -q backtide-lab-ps || systemd-run --quiet --unit backtide-lab-ps \'
    echo "      bash -c 'while :; do ps -eww -o pid=,args= >> /var/lib/backtide-lab/ps.log; sleep 0.2; done'"
  } > "$LAB/lab.yaml"
  result archive "$(cat "$LAB/src.sha256") $(wc -c < "$LAB/src.tar" | tr -d ' ') B"
  result port "$port"
  lab_env sh -c 'command -v limactl || echo "no limactl on the lab PATH"'
}

instalar() {
  ( while :; do ps -axww -o pid=,command= >> "$LAB/mac-ps.log"; sleep 0.2; done ) &
  watcher=$!
  start=$(date +%s) code=0
  lab_env sh "$LAB/install-mac.sh" --desde "$LAB/src.tar" --sha256 "$(cat "$LAB/src.sha256")" \
    --nombre-vm "$VM" --si --clave-archivo "$LAB/made-up.key" "$@" \
    > "$LAB/install.$start.log" 2>&1 < /dev/null || code=$?
  kill "$watcher" 2>/dev/null || true
  tail -n 25 "$LAB/install.$start.log"
  result install_exit "$code"
  result install_seconds "$(( $(date +%s) - start ))"
  return "$code"
}

vm() { lab_env "$LIMACTL" shell --workdir / "$VM" -- bash -c "$1"; }

fugas() {
  key=$LAB/made-up.key  # grep reads it (-f): never in an argument
  found=""
  grep -qF -f "$key" "$LAB/mac-ps.log" && found="$found mac-ps"
  for log in "$LAB"/install.*.log; do grep -qF -f "$key" "$log" && found="$found $(basename "$log")"; done
  # Lima's own files: logs, config, cloud-init; not the VM's disks (the key is in the VM, rightly).
  while IFS= read -r file; do found="$found $file"; done <<EOF
$(grep -rlF -f "$key" "$LAB/l" "$LAB/home" "$LAB/tmp" --exclude=disk --exclude=basedisk --exclude=diffdisk \
  --exclude='*.qcow2' --exclude='*.raw' 2>/dev/null || true)
EOF
  for history in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.sh_history"; do
    [ -r "$history" ] && grep -aqF -f "$key" "$history" && found="$found $history"
  done
  result mac_ps_samples "$(grep -c . "$LAB/mac-ps.log")"
  result mac_key_leaks "[${found# }]"
  # The VM: the same check as on Linux (instalar_lab.sh fugas), with the key sent by stdin.
  lab_env "$LIMACTL" shell --workdir / "$VM" -- sudo sh -c \
    'umask 077 && cat > /var/lib/backtide-lab/made-up.key' < "$LAB/made-up.key"
  vm 'sudo bash /var/lib/backtide-lab/instalar_lab.sh fugas; for h in /root/.bash_history /home/*/.bash_history; do sudo test -e "$h" && sudo grep -qF -f /var/lib/backtide-lab/made-up.key "$h" && echo "RESULT history_leak=$h"; done; true'
}

bateria() {
  # The seven T13 scenarios and the Mac's three, as root, with the web's real port on the Mac.
  lab_env "$LIMACTL" copy "$LAB/src.tar" "$VM:lab-src.tar" < /dev/null
  vm "sudo env BACKTIDE_LAB_HOST_PORT=$(cat "$LAB/port") bash /var/lib/backtide-lab/instalar_lab.sh \
    bateria \$HOME/lab-src.tar tests/attacks/test_mac_vm_attacks.py $*"
}

alcance() {
  # From the Mac's side: listeners in the VM (TCP and UDP, on 127.0.0.1, 0.0.0.0 and [::]) for a
  # while, and what Lima's hostagent opens on the Mac meanwhile. Only the web's port may appear,
  # besides Lima's own ssh and DNS; and that port answers (the control).
  vm 'nohup python3 -c "
import socket, time
s = []
for a, f in ((\"127.0.0.1\", socket.AF_INET), (\"0.0.0.0\", socket.AF_INET), (\"::\", socket.AF_INET6)):
    for k in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        x = socket.socket(f, k); x.bind((a, 0)); k == socket.SOCK_STREAM and x.listen(); s.append(x)
print(\" \".join(str(x.getsockname()[1]) for x in s), flush=True)
time.sleep(40)
" > /tmp/alcance.ports 2>&1 &'
  sleep 15
  ha=$(cat "$LAB/l/$VM/ha.pid")
  ssh_port=$(lab_env "$LIMACTL" list --format '{{.SSHLocalPort}}' "$VM")
  dns=$(sed -n 's/.*Start tcp DNS listening on: 127.0.0.1:\([0-9]*\).*/\1/p' "$LAB/l/$VM/ha.stderr.log" | tail -n 1)
  udp_dns=$(sed -n 's/.*Start udp DNS listening on: 127.0.0.1:\([0-9]*\).*/\1/p' "$LAB/l/$VM/ha.stderr.log" | tail -n 1)
  tcp=$(lsof -nP -a -p "$ha" -iTCP -sTCP:LISTEN | awk 'NR > 1 {print $9}' | sort | tr '\n' ' ')
  udp=$(lsof -nP -a -p "$ha" -iUDP | awk 'NR > 1 && $9 ~ /^127\.0\.0\.1:/ {print $9}' | sort | tr '\n' ' ')
  want_tcp=$(printf '127.0.0.1:%s\n' "$(cat "$LAB/port")" "$ssh_port" "$dns" | sort | tr '\n' ' ')
  result vm_listeners "$(vm 'cat /tmp/alcance.ports')"
  result mac_tcp "[$tcp]"
  result mac_udp "[$udp]"
  result want "tcp [$want_tcp] udp [127.0.0.1:$udp_dns ]"
  control=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: 127.0.0.1:8765' "http://127.0.0.1:$(cat "$LAB/port")/")
  result control "$control"
  [ "$tcp" = "$want_tcp" ] && [ "$udp" = "127.0.0.1:$udp_dns " ] && [ "$control" != 000 ] \
    || { echo "FALLO: el Mac tiene algo más que la web, el ssh y el DNS de Lima" >&2; return 1; }
  result alcance OK
}

bateria_dev() {
  # The dev battery brings its own agent, proxy and sensor: the installed ones are stopped meanwhile
  # (two Tetragons would share the kernel's BPF pins) and started again after, whatever happened.
  lab_env "$LIMACTL" copy "$LAB/src.tar" "$VM:lab-src.tar" < /dev/null
  vm "set -u
sudo systemctl stop backtide-web.service backtide.service
sudo docker rm -f backtide-agente backtide-egress backtide-sensor >/dev/null 2>&1
# Its loop device too: mkfs.btrfs, as the Lima user, cannot look at a backing file under
# /var/lib/backtide (0710) and refuses to format the battery's own volumes.
sudo systemctl stop 'var-lib-backtide\\x2dagent.mount'
# The lab's cut counts what Docker's bridges try to send out of the VM: its count now, and the
# same after the whole battery (nothing of any agent's left the VM, nor even tried).
fwd() { sudo nft list chain inet backtide_lab forward | sed -n 's/.*counter packets \\([0-9]*\\).*/\\1/p' | head -n 1; }
before=\$(fwd)
sudo chgrp \$(id -g) /run/docker.sock  # this VM only, until the end of this function
rm -rf ~/bt && mkdir ~/bt && tar -xf ~/lab-src.tar -C ~/bt && cd ~/bt
export UV_CACHE_DIR=\$HOME/.cache/uv UV_PROJECT_ENVIRONMENT=\$HOME/.venvs/bt BACKTIDE_ATK_PERFIL=openclaw
# The VM's /tmp is a tmpfs of half its memory (3 GiB): the battery's Btrfs images go on its disk,
# in /var/tmp/pytest-of-<user>/ (the harness only mounts and sudos under a pytest-of-* folder).
# Every scenario but the installation's (those run as root: \`bateria\`).
TMPDIR=/var/tmp /opt/backtide/uv/*/uv run --quiet --locked --python 3.12 pytest \\
  -m 'ataques and not instalada' -q --tb=short -p no:cacheprovider ${ATK_PATH:-tests/attacks} $*
rc=\$?
forward=\$(( \$(fwd) - before ))
echo \"RESULT forward_packets_during_battery=\$forward (counter \$before before)\"
[ \"\$forward\" = 0 ] || { echo 'FALLO: algo intentó salir de la VM por los puentes de Docker' >&2; rc=1; }
sudo chgrp docker /run/docker.sock
sudo systemctl start 'var-lib-backtide\\x2dagent.mount' backtide.service backtide-web.service
exit \$rc"
}

borrar() {
  if [ -x "$LIMACTL" ]; then lab_env "$LIMACTL" delete --force "$VM" || true; fi
  case "$LAB" in */.btm.*) rm -rf "$LAB" ;; *) echo "not removing $LAB: not a .btm.* folder" >&2; exit 2 ;; esac
  result removed "$LAB"
}

case "${1:-}" in
  preparar) preparar ;;
  instalar) shift; instalar "$@" ;;
  mac) shift; lab_env "$@" ;;
  vm) vm "${2:?a command}" ;;
  bateria) shift; bateria "$@" ;;
  alcance) alcance ;;
  bateria-dev) shift; bateria_dev "$@" ;;
  fugas) fugas ;;
  borrar) borrar ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
