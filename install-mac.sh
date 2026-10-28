#!/bin/sh
# backtide on a Mac (T13b; docs/25, section 7). Read it before running it: it is short.
#
#   sh install-mac.sh --desde ARCHIVO --sha256 HUELLA [--clave-archivo RUTA | --clave-stdin]
#   sh install-mac.sh --desinstalar [--borrar-datos] [--si]    (the same as `backtide desinstalar`)
#
# backtide needs a Linux kernel (Btrfs and eBPF), so on a Mac it lives in a Linux VM of its own,
# made with Lima and Apple's virtualization. As you, never with sudo, it does this and nothing else:
#   1. checks the Mac: Apple Silicon, macOS 13.5 or later, memory, disk, and that port 8765 is free;
#   2. uses your Lima (limactl 2.x) or, if there is none, downloads Lima 2.2.1, checked against its
#      sha256 below, to ~/.backtide/lima/2.2.1 (no Homebrew, nothing outside your home);
#   3. checks backtide's archive (sha256) and makes the VM `backtide` from lima/backtide-mac.yaml in
#      it: Fedora 44 by digest, 4 CPU, 6 GiB, a 40 GiB sparse disk, NO folder of the Mac mounted,
#      and only the web's port forwarded to this Mac's 127.0.0.1 (tested with Lima 2.2.1). The VM
#      itself (its root, never the agent's jail) can still reach services on this Mac's 127.0.0.1
#      through Lima's host address, 192.168.5.2: that is how Lima's network works;
#   4. copies the archive in and runs the Linux install.sh inside, unchanged, as the VM's root;
#   5. leaves ~/.local/bin/backtide, which runs `sudo backtide ...` inside the VM.
# Keys never go in an argument, here or in the VM: --clave-archivo RUTA (read here and sent through
# standard input), --clave-stdin, or typed when asked (no echo). Running it again changes nothing.
# Other arguments go to `backtide instalar` in the VM. --nombre-vm is for the lab only
# (backtide-prueba-*, with BACKTIDE_MAC_LAB_YAML: tests/install/instalar_mac_lab.sh).
set -eu

LIMA_VERSION=2.2.1
LIMA_SHA256_ARM64=9e9eacce88f37e185c346bad73aa6136f738d8cdf8c3bb23cd42b071824bc66e
# The published release, as in install.sh: empty until the first one (T14).
BACKTIDE_URL=
BACKTIDE_SHA256=
WEB_PORT=8765
MIN_MEMORY_GIB=8
MIN_FREE_GIB=25

say() { printf '%s\n' "backtide: $*"; }
clean() { printf '%s' "$1" | tr -cd '[:print:]'; }  # text from the VM, shown here: no escapes
die() { printf '%s\n' "backtide: $*" >&2; exit 1; }
hash_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

VM=backtide
SOURCE= SOURCE_SHA256= KEY_FILE= KEY_MODE= PROVIDER=anthropic YES=0 DRY_RUN=0 UNINSTALL=0 ERASE=0
left=$#
while [ "$left" -gt 0 ]; do
  arg=$1; shift; left=$((left - 1))
  case "$arg" in
    --desde | --sha256 | --nombre-vm | --clave-archivo)
      [ "$left" -gt 0 ] || die "$arg necesita un valor"
      value=$1; shift; left=$((left - 1))
      case "$arg" in
        --desde) SOURCE=$value ;; --sha256) SOURCE_SHA256=$value ;; --nombre-vm) VM=$value ;;
        --clave-archivo) KEY_FILE=$value ;;
      esac ;;
    --clave-archivo=*) KEY_FILE=${arg#--clave-archivo=} ;;
    --clave-stdin) KEY_MODE=stdin ;;
    --sin-clave) KEY_MODE=none ;;
    --si) YES=1 ;;
    --desinstalar) UNINSTALL=1 ;;
    --borrar-datos) ERASE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --proveedor) [ "$left" -gt 0 ] || die "--proveedor necesita un valor"
      PROVIDER=$1; set -- "$@" "$arg" "$1"; shift; left=$((left - 1)) ;;
    --proveedor=*) PROVIDER=${arg#--proveedor=}; set -- "$@" "$arg" ;;
    *) set -- "$@" "$arg" ;;
  esac
done
if [ -n "$KEY_FILE" ]; then [ -z "$KEY_MODE" ] || die "una sola forma de dar la clave"; KEY_MODE=file; fi
# With --clave-stdin the key is on standard input: keep it on fd 3 for the one call that sends it,
# so that no other call (each limactl shell forwards its stdin to the VM) can swallow it.
if [ "$KEY_MODE" = stdin ]; then
  [ ! -t 0 ] || die "--clave-stdin lee de una tubería o un archivo, no de la terminal (se vería y quedaría en el historial): usa --clave-archivo RUTA, o nada y te la pido sin eco"
  exec 3<&0 0</dev/null
fi
case "$VM" in [a-z]*) ;; *) die "--nombre-vm: letras minúsculas, cifras y guiones" ;; esac
case "$VM" in *[!a-z0-9-]*) die "--nombre-vm: letras minúsculas, cifras y guiones" ;; esac
case "$PROVIDER" in *[!a-z]* | "") die "--proveedor no válido" ;; esac
case "$VM" in backtide-prueba-*)
  [ -f "${BACKTIDE_MAC_LAB_YAML:-}" ] || die "las VMs backtide-prueba-* son del laboratorio: hace falta BACKTIDE_MAC_LAB_YAML (su corte de red)" ;;
esac

# The `backtide` of the Mac, as text: written by the install and, to uninstall, run from a copy.
wrapper_text() {
  printf '%s\n' '#!/bin/sh' \
    "# backtide on this Mac: it runs inside the VM $VM (Lima). Written by install-mac.sh (T13b)." \
    '# `backtide vm estado|arrancar|parar|shell` handle the VM; anything else is `sudo backtide`' \
    '# in it. --clave-archivo RUTA is read here and sent through standard input, never as an argument.' \
    'set -eu' "LIMACTL=$(quote "$LIMACTL")" "VM=$VM" "PORT=$HOST_PORT" \
    "LIMA_HOME=$(quote "$LIMA_HOME"); export LIMA_HOME"
  cat <<'WRAPPER'
die() { echo "backtide: $*" >&2; exit 1; }
for file in default.yaml override.yaml base.yaml; do
  [ ! -e "$LIMA_HOME/_config/$file" ] || die "$LIMA_HOME/_config/$file cambiaría la VM (podría montar carpetas tuyas): quítalo"
done
status=$("$LIMACTL" list --format '{{.Status}}' "$VM" 2>/dev/null < /dev/null || true)
if [ "${1:-}" = desinstalar ]; then  # T13-4: by default the VM stays, stopped, with the data in it
  shift; erase=0 yes=0 me=$HOME/.local/bin/backtide
  for arg in "$@"; do case "$arg" in --borrar-datos) erase=1 ;; --si) yes=1 ;;
    *) die "en el Mac, desinstalar solo admite --borrar-datos y --si" ;; esac; done
  [ -x "$LIMACTL" ] || die "no está $LIMACTL (la Lima de esta instalación): no se toca nada"
  [ -z "$status" ] || head -n 1 "$LIMA_HOME/$VM/lima.yaml" 2>/dev/null | grep -q '^# backtide-mac:' \
    || die "la VM $VM no es la de backtide: no se toca"
  ours() { head -n 2 "$me" 2>/dev/null | grep -q '^# backtide on this Mac'; }
  if [ "$erase" = 0 ] && { [ -z "$status" ] || { [ "$status" = Stopped ] && ! ours; }; }; then
    echo "No queda nada de backtide que quitar${status:+: la VM $VM sigue, parada, con tus datos}."; exit 0
  fi
  if [ "$erase" = 1 ]; then
    echo "Se borrará PARA SIEMPRE la VM $VM y todo lo que tiene: la caja negra, el trabajo del agente y sus instantáneas."
    if [ "$yes" = 0 ]; then
      [ -t 0 ] || die "sin terminal hace falta --si"
      printf 'Para seguir, escribe el nombre de la VM (%s): ' "$VM"; read -r answer
      [ "$answer" = "$VM" ] || die "el nombre no coincide: no se ha tocado nada"
    fi
    urls=
    if [ -n "$status" ]; then
      urls=$("$LIMACTL" list --format '{{range .Config.Images}}{{.Location}} {{end}}' "$VM" < /dev/null)
      "$LIMACTL" delete --force "$VM" < /dev/null || die "Lima no pudo borrar la VM $VM"
    fi
    # The VMs left in LIMA_HOME; no answer is no proof there are none (review of T13-4, R1).
    others=$("$LIMACTL" list --quiet < /dev/null 2>/dev/null) || die "Lima no puede listar sus VMs: no se borra nada más"
    # A LIMA_HOME the install made, emptied of our VM just now, holding only Lima's own files.
    if [ -n "$status" ] && [ -z "$others" ] && [ "$(cat "$HOME/.backtide/lima-home" 2>/dev/null)" = "$LIMA_HOME" ]; then
      for entry in "$LIMA_HOME"/* "$LIMA_HOME"/.[!.]*; do
        [ -e "$entry" ] || continue
        case "${entry##*/}" in
          _networks | _cache) ;;
          _config) for f in "$entry"/* "$entry"/.[!.]*; do [ -e "$f" ] || continue
              case "${f##*/}" in networks.yaml | user | user.pub) ;; *) die "$LIMA_HOME tiene $f, que no es de Lima: no se borra" ;; esac; done ;;
          *) die "$LIMA_HOME tiene ${entry##*/}, que no es de Lima ni de backtide: no se borra" ;;
        esac
      done
      rm -rf "$LIMA_HOME"
    fi
    case "$LIMACTL" in "$HOME/.backtide/lima/"*/bin/limactl)  # ours: only if no other VM uses it
      if [ -n "$others" ]; then
        echo "backtide: la Lima de $HOME/.backtide se queda: la usan otras VMs"
      else
        for url in $urls; do  # Lima's download of the VM's image, in its cache (by the URL's hash)
          h=$(printf '%s' "$url" | shasum -a 256 | cut -d' ' -f1)
          case "$h" in *[!0-9a-f]* | "") continue ;; esac
          [ "${#h}" != 64 ] || rm -rf "$HOME/Library/Caches/lima/download/by-url-sha256/$h"
        done
        rm -rf "${LIMACTL%/bin/limactl}"
        c=$HOME/Library/Caches/lima; rmdir "$c/download/by-url-sha256" "$c/download" "$c" 2>/dev/null || true
      fi ;;
    esac
    [ -n "$others" ] || rm -f "$HOME/.backtide/lima-home"
    rmdir "$HOME/.backtide/lima" "$HOME/.backtide" 2>/dev/null || true
  else
    if [ "$yes" = 0 ]; then
      [ -t 0 ] || die "sin terminal hace falta --si"
      printf 'Se quitará backtide de la VM %s, que se queda parada con tus datos. ¿Seguimos? [s/N] ' "$VM"
      read -r answer; case "$answer" in s | S | si | sí | Si | Sí) ;; *) die "no se ha tocado nada" ;; esac
    fi
    [ "$status" = Running ] || "$LIMACTL" start --tty=false "$VM" < /dev/null >&2
    # The command, or the program itself if a run that stopped took the command already (R4).
    inner=$("$LIMACTL" shell --workdir / "$VM" -- sh -c 'for p in /usr/local/bin/backtide /opt/backtide/current/.venv/bin/backtide; do [ -x "$p" ] && { echo "$p"; exit 0; }; done; echo ninguno' < /dev/null) \
      || die "no se pudo mirar dentro de la VM $VM: no se ha desinstalado nada; vuelve a ejecutarlo"
    stopped="la desinstalación dentro de la VM se ha parado (arriba dice dónde): vuelve a ejecutarla"
    case "$inner" in
      ninguno) ;;
      /usr/local/bin/backtide) "$LIMACTL" shell --workdir / "$VM" -- sudo backtide desinstalar --si < /dev/null || die "$stopped" ;;
      /opt/backtide/current/.venv/bin/backtide)
        "$LIMACTL" shell --workdir / "$VM" -- sudo /opt/backtide/current/.venv/bin/backtide desinstalar --si < /dev/null || die "$stopped" ;;
      *) die "respuesta rara de la VM: no se ha desinstalado nada" ;;
    esac
    "$LIMACTL" stop "$VM" < /dev/null || die "Lima no pudo parar la VM $VM"
  fi
  ! ours || rm -f "$me"
  if [ "$erase" = 1 ]; then echo "backtide está desinstalado: la VM $VM y la caja negra se han borrado para siempre."; exit 0; fi
  lh=; [ "$LIMA_HOME" = "$HOME/.lima" ] || lh="LIMA_HOME=$LIMA_HOME "
  cat <<EOF
backtide está desinstalado. La VM $VM se queda PARADA con tus datos ($(du -sh "$LIMA_HOME/$VM" | cut -f1) en $LIMA_HOME/$VM):
la caja negra y su clave, el trabajo del agente y sus instantáneas, y las claves, en /var/lib/backtide.
  - Volver a instalar sobre ellos: el mismo \`sh install-mac.sh --desde ...\` (usa esta VM).
  - Verlos: $lh$LIMACTL start $VM y luego $lh$LIMACTL shell $VM.
  - Borrarlo todo, para siempre: sh install-mac.sh --desinstalar --borrar-datos.
EOF
  exit 0
fi
[ -n "$status" ] || die "no existe la VM $VM: vuelve a ejecutar install-mac.sh"
# The web's port on this Mac must be Lima's forward to the VM, and nobody else's.
web_port_is_ours() {
  n=0
  while :; do
    who=$(lsof -nP -t -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)
    [ -z "$who" ] || break
    n=$((n + 1)); [ "$n" -lt 15 ] || die "el puerto $PORT del Mac no está reenviado a la VM: \`backtide vm parar\` y otra vez"
    sleep 1
  done
  [ "$who" = "$(cat "$LIMA_HOME/$VM/ha.pid" 2>/dev/null)" ] \
    || die "el puerto $PORT del Mac lo tiene otro programa (pid $who), no la VM: el enlace llegaría a él"
}
if [ "${1:-}" = vm ]; then
  case "${2:-}" in
    estado) exec "$LIMACTL" list "$VM" ;;
    arrancar) exec "$LIMACTL" start --tty=false "$VM" ;;
    parar) exec "$LIMACTL" stop "$VM" ;;
    shell) exec "$LIMACTL" shell --workdir / "$VM" ;;
    *) echo "uso: backtide vm estado|arrancar|parar|shell" >&2; exit 2 ;;
  esac
fi
if [ "$status" != Running ]; then
  echo "backtide: la VM $VM está parada; arrancándola..." >&2
  "$LIMACTL" start --tty=false "$VM" < /dev/null >&2
  web_port_is_ours
elif [ "${1:-}" = enlace ]; then
  web_port_is_ours
fi
key=
left=$#
while [ "$left" -gt 0 ]; do
  arg=$1; shift; left=$((left - 1))
  case "$arg" in
    --clave-archivo) [ "$left" -gt 0 ] || { echo "backtide: --clave-archivo necesita un valor" >&2; exit 2; }
      key=$1; shift; left=$((left - 1)); set -- "$@" --clave-stdin ;;
    --clave-archivo=*) key=${arg#--clave-archivo=}; set -- "$@" --clave-stdin ;;
    --clave-stdin) [ ! -t 0 ] || die "--clave-stdin lee de una tubería o un archivo, no de la terminal: usa --clave-archivo RUTA"
      set -- "$@" "$arg" ;;
    *) set -- "$@" "$arg" ;;
  esac
done
if [ -n "$key" ]; then
  [ -f "$key" ] && [ -r "$key" ] || die "no se puede leer $key"
  exec "$LIMACTL" shell --workdir / "$VM" -- sudo backtide "$@" < "$key"
fi
exec "$LIMACTL" shell --workdir / "$VM" -- sudo backtide "$@"
WRAPPER
}

if [ "$UNINSTALL" = 1 ]; then  # through the `backtide` it left, or a copy of it if it is gone
  BIN=$HOME/.local/bin
  [ $# = 0 ] && [ "$DRY_RUN" = 0 ] && [ -z "$SOURCE$SOURCE_SHA256$KEY_FILE$KEY_MODE" ] \
    || die "--desinstalar solo admite --borrar-datos y --si (sin --dry-run: lo que haría, lo dice antes de preguntar)"
  set --; [ "$ERASE" = 0 ] || set -- --borrar-datos; [ "$YES" = 0 ] || set -- "$@" --si
  ! head -n 2 "$BIN/backtide" 2>/dev/null | grep -q '^# backtide on this Mac' || exec sh "$BIN/backtide" desinstalar "$@"
  LIMA_HOME=${LIMA_HOME:-$HOME/.lima}; HOST_PORT=$WEB_PORT; export LIMA_HOME
  LIMACTL=$(command -v limactl 2>/dev/null || true)
  "${LIMACTL:-false}" --version 2>/dev/null | grep -q '^limactl version [2-9]' || LIMACTL=$HOME/.backtide/lima/$LIMA_VERSION/bin/limactl
  [ -x "$LIMACTL" ] || { say "no hay Lima ni orden backtide: no queda nada de backtide que quitar"; exit 0; }
  copy=$(mktemp "${TMPDIR:-/tmp}/backtide-desinstalar.XXXXXX"); wrapper_text > "$copy"
  code=0; sh "$copy" desinstalar "$@" || code=$?; rm -f "$copy"; exit "$code"
fi

cat <<'NOTICE'
backtide is a PREVIEW, with no human security audit yet.
  - Use a model key with a spending limit, never a production key.
  - A rewind does not bring back what already left the machine, and calls to the model are never held.
  - On a Mac: when it sleeps, the agent and its alerts sleep; the agent's files live in the VM.
  - Supported: Linux (Fedora, Ubuntu) and Macs with Apple Silicon. On Fedora with kernel 7.1+ the
    process sensor does not start (D24).
  - To remove it: backtide desinstalar (keeps your data; --borrar-datos removes everything).
NOTICE

# 1. The Mac.
[ "$(uname -s)" = Darwin ] || die "esto es para un Mac; en Linux, sudo sh install.sh"
case "$(uname -m)" in
  arm64) ;;
  x86_64) die "los Mac con Intel aún no (T13b empieza por Apple Silicon): de momento, un Linux con install.sh" ;;
  *) die "arquitectura $(uname -m) no admitida" ;;
esac
[ "$(id -u)" != 0 ] || die "sin sudo: ejecútalo como tú (la VM tiene su propio root)"
for tool in curl tar shasum mktemp lsof sysctl sw_vers df; do
  command -v "$tool" >/dev/null 2>&1 || die "falta $tool"
done
macos=$(sw_vers -productVersion)
major=${macos%%.*}; minor=$(printf '%s' "$macos" | cut -d. -f2); minor=${minor:-0}
[ "$major" -gt 13 ] || { [ "$major" = 13 ] && [ "$minor" -ge 5 ]; } \
  || die "macOS $macos: hace falta 13.5 o posterior (la virtualización de Apple)"
memory_gib=$(( $(sysctl -n hw.memsize) / 1073741824 ))
[ "$memory_gib" -ge "$MIN_MEMORY_GIB" ] || die "este Mac tiene $memory_gib GiB de memoria; la VM usa 6 y hacen falta $MIN_MEMORY_GIB"
if [ "$KEY_MODE" = file ]; then
  [ -f "$KEY_FILE" ] && [ -r "$KEY_FILE" ] || die "no se puede leer el archivo de la clave $KEY_FILE"
fi

LIMA_HOME=${LIMA_HOME:-$HOME/.lima}
case "$LIMA_HOME" in /*) ;; *) LIMA_HOME=$PWD/$LIMA_HOME ;; esac  # the wrapper keeps it absolute
export LIMA_HOME
for file in default.yaml override.yaml base.yaml; do
  [ ! -e "$LIMA_HOME/_config/$file" ] \
    || die "$LIMA_HOME/_config/$file cambiaría la VM de backtide (podría montar carpetas tuyas): quítalo o usa otro LIMA_HOME"
done
# 3a. The archive, checked before anything is written.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/backtide-mac.XXXXXX")
ECHO_OFF=0
# Ctrl-C (at the key's prompt too) stops everything; the exit puts the terminal back and cleans.
trap '[ "$ECHO_OFF" = 0 ] || stty echo; rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM
ARCHIVE=$WORK/backtide.tar
if [ -n "$SOURCE" ]; then
  [ -n "$SOURCE_SHA256" ] || die "con --desde hace falta --sha256 (la huella que te dio quien te pasó el archivo)"
  [ -f "$SOURCE" ] || die "no existe $SOURCE"
  cp "$SOURCE" "$ARCHIVE" || die "no se pudo copiar $SOURCE"
  WANT=$SOURCE_SHA256
else
  [ -n "$BACKTIDE_URL" ] || die "aún no hay versión publicada: usa --desde ARCHIVO --sha256 HUELLA"
  curl -fsSL --proto =https --tlsv1.2 -o "$ARCHIVE" "$BACKTIDE_URL" || die "no se pudo descargar $BACKTIDE_URL"
  WANT=$BACKTIDE_SHA256
fi
GOT=$(hash_of "$ARCHIVE")
[ "$GOT" = "$WANT" ] || die "la huella del archivo es $GOT y debía ser $WANT: no se usa"
say "archivo comprobado (sha256 $GOT)"
TEMPLATE=$(tar -tf "$ARCHIVE" | grep -E '^(\./)?([^/]+/)?lima/backtide-mac\.yaml$' | head -n 1 || true)
[ -n "$TEMPLATE" ] || die "el archivo no trae lima/backtide-mac.yaml: no es una versión de backtide para Mac"
tar -xOf "$ARCHIVE" "$TEMPLATE" > "$WORK/backtide-mac.yaml"
head -n 1 "$WORK/backtide-mac.yaml" | grep -q '^# backtide-mac:' || die "lima/backtide-mac.yaml no es la plantilla de backtide"
# A test VM may forward the web to another port of the Mac (tests/install/instalar_mac_lab.sh).
HOST_PORT=$WEB_PORT
case "$VM" in backtide-prueba-*) HOST_PORT=${BACKTIDE_MAC_LAB_PORT:-$WEB_PORT} ;; esac
case "$HOST_PORT" in "" | *[!0-9]*) die "puerto de prueba no válido" ;; esac
listener=$(lsof -nP -t -iTCP:"$HOST_PORT" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)
if [ -n "$listener" ] && [ "$listener" != "$(cat "$LIMA_HOME/$VM/ha.pid" 2>/dev/null || true)" ]; then
  die "el puerto $HOST_PORT del Mac ya lo usa $(clean "$(ps -p "$listener" -o comm= 2>/dev/null || echo otro programa)") (pid $listener): ciérralo y vuelve a ejecutarlo"
fi
# The lab's network cut goes in at the first boot of a test VM, before Docker exists (invariant 8).
case "$VM" in backtide-prueba-*) cat "$BACKTIDE_MAC_LAB_YAML" >> "$WORK/backtide-mac.yaml" ;; esac

if [ "$DRY_RUN" = 1 ]; then
  say "--dry-run: usaría Lima ${LIMA_VERSION} (la tuya si es 2.x), crearía la VM $VM (4 CPU, 6 GiB,"
  say "40 GiB, sin carpetas del Mac, solo el puerto $WEB_PORT), instalaría backtide dentro y"
  say "dejaría $HOME/.local/bin/backtide. No se ha cambiado nada."
  exit 0
fi
if [ "$YES" != 1 ]; then
  [ -t 0 ] || die "sin terminal hace falta --si para seguir"
  printf 'Se creará (o se pondrá al día) la VM %s con backtide dentro. ¿Seguimos? [s/N] ' "$VM"
  read -r answer; case "$answer" in s | S | si | sí | Si | Sí) ;; *) die "no se ha cambiado nada" ;; esac
fi

# 2. Lima: yours if it is 2.x; otherwise the pinned one, in a folder of ours.
lima_major() { "$1" --version 2>/dev/null 3<&- | sed -n 's/^limactl version \([0-9][0-9]*\)\..*/\1/p'; }
LIMACTL=$(command -v limactl 2>/dev/null || true)
lmajor=; [ -z "$LIMACTL" ] || lmajor=$(lima_major "$LIMACTL")
case "$lmajor" in "" | 0 | 1) LIMACTL= ;; esac
# Absolute, for the wrapper (a PATH entry may be relative).
[ -z "$LIMACTL" ] || LIMACTL=$(cd "$(dirname "$LIMACTL")" && pwd -P)/$(basename "$LIMACTL")
if [ -z "$LIMACTL" ]; then
  LIMA_DIR=$HOME/.backtide/lima/$LIMA_VERSION
  LIMACTL=$LIMA_DIR/bin/limactl
  if [ ! -x "$LIMACTL" ] || [ "$("$LIMACTL" --version 2>/dev/null 3<&-)" != "limactl version $LIMA_VERSION" ]; then
    say "descargando Lima $LIMA_VERSION"
    curl -fsSL --proto =https --tlsv1.2 -o "$WORK/lima.tar.gz" \
      "https://github.com/lima-vm/lima/releases/download/v$LIMA_VERSION/lima-$LIMA_VERSION-Darwin-arm64.tar.gz" \
      || die "no se pudo descargar Lima"
    [ "$(hash_of "$WORK/lima.tar.gz")" = "$LIMA_SHA256_ARM64" ] || die "la huella de Lima no es la esperada: no se usa"
    mkdir -p "$WORK/lima" "$HOME/.backtide/lima"
    tar -xzf "$WORK/lima.tar.gz" -C "$WORK/lima"
    rm -rf "$LIMA_DIR" && mv "$WORK/lima" "$LIMA_DIR"
  fi
fi
lima() { "$LIMACTL" "$@" 3<&-; }  # every Lima call but the install: no key's descriptor
say "Lima: $LIMACTL ($(lima --version))"

# 3b. The VM: made once from the template, started if it is stopped, and never someone else's.
status=$(lima list --format '{{.Status}}' "$VM" 2>/dev/null || true)
if [ -z "$status" ]; then
  free_gib=$(( $(df -k "$HOME" | awk 'NR == 2 {print $4}') / 1048576 ))
  [ "$free_gib" -ge "$MIN_FREE_GIB" ] || die "quedan $free_gib GiB libres; hacen falta $MIN_FREE_GIB (la VM, Fedora y las imágenes)"
  # Lima's ssh socket lives in the VM's folder, with its real path: it must fit in 104 bytes.
  # A LIMA_HOME made here is ours to remove with the VM (`backtide desinstalar --borrar-datos`).
  if [ ! -e "$LIMA_HOME" ]; then mkdir -p "$HOME/.backtide" && printf '%s\n' "$LIMA_HOME" > "$HOME/.backtide/lima-home"; fi
  mkdir -p "$LIMA_HOME"
  sock="$(cd "$LIMA_HOME" && pwd -P)/$VM/ssh.sock.0123456789abcdef"
  [ "${#sock}" -lt 104 ] || die "la ruta de Lima ($LIMA_HOME) es demasiado larga para sus sockets: usa un LIMA_HOME más corto"
  say "creando la VM $VM (la primera vez descarga Fedora 44: unos minutos)"
  lima create --tty=false --name "$VM" \
    --set ".portForwards[0].hostPort = $HOST_PORT" "$WORK/backtide-mac.yaml" < /dev/null || die "Lima no pudo crear la VM"
  status=Stopped
fi
head -n 1 "$LIMA_HOME/$VM/lima.yaml" 2>/dev/null | grep -q '^# backtide-mac:' \
  || die "ya hay una VM $VM que no es la de backtide: no se toca"
# What Lima will really apply (its lima.yaml, filled with defaults and any _config file): no
# mount, and the template's three port rules. Checked on every run, before the VM starts.
mounts=$(lima list --format '{{len .Config.Mounts}}' "$VM" 2>/dev/null) || die "Lima no puede leer la VM $VM"
[ "$mounts" = 0 ] || die "la VM $VM tiene $(clean "$mounts") carpetas del Mac montadas: no se toca (bórrala con limactl delete $VM)"
FORWARDS_WANT="127.0.0.1 [8765 8765] 127.0.0.1 [$HOST_PORT $HOST_PORT] tcp false;0.0.0.0 [1 65535] 127.0.0.1 [1 65535] any true;:: [1 65535] 127.0.0.1 [1 65535] any true;"
forwards=$(lima list --format '{{range .Config.PortForwards}}{{.GuestIP}} {{.GuestPortRange}} {{.HostIP}} {{.HostPortRange}} {{.Proto}} {{.Ignore}};{{end}}' "$VM") \
  || die "Lima no puede leer la VM $VM"
[ "$forwards" = "$FORWARDS_WANT" ] || die "los puertos de la VM $VM no son los de la plantilla ($(clean "$forwards")): no se toca"
if [ "$status" != Running ]; then
  say "arrancando la VM $VM"
  lima start --tty=false "$VM" < /dev/null || die "Lima no pudo arrancar la VM: mira $LIMA_HOME/$VM/ha.stderr.log"
fi
in_vm() { "$LIMACTL" shell --workdir / "$VM" -- "$@"; }
# Every call but the install gets no standard input and no fd 3: only that one may carry a key.
probe() { in_vm "$@" < /dev/null 3<&-; }
# findmnt says 1 when it finds nothing: that is the good answer; anything else is a failure.
shared=$(probe sh -c 'findmnt -rn -o TARGET -t virtiofs,9p,fuse.sshfs,nfs,nfs4,cifs,smb3 || [ $? = 1 ]') \
  || die "no se pudo mirar dentro de la VM qué tiene montado"
[ -z "$shared" ] || die "la VM ve carpetas del Mac ($(clean "$shared")): no se instala nada en ella"

# 4. backtide inside: the same archive, checked again there, and the Linux install.sh.
# Into the Lima user's home, not a shared /tmp: nobody else in the VM can swap it.
VM_HOME=$(probe printenv HOME) || die "no se pudo hablar con la VM"
case "$VM_HOME" in /home/*[!a-zA-Z0-9._/-]*) die "carpeta de la VM rara: $(clean "$VM_HOME")" ;; /home/*) ;;
  *) die "no se encuentra la carpeta de tu usuario en la VM ($(clean "$VM_HOME"))" ;; esac
VM_ARCHIVE=$VM_HOME/backtide-mac.tar
probe rm -f "$VM_ARCHIVE"
lima copy "$ARCHIVE" "$VM:$VM_ARCHIVE" < /dev/null || die "no se pudo copiar el archivo a la VM"
INNER='set -eu; a=$1; h=$2; shift 2; d=$(mktemp -d); trap '\''rm -rf "$d" "$a"'\'' EXIT
[ "$(sha256sum "$a" | cut -d" " -f1)" = "$h" ] || { echo "backtide: la copia de la VM no tiene la huella" >&2; exit 1; }
tar -xf "$a" -C "$d" --no-same-owner; s=$d/install.sh
[ -f "$s" ] || s=$(find "$d" -mindepth 2 -maxdepth 2 -name install.sh | head -n 1)
sh "$s" --desde "$a" --sha256 "$h" --sin-aviso "$@"'
install_in_vm() { in_vm sudo sh -c "$INNER" sh "$VM_ARCHIVE" "$GOT" --si "$@"; }
say "instalando backtide dentro de la VM (la primera vez, unos minutos)"
case "$KEY_MODE" in
  file) install_in_vm --clave-stdin "$@" < "$KEY_FILE" 3<&- ;;
  stdin) install_in_vm --clave-stdin "$@" <&3 3<&- ;;
  none) install_in_vm --sin-clave "$@" 3<&- ;;
  *)
    if ! probe sudo test -e "/var/lib/backtide/keys/$PROVIDER.key" && [ -t 0 ]; then
      printf 'Clave de %s (no se ve al escribirla; vacío para ponerla después): ' "$PROVIDER"
      ECHO_OFF=1; stty -echo; read -r key || key=; stty echo; ECHO_OFF=0; printf '\n'
      if [ -n "$key" ]; then printf '%s\n' "$key" | install_in_vm --clave-stdin "$@" 3<&-; key=
      else install_in_vm "$@" < /dev/null 3<&-; fi
    else
      install_in_vm "$@" < /dev/null 3<&-
    fi ;;
esac || die "la instalación dentro de la VM se ha parado (arriba dice dónde); vuelve a ejecutar esto para seguir"

# 5. The `backtide` of the Mac: rewritten only when it changes.
BIN=$HOME/.local/bin
mkdir -p "$BIN"
wrapper_text > "$WORK/backtide"
if ! cmp -s "$WORK/backtide" "$BIN/backtide"; then
  chmod 0755 "$WORK/backtide" && mv "$WORK/backtide" "$BIN/backtide"
  say "orden backtide en $BIN/backtide"
fi
case ":$PATH:" in *":$BIN:"*) ;; *) say "añade $BIN a tu PATH para usar \`backtide\` (o llámalo por su ruta)" ;; esac

cat <<EOF

backtide está instalado en la VM $VM de este Mac y vigila al agente.
  - La web, solo en este Mac: \`backtide enlace\` da su enlace de un uso (http://127.0.0.1:$WEB_PORT/...).
  - El estado: \`backtide comprobar --despues-de-instalar\`; la VM: \`backtide vm estado\`.
  - Quitarlo: \`backtide desinstalar\` (conserva tus datos en la VM, parada; --borrar-datos lo borra todo).
  - Telegram todavía no: se pondrá en la página Ajustes de la web.
Lo que hay que saber de un Mac:
  - Si el Mac duerme, la VM duerme: el agente se para y no llegan avisos hasta que despierta.
  - Tras reiniciar el Mac la VM queda parada: cualquier \`backtide ...\` la arranca, o \`backtide vm arrancar\`.
  - Los archivos del agente viven en la VM, no en tu Mac: \`backtide exportar\` los copia a una carpeta
    de la VM y \`backtide vm shell\` te lleva allí (traerlos al Mac de un paso aún no está).
  - Al despertar, Lima pone la hora de la VM con la del Mac en unos segundos; \`backtide comprobar\` lo mira.
EOF
