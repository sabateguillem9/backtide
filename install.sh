#!/bin/sh
# backtide's installer bootstrap (docs/25, section 4). Read it before running it: it is short.
#
#   curl -fsSL <url>/install.sh -o install.sh && less install.sh && sudo sh install.sh
#
# What it does, and nothing else:
#   1. checks it runs as root on Ubuntu 24.04/26.04 or Fedora 43/44, x86_64 or aarch64 (tested so
#      far: Fedora 44 and Ubuntu 24.04 on aarch64; the others are accepted and said untested);
#   2. gets the release (the one this script names, or --desde ARCHIVE --sha256 HEX), checks its
#      sha256 and, before writing anything, that its requirements.txt pins every dependency with
#      == and its sha256 (and holds nothing else: no options, URLs, paths or editables);
#   3. downloads uv (a pinned version, checked against its sha256 below) to /opt/backtide/uv;
#   4. installs the release in /opt/backtide/releases/<version>-<hash>: uv's own Python 3.12
#      (checked by uv against the hash it carries) and only wheels, each checked against its
#      sha256 (--require-hashes --no-build). NOTHING IS BUILT: backtide itself is not installed
#      as a package, its folder goes on the path and .venv/bin/backtide runs it with python -I;
#   5. hands over to `backtide instalar`, which does the rest step by step, asks before it
#      touches anything that is not backtide's, and can be run again safely.
# A release is made with `make release` (scripts/release/); a plain `git archive` is refused.
# Every other argument goes to `backtide instalar` (see `backtide instalar --help`), such as
# --perfil claude-code or --telegram. Keys never go in an argument: use --clave-archivo FILE,
# --clave-stdin, or type it when asked.
set -eu

# On a Mac, backtide lives in a Linux VM of its own: install-mac.sh, next to this file, makes it.
if [ "$(uname -s)" = Darwin ]; then
  case "$0" in */install.sh | install.sh) MAC=$(dirname "$0")/install-mac.sh ;; *) MAC= ;; esac
  [ -n "$MAC" ] && [ -f "$MAC" ] || { printf '%s\n' "backtide: en un Mac, sh install-mac.sh (sin sudo; va junto a install.sh)" >&2; exit 1; }
  exec sh "$MAC" "$@"
fi

UV_VERSION=0.12.17
UV_SHA256_X86_64=fa82fd8dde8e8eefdecada6aa0889666556cfceb690d06e0c3bca49eb3070a63
UV_SHA256_AARCH64=d636d1b678e9e7f367ecb22b46bd1cabbed234d6bc3b4d96365d2b507f72f86c
# The published release this script installs: empty until the first (T14); use --desde --sha256.
BACKTIDE_URL=
BACKTIDE_SHA256=
OPT=/opt/backtide
say() { printf '%s\n' "backtide: $*"; }
die() { printf '%s\n' "backtide: $*" >&2; exit 1; }
# requirements.txt as `uv export --hashes --no-header --no-annotate` writes it, and nothing else:
# only the bytes it uses (no comment, tab, \r or non-ASCII), each line `name==version [; markers]`
# and one or more `--hash=sha256:<64 hex>`, joined only at a final ` \` (review of T14-R1).
check_requirements() {
  [ "$(LC_ALL=C tr -d 'A-Za-z0-9 ._=:;<>!~()"\\+\n'"'"'-' < "$1" | wc -c | tr -d ' ')" = 0 ] \
    || { printf '%s\n' "backtide: requirements.txt tiene bytes que uv export no escribe (#, tabuladores, \\r, no ASCII…)" >&2; return 1; }
  awk '
    function bad(why) { printf "backtide: requirements.txt, línea %d: %s\n", NR, why > "/dev/stderr"; failed = 1 }
    /\\$/ { s = substr($0, 1, length($0) - 1); if (index(s, "\\") || s !~ / $/) bad("barra fuera de sitio")
            joined = joined s; next }
    index($0, "\\") { bad("barra fuera de sitio"); joined = ""; next }
    { line = joined $0; joined = ""; n = split(line, t) }
    n == 0 { next }
    t[1] !~ /^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!]+$/ { bad("no es nombre==versión: " t[1]); next }
    {
      i = 2
      if (t[i] == ";") for (i = 3; i <= n && t[i] !~ /^--hash=/; i++)
        if (t[i] !~ /^[A-Za-z0-9_.<>=!~()\047"-]+$/ || t[i] ~ /^-/) { bad("marcador raro: " t[i]); next }
      if (i > n) { bad("sin sha256: " t[1]); next }
      for (; i <= n; i++)
        if (t[i] !~ /^--hash=sha256:[0-9a-f]+$/ || length(t[i]) != 78) { bad("no es una sha256: " t[i]); next }
      pinned++
    }
    END { if (joined != "") bad("acaba en una barra"); if (!pinned) bad("no hay dependencias"); exit failed || !pinned }
  ' "$1"
}
# Nothing of the caller's environment steers uv, curl or the temporary folder: no inherited UV_*
# (UV_PYTHON_DOWNLOADS_JSON_URL could swap the Python), certificate paths or TMPDIR.
clean_env() {
  for name in $(env | sed -n 's/^\(UV_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$name"; done
  unset SSL_CERT_FILE SSL_CERT_DIR TMPDIR
}
# The release's venv: uv's Python 3.12, then only wheels, each against its sha256. backtide is
# not installed as a package (nothing to build): a .pth puts its folder on the venv's path and
# .venv/bin/backtide runs it with `python -I` (no PYTHON* variables, no current folder).
install_release() {
  "$UV" venv --quiet --python 3.12 "$1/.venv" \
    && "$UV" pip install --python "$1/.venv/bin/python" --require-hashes --no-build -r "$1/requirements.txt" \
    && [ -d "$1/.venv/lib/python3.12/site-packages" ] \
    && printf '%s\n' "$1" > "$1/.venv/lib/python3.12/site-packages/backtide-release.pth" \
    && printf '#!%s -I\nimport sys\nfrom backtide.cli import main\nsys.exit(main())\n' "$1/.venv/bin/python" \
      > "$1/.venv/bin/backtide.new" \
    && chmod 0755 "$1/.venv/bin/backtide.new" && mv "$1/.venv/bin/backtide.new" "$1/.venv/bin/backtide"
}

# A file named for `backtide instalar` (--*-archivo), from where this ran: `cd /` comes first (I3).
absolute() {
  case "$1" in /* | -) printf '%s' "$1" ;; *) printf '%s/%s' "$(pwd)" "$1" ;; esac
}

# Take --desde and --sha256 out; everything else stays, in order, for `backtide instalar`.
DRY_RUN=0 SOURCE= SOURCE_SHA256= NOTICE=1
left=$#
while [ "$left" -gt 0 ]; do
  arg=$1; shift; left=$((left - 1))
  case "$arg" in
    --desde | --sha256)
      [ "$left" -gt 0 ] || die "$arg necesita un valor"
      if [ "$arg" = --desde ]; then SOURCE=$1; else SOURCE_SHA256=$1; fi
      shift; left=$((left - 1)) ;;
    --*-archivo) [ "$left" -gt 0 ] || die "$arg necesita un valor"
      set -- "$@" "$arg" "$(absolute "$1")"; shift; left=$((left - 1)) ;;
    --*-archivo=*) set -- "$@" "${arg%%=*}=$(absolute "${arg#*=}")" ;;
    --dry-run) DRY_RUN=1; set -- "$@" "$arg" ;;
    --sin-aviso) NOTICE=0 ;;  # install-mac.sh has shown the notice already
    *) set -- "$@" "$arg" ;;
  esac
done

[ "$NOTICE" = 0 ] || cat <<'EOF'
backtide is a PREVIEW, with no human security audit yet.
  - Use a model key with a spending limit, never a production key.
  - A rewind does not bring back what already left the machine, and calls to the model are never held.
  - Tested: Fedora 44 and Ubuntu 24.04 on arm64 (aarch64), and Macs with Apple Silicon. Fedora 43,
    Ubuntu 26.04 and x86_64 are accepted but untested. On Fedora with kernel 7.1+ the process
    sensor does not start (D24).
  - To remove it: sudo backtide desinstalar (keeps your data; --borrar-datos removes everything).
EOF
[ "$(id -u)" = 0 ] || die "hace falta root: sudo sh install.sh"
clean_env
[ -r /etc/os-release ] || die "no se puede leer /etc/os-release"
DISTRO=$(. /etc/os-release && printf '%s %s' "$ID" "$VERSION_ID")
case "$DISTRO" in
  "ubuntu 24.04" | "fedora 44") ;;
  "ubuntu 26.04" | "fedora 43") say "$DISTRO se admite pero aún no se ha probado (solo Fedora 44 y Ubuntu 24.04)" ;;
  *) die "$DISTRO no es una de las que admite backtide (Ubuntu 24.04 o 26.04, Fedora 43 o 44)" ;;
esac
case "$(uname -m)" in
  x86_64) UV_TRIPLE=x86_64-unknown-linux-gnu; UV_SHA256=$UV_SHA256_X86_64
    say "x86_64 se admite pero aún no se ha probado (solo aarch64)" ;;
  aarch64) UV_TRIPLE=aarch64-unknown-linux-gnu; UV_SHA256=$UV_SHA256_AARCH64 ;;
  *) die "arquitectura $(uname -m) no admitida: x86_64 o aarch64" ;;
esac
for tool in curl tar sha256sum mktemp awk; do
  command -v "$tool" >/dev/null 2>&1 || die "falta $tool"
done

hash_of() { sha256sum "$1" | cut -d' ' -f1; }
WORK=$(mktemp -d /tmp/backtide.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM

# The release: a local archive or the published one, checked either way.
if [ -n "$SOURCE" ]; then
  [ -n "$SOURCE_SHA256" ] || die "con --desde hace falta --sha256 (la huella que te dio quien te pasó el archivo)"
  [ -f "$SOURCE" ] || die "no existe $SOURCE"
  # A copy of our own: what is hashed is what is unpacked, even if $SOURCE changes meanwhile.
  ARCHIVE=$WORK/backtide.tar
  cp "$SOURCE" "$ARCHIVE" || die "no se pudo copiar $SOURCE"
  WANT=$SOURCE_SHA256
else
  [ -n "$BACKTIDE_URL" ] || die "aún no hay versión publicada: usa --desde ARCHIVO --sha256 HUELLA"
  ARCHIVE=$WORK/backtide.tar
  curl -fsSL --proto =https --tlsv1.2 -o "$ARCHIVE" "$BACKTIDE_URL" || die "no se pudo descargar $BACKTIDE_URL"
  WANT=$BACKTIDE_SHA256
fi
GOT=$(hash_of "$ARCHIVE")
[ "$GOT" = "$WANT" ] || die "la huella del archivo es $GOT y debía ser $WANT: no se usa"
say "archivo comprobado (sha256 $GOT)"
cd /  # the archive is ours now: no relative path, and uv runs from no folder of the caller's

# Unpacked and checked in the temporary folder, before anything of this machine changes.
mkdir "$WORK/src"
tar -xf "$ARCHIVE" -C "$WORK/src" --no-same-owner --no-same-permissions
TOP=$WORK/src
[ -f "$TOP/pyproject.toml" ] || TOP=$(find "$WORK/src" -mindepth 2 -maxdepth 2 -name pyproject.toml -exec dirname {} \; | head -n 1)
[ -n "$TOP" ] && [ -f "$TOP/pyproject.toml" ] || die "el archivo no es una versión de backtide"
[ -f "$TOP/requirements.txt" ] \
  || die "el archivo no trae requirements.txt: no es una versión hecha con \`make release\` (un git archive no vale)"
check_requirements "$TOP/requirements.txt" || die "requirements.txt no vale: no se instala nada"
VERSION=$(sed -n 's/^version = "\([0-9A-Za-z.+-]*\)"$/\1/p' "$TOP/pyproject.toml" | head -n 1)
[ -n "$VERSION" ] || die "no se encuentra la versión en pyproject.toml"
RELEASE=$OPT/releases/$VERSION-$(printf '%s' "$GOT" | cut -c1-12)

if [ "$DRY_RUN" = 1 ]; then
  say "--dry-run: instalaría uv $UV_VERSION en $OPT/uv, la versión $VERSION en $RELEASE (sin"
  say "construir nada) y después ejecutaría \`backtide instalar\`. No se ha cambiado nada."
  [ -x "$OPT/current/.venv/bin/backtide" ] || { say "la máquina NO se ha comprobado: sin --dry-run, se comprueba antes de cambiar nada"; exit 0; }
  say "lo de abajo es de la versión ya instalada, no de $VERSION"
  exec "$OPT/current/.venv/bin/backtide" instalar "$@"
fi

umask 022
mkdir -p "$OPT/uv/$UV_VERSION" "$OPT/releases"
chmod 0755 "$OPT" "$OPT/uv" "$OPT/releases"
UV=$OPT/uv/$UV_VERSION/uv
# `uv --version` says "uv 0.12.17 (aarch64-unknown-linux-gnu)": only its first two words count.
if [ ! -x "$UV" ] || [ "$("$UV" --version 2>/dev/null | cut -d' ' -f1,2)" != "uv $UV_VERSION" ]; then
  say "descargando uv $UV_VERSION"
  curl -fsSL --proto =https --tlsv1.2 -o "$WORK/uv.tar.gz" \
    "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$UV_TRIPLE.tar.gz" \
    || die "no se pudo descargar uv"
  [ "$(hash_of "$WORK/uv.tar.gz")" = "$UV_SHA256" ] || die "la huella de uv no es la esperada: no se usa"
  tar -xzf "$WORK/uv.tar.gz" -C "$WORK" --no-same-owner
  install -m 0755 "$WORK/uv-$UV_TRIPLE/uv" "$UV"
fi

export UV_PYTHON_INSTALL_DIR="$OPT/python" UV_PYTHON_PREFERENCE=only-managed \
  UV_CACHE_DIR="$OPT/cache" UV_NO_CONFIG=1
if [ -x "$RELEASE/.venv/bin/backtide" ]; then
  say "esta versión ya está en $RELEASE"
else
  # A release folder without its program is one a cut left half made: made again.
  say "instalando $VERSION en $RELEASE (solo ruedas con su sha256: no se construye nada)"
  rm -rf "$RELEASE"
  mv "$TOP" "$RELEASE"
  install_release "$RELEASE" \
    || { rm -rf "$RELEASE"; die "uv no pudo instalar las dependencias (con sus huellas y sin construir nada)"; }
fi
chown -R root:root "$OPT"
chmod -R go-w "$OPT"
# SELinux: what came from the temporary folder keeps its label there (user_tmp_t), and systemd
# may not run it (seen in Fedora 44, T13-3). Give everything /opt's own labels.
if command -v restorecon >/dev/null 2>&1; then restorecon -RF "$OPT"; fi
# What this run would refuse (another agent, --telegram without its token...) stops it here,
# before the version in use changes.
"$RELEASE/.venv/bin/backtide" instalar --solo-comprobar "$@" < /dev/null || die "no se ha cambiado la versión en uso"
ln -sfn "releases/$(basename "$RELEASE")" "$OPT/current.tmp"
mv -T "$OPT/current.tmp" "$OPT/current"

say "pasando a \`backtide instalar\`"
exec "$OPT/current/.venv/bin/backtide" instalar "$@"
