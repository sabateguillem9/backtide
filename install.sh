#!/bin/sh
# backtide's installer bootstrap (docs/25, section 4). Read it before running it: it is short.
#
#   curl -fsSL <url>/install.sh -o install.sh && less install.sh && sudo sh install.sh
#
# What it does, and nothing else:
#   1. checks it runs as root on Ubuntu 24.04/26.04 or Fedora 43/44, x86_64 or aarch64;
#   2. downloads uv (a pinned version, checked against its sha256 below) to /opt/backtide/uv;
#   3. gets backtide (the release this script names, or --desde ARCHIVE --sha256 HEX), checks
#      its sha256, and installs it in /opt/backtide/releases/<version>-<hash> with its own
#      Python 3.12 and its locked dependencies (uv sync --locked --no-dev). Not locked yet: the
#      build backend (hatchling, from PyPI) that uv uses to install backtide itself (T14);
#   4. hands over to `backtide instalar`, which does the rest step by step, asks before it
#      touches anything that is not backtide's, and can be run again safely.
# Every other argument goes to `backtide instalar` (see `backtide instalar --help`). Keys never
# go in an argument: use --clave-archivo FILE, --clave-stdin, or type it when asked.
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
    --dry-run) DRY_RUN=1; set -- "$@" "$arg" ;;
    --sin-aviso) NOTICE=0 ;;  # install-mac.sh has shown the notice already
    *) set -- "$@" "$arg" ;;
  esac
done

[ "$NOTICE" = 0 ] || cat <<'EOF'
backtide is a PREVIEW, with no human security audit yet.
  - Use a model key with a spending limit, never a production key.
  - A rewind does not bring back what already left the machine, and calls to the model are never held.
  - Supported: Linux (Fedora, Ubuntu) and Macs with Apple Silicon. On Fedora with kernel 7.1+ the
    process sensor does not start (D24).
  - To remove it: sudo backtide desinstalar (keeps your data; --borrar-datos removes everything).
EOF
[ "$(id -u)" = 0 ] || die "hace falta root: sudo sh install.sh"
[ -r /etc/os-release ] || die "no se puede leer /etc/os-release"
DISTRO=$(. /etc/os-release && printf '%s %s' "$ID" "$VERSION_ID")
case "$DISTRO" in
  "ubuntu 24.04" | "ubuntu 26.04" | "fedora 43" | "fedora 44") ;;
  *) die "$DISTRO no es una de las que admite backtide (Ubuntu 24.04 o 26.04, Fedora 43 o 44)" ;;
esac
case "$(uname -m)" in
  x86_64) UV_TRIPLE=x86_64-unknown-linux-gnu; UV_SHA256=$UV_SHA256_X86_64 ;;
  aarch64) UV_TRIPLE=aarch64-unknown-linux-gnu; UV_SHA256=$UV_SHA256_AARCH64 ;;
  *) die "arquitectura $(uname -m) no admitida: x86_64 o aarch64" ;;
esac
for tool in curl tar sha256sum mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "falta $tool"
done

hash_of() { sha256sum "$1" | cut -d' ' -f1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# The release: a local archive (until T14) or the published one, checked either way.
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

if [ "$DRY_RUN" = 1 ]; then
  say "--dry-run: instalaría uv $UV_VERSION en $OPT/uv, esta versión en $OPT/releases y"
  say "después ejecutaría \`backtide instalar\`. No se ha cambiado nada."
  [ -x "$OPT/current/.venv/bin/backtide" ] && exec "$OPT/current/.venv/bin/backtide" instalar "$@"
  exit 0
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

mkdir "$WORK/src"
tar -xf "$ARCHIVE" -C "$WORK/src" --no-same-owner --no-same-permissions
TOP=$WORK/src
[ -f "$TOP/pyproject.toml" ] || TOP=$(find "$WORK/src" -mindepth 2 -maxdepth 2 -name pyproject.toml -exec dirname {} \; | head -n 1)
[ -n "$TOP" ] && [ -f "$TOP/pyproject.toml" ] && [ -f "$TOP/uv.lock" ] || die "el archivo no es una versión de backtide"
VERSION=$(sed -n 's/^version = "\([0-9A-Za-z.+-]*\)"$/\1/p' "$TOP/pyproject.toml" | head -n 1)
[ -n "$VERSION" ] || die "no se encuentra la versión en pyproject.toml"
RELEASE=$OPT/releases/$VERSION-$(printf '%s' "$GOT" | cut -c1-12)

export UV_PYTHON_INSTALL_DIR="$OPT/python" UV_PYTHON_PREFERENCE=only-managed \
  UV_CACHE_DIR="$OPT/cache" UV_NO_CONFIG=1
if [ -x "$RELEASE/.venv/bin/backtide" ]; then
  say "esta versión ya está en $RELEASE"
else
  # A release folder without its program is one a cut left half made: made again.
  say "instalando $VERSION en $RELEASE"
  rm -rf "$RELEASE"
  mv "$TOP" "$RELEASE"
  "$UV" sync --quiet --locked --no-dev --python 3.12 --project "$RELEASE" \
    || { rm -rf "$RELEASE"; die "uv no pudo instalar las dependencias"; }
fi
chown -R root:root "$OPT"
chmod -R go-w "$OPT"
# SELinux: what came from the temporary folder keeps its label there (user_tmp_t), and systemd
# may not run it (seen in Fedora 44, T13-3). Give everything /opt's own labels.
if command -v restorecon >/dev/null 2>&1; then restorecon -RF "$OPT"; fi
ln -sfn "releases/$(basename "$RELEASE")" "$OPT/current.tmp"
mv -T "$OPT/current.tmp" "$OPT/current"

say "pasando a \`backtide instalar\`"
exec "$OPT/current/.venv/bin/backtide" instalar "$@"
