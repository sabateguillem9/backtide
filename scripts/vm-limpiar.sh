#!/bin/sh
# Removes backtide's own leftovers from the dev VM (`make vm-limpiar`), and prints what it removed:
# - containers (stopped or running) named backtide-*, vigia-demo-* (the demo before the rename);
#   the tests' are backtide-test-*; `rm -f -v` so their anonymous volumes go too;
# - networks named backtide-* or vigia-demo-*;
# - unused anonymous volumes (`docker volume prune`: only volumes no container uses).
# It never touches images, nor containers or networks with other names. Runs inside the VM.
#
# It refuses to run while pytest is running (it would pull the rug from under a `make it` or
# `make ataques`) unless FORZAR=1.

set -u

OURS='^(backtide-|vigia-demo-)'

if [ "${FORZAR:-}" != 1 ] && pgrep -f 'pytest' >/dev/null 2>&1; then
  echo "Hay pruebas en marcha (pytest) en la VM: limpiar ahora las rompería." >&2
  echo "Espera a que acaben, o fuerza la limpieza con: make vm-limpiar FORZAR=1" >&2
  exit 2
fi

status=0

containers=$(docker ps -a --format '{{.Names}}' | grep -E "$OURS" || true)
if [ -n "$containers" ]; then
  echo "Contenedores:"
  for name in $containers; do
    if docker rm --force --volumes "$name" >/dev/null 2>&1; then
      echo "  borrado $name"
    else
      echo "  NO se pudo borrar $name" >&2
      status=1
    fi
  done
else
  echo "Contenedores: nada que borrar"
fi

networks=$(docker network ls --format '{{.Name}}' | grep -E "$OURS" || true)
if [ -n "$networks" ]; then
  echo "Redes:"
  for name in $networks; do
    if docker network rm "$name" >/dev/null 2>&1; then
      echo "  borrada $name"
    else
      echo "  NO se pudo borrar $name (¿la usa algo que no es nuestro?)" >&2
      status=1
    fi
  done
else
  echo "Redes: nada que borrar"
fi

# Only anonymous volumes that no container uses (a named volume stays: no --all).
before=$(docker volume ls -q | wc -l | tr -d ' ')
docker volume prune --force >/dev/null 2>&1 || { echo "  fallo en docker volume prune" >&2; status=1; }
after=$(docker volume ls -q | wc -l | tr -d ' ')
echo "Volúmenes anónimos sin usar: borrados $((before - after)) (quedan $after)"

if [ "$status" -ne 0 ]; then
  echo "Algo no se pudo limpiar: mira make vm-estado" >&2
fi
exit "$status"
