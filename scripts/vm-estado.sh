#!/bin/sh
# What the dev VM is doing right now (`make vm-estado`): containers with their CPU and memory,
# leftovers, test btrfs mounts that are still mounted and the processes that burn CPU.
# Read-only: it changes nothing. Runs inside the VM.

set -u

echo "== La VM =="
uptime
echo

echo "== Contenedores en marcha (CPU y memoria) =="
running=$(docker ps -q | wc -l | tr -d ' ')
if [ "$running" -eq 0 ]; then
  echo "(ninguno)"
else
  docker stats --no-stream
fi
echo

echo "== Restos de Docker =="
all=$(docker ps -aq | wc -l | tr -d ' ')
stopped=$((all - running))
networks=$(docker network ls --format '{{.Name}}' | grep -vxE 'bridge|host|none' || true)
network_count=$(printf '%s' "$networks" | grep -c . || true)
volumes=$(docker volume ls -q | wc -l | tr -d ' ')
loose=$(docker volume ls -q -f dangling=true | wc -l | tr -d ' ')
echo "contenedores en marcha: $running"
echo "contenedores parados:   $stopped"
echo "redes (sin las de Docker): $network_count"
echo "volúmenes:              $volumes ($loose sin usar)"
if [ "$all" -gt 0 ]; then
  echo "contenedores:"
  docker ps -a --format '  {{.Names}}  [{{.Status}}]'
fi
if [ "$network_count" -gt 0 ]; then
  echo "redes:"
  printf '%s\n' "$networks" | sed 's/^/  /'
fi
echo

echo "== Montajes btrfs de prueba o demo (siguen montados) =="
mounts=$(findmnt -rn -t btrfs -o TARGET,SOURCE | grep ' /dev/loop' || true)
if [ -z "$mounts" ]; then
  echo "(ninguno)"
else
  printf '%s\n' "$mounts" | sed 's/^/  /'
fi
echo

echo "== Los 5 procesos que más CPU gastan =="
ps -eo pid,pcpu,pmem,etime,comm --sort=-pcpu | head -n 6
echo

if [ "$running" -gt 0 ]; then
  echo "AVISO: hay $running contenedor(es) en marcha. Si no estás probando nada, sobran: make vm-limpiar"
fi
