#!/bin/sh
# Regenerate the agent's seccomp profile (agent.json) from Docker's default profile.
#
#   deploy/seccomp/regenerate.sh            # check the pinned copy and rebuild agent.json
#   deploy/seccomp/regenerate.sh --fetch    # download the pinned copy again first
#
# docker-default.json is Docker's own default profile for the Docker version below, copied
# from the moby repository (it is vendored there from github.com/moby/profiles). agent.json
# is that profile plus the Btrfs ioctl and copy_file_range blocks of backtide/jail/seccomp.py, and nothing else:
# `git diff --no-index docker-default.json agent.json` shows exactly what we change.
#
# To move to a new Docker version: update DOCKER_VERSION, run with --fetch, check the new
# SHA-256 by hand against the moby tag, update DOCKER_DEFAULT_SHA256, and run `make it`.
set -eu

DOCKER_VERSION="29.8.2"
DOCKER_DEFAULT_SHA256="536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"
URL="https://raw.githubusercontent.com/moby/moby/docker-v${DOCKER_VERSION}/vendor/github.com/moby/profiles/seccomp/default.json"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
default="$here/docker-default.json"

if [ "${1:-}" = "--fetch" ]; then
	curl --fail --silent --show-error --location --proto '=https' --output "$default.tmp" "$URL"
	mv "$default.tmp" "$default"
fi

actual=$(uv run --project "$root" python -c \
	'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
	"$default")
if [ "$actual" != "$DOCKER_DEFAULT_SHA256" ]; then
	echo "docker-default.json has SHA-256 $actual, expected $DOCKER_DEFAULT_SHA256" >&2
	exit 1
fi

cd "$root"
uv run python -m backtide.jail.seccomp "$default" "$here/agent.json"
echo "wrote $here/agent.json (Docker $DOCKER_VERSION default + Btrfs ioctl and copy_file_range blocks)"
