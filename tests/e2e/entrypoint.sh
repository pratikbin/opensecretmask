#!/usr/bin/env bash
set -euo pipefail

# osm setup happens once per container at boot. --no-trust skips the
# system-trust install (the container is disposable; OSM_KEY-derived envs
# are enough for the tests).
if [[ ! -f "$HOME/.opensecretmask/ca-cert.pem" ]]; then
  osm init --no-trust >/dev/null
fi

exec "$@"
