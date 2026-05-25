#!/usr/bin/env bash
set -euo pipefail

# osm setup happens once per container at boot. osm init only writes the CA
# file; per-process trust via 'osm run' env vars is the only path.
if [[ ! -f "$HOME/.opensecretmask/ca-cert.pem" ]]; then
  osm init >/dev/null
fi

exec "$@"
