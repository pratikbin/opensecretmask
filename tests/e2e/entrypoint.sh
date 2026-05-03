#!/usr/bin/env bash
set -euo pipefail

# osm setup happens once per container at boot. Hooks land in
# ~/.claude/settings.json so subsequent claude-code invocations route
# through osm.
if [[ ! -f "$HOME/.opensecretmask/install.key" ]]; then
  osm init >/dev/null
fi
if [[ ! -f "$HOME/.claude/settings.json" ]] || ! grep -q '"opensecretmask"' "$HOME/.claude/settings.json" 2>/dev/null; then
  mkdir -p "$HOME/.claude"
  osm install --global claude-code >/dev/null
fi

exec "$@"
