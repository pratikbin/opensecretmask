#!/usr/bin/env bash
# The scenario matrix, inside a disposable Linux box, against OpenRouter.
#
# This is the box-side half. It prepares the machine and then runs
# scripts/scenario-e2e.sh, which is the same suite the local runner uses. Run
# it from the repository root with the CreateOS sandbox driver, and export
# OPENROUTER_API_KEY in your own shell first:
#
#   cos offload -E -s s-2vcpu-4gb -v OPENROUTER_API_KEY . \
#       'bash /work/scripts/sandbox-scenarios.sh'
#
# Why a wrapper instead of running scenario-e2e.sh directly: the image ships an
# older Claude Code, has no tmux and no jq, and the model has to be repointed
# at OpenRouter through the Anthropic-compatible variables.
set -uo pipefail
cd /work

echo "=== 1. the box ==="
uname -srm
node --version 2>/dev/null || true

echo
echo "=== 2. tools ==="
# The matrix needs tmux to run the passes at the same time and jq to read the
# JSON each pass writes.
for pkg in tmux jq; do
  command -v "$pkg" >/dev/null || MISSING="${MISSING:-} $pkg"
done
if [ -n "${MISSING:-}" ]; then
  echo "installing:$MISSING"
  (apt-get update -qq && apt-get install -y -qq $MISSING) >/tmp/apt.log 2>&1 \
    || { echo "apt failed:"; tail -5 /tmp/apt.log; }
fi
tmux -V; jq --version

echo
echo "=== 3. claude ==="
# Function hooks need 2.1.272 or newer. The image ships something older.
claude --version
npm install -g @anthropic-ai/claude-code@latest >/tmp/npm.log 2>&1 \
  || { echo "npm install failed:"; tail -5 /tmp/npm.log; }
hash -r
claude --version

echo
echo "=== 4. provider ==="
M="${OSM_MODEL:-anthropic/claude-sonnet-4.5}"
export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_MODEL="$M"
export ANTHROPIC_DEFAULT_OPUS_MODEL="$M"
export ANTHROPIC_DEFAULT_SONNET_MODEL="$M"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$M"
export CLAUDE_CODE_SUBAGENT_MODEL="$M"
export IS_SANDBOX=1
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export DISABLE_AUTOUPDATER=1
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
echo "model: $M via $ANTHROPIC_BASE_URL"

echo
echo "=== 5. static checks ==="
# bun is not in the image and the checks are pure TypeScript, so run them with
# whatever runtime is here. Node 22 or newer runs a .ts file directly.
if command -v bun >/dev/null; then
  bun run scripts/unit-check.ts | tail -3
  bun run scripts/hook-check.ts | tail -3
else
  echo "(no bun in the image; the unit and hook checks run on the host)"
fi
claude plugin validate .claude-plugin/plugin.json 2>&1 | tail -3

echo
echo "=== 6. the matrix ==="
# Every pass names the tools it needs with --allowedTools, so no pass waits on
# a permission prompt.
#
# The driver's heartbeat drops lines from a long quiet stream, so the run also
# writes a full log that `cos offload -o` can pull back.
LOG="/work/${OSM_LOG:-matrix.log}"
bash scripts/scenario-e2e.sh "$@" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}

echo
echo "=== done, rc=$rc ==="
exit $rc
