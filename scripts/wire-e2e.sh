#!/usr/bin/env bash
# Does the secret actually leave the machine masked?
#
# Every other check in this repository is in-process. They prove our hook
# returned a fake. This one reads the request bodies Claude Code put on the
# wire and asserts the real value is not in any of them.
#
# Run it in a throwaway box, never on a laptop: the fixtures below are
# registered by the local osm install and written to the host store, which is
# per-plugin and not per-fixture. Export OPENROUTER_API_KEY first.
#
# The box alone is not enough. Whatever this script PRINTS travels back through
# the caller's tool result, and osm registers a credential-shaped string
# wherever it reads one — so an early version that echoed the model's answer
# wrote its own canary into the host store it was trying to stay out of.
# Nothing below prints the canary, the fake, or any model output that could
# contain either. Counts and verdicts only.
#
#   cos offload -p openrouter -p npm -p anthropic -v OPENROUTER_API_KEY \
#       -s s-2vcpu-2gb . 'bash /work/scripts/wire-e2e.sh'
set -uo pipefail
cd /work

fail=0
ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }

echo "=== 1. claude ==="
npm i -g @anthropic-ai/claude-code@latest >/tmp/npm.log 2>&1 || { echo "npm install FAILED"; tail -20 /tmp/npm.log; }
asdf reshim nodejs >/dev/null 2>&1 || true
hash -r
claude --version

# Minted here rather than committed. A canary living in the repository would be
# read by every later session, registered, and masked in our own source.
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
CANARY="sk-ant-api03-$(rand 40)"
# The fake preserves character classes, not literal text: `api03` comes back as
# five alphanumerics of the same shape, not as `api03`. Matching the literal
# segment is how the first version of this check failed against a healthy mask.
SHAPE='sk-ant-[A-Za-z0-9]{5}-[A-Za-z0-9]{40}'

echo
echo "=== 2. fixture ==="
printf 'ACME_SERVICE_KEY=%s\n' "$CANARY" > /work/canary.txt
echo "canary planted, ${#CANARY} chars"

echo
echo "=== 3. recorder ==="
export WIRE_OUT=/tmp/wire
export WIRE_UPSTREAM=https://openrouter.ai/api
export WIRE_PORT=8788
rm -rf "$WIRE_OUT"
bun run /work/scripts/wire-recorder.ts > /tmp/recorder.log 2>&1 &
RECORDER=$!
trap 'kill $RECORDER 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$WIRE_PORT/" >/dev/null 2>&1 && break
  sleep 0.2
done
cat /tmp/recorder.log

M='anthropic/claude-sonnet-4.5'
export ANTHROPIC_BASE_URL="http://127.0.0.1:$WIRE_PORT"
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

PROMPT='Read the file /work/canary.txt with the Read tool, then reply with exactly one line and nothing else: SAW=<the ACME_SERVICE_KEY value>'

bodies() { cat "$WIRE_OUT"/bodies.txt 2>/dev/null; }
count()  { bodies | grep -F -c "$CANARY"; }

# The control must run first: it establishes that this prompt puts the canary
# on the wire at all. Without it a masking pass proves nothing — a model that
# never read the file looks exactly like a model that read a fake. The box is
# fresh and osm is not installed globally here, so omitting --plugin-dir really
# does mean no plugin; on a developer's machine it would not.
echo
echo "=== 4. control: no plugin ==="
timeout 300 claude -p --dangerously-skip-permissions "$PROMPT" > /tmp/control.log 2>&1
echo "claude rc=$?"
CONTROL=$(count)
echo "canary occurrences on the wire: $CONTROL"
[ "$CONTROL" -gt 0 ] && ok "control leaks the canary, so the run is meaningful" \
                     || bad "control never sent the canary; the setup is broken, not the plugin"

echo
echo "=== 5. with the plugin ==="
rm -rf "$WIRE_OUT"; mkdir -p "$WIRE_OUT"
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
timeout 300 claude -p --dangerously-skip-permissions --plugin-dir /work "$PROMPT" > /tmp/plugin.log 2>&1
echo "claude rc=$?"
MASKED=$(count)
echo "canary occurrences on the wire: $MASKED"
[ "$MASKED" -eq 0 ] && ok "the canary never reached the wire" \
                    || bad "the canary appears in $MASKED request bodies"

# A run that sent nothing at all would also score zero above.
SENT=$(bodies | grep -c 'ACME_SERVICE_KEY')
[ "$SENT" -gt 0 ] && ok "the file did reach the model, so the zero above means masked" \
                  || bad "no request mentions the fixture; the model never read it"

FAKE=$(bodies | grep -oE "$SHAPE" | grep -v -F "$CANARY" | head -1)
if [ -n "$FAKE" ]; then
  ok "a same-shaped fake travelled instead"
  [ ${#FAKE} -eq ${#CANARY} ] && ok "the fake is the same length" \
                              || bad "length ${#FAKE} vs ${#CANARY}"
else
  bad "no sk-ant-shaped replacement on the wire; the value was dropped, not masked"
fi

echo
echo "================ VERDICT ================"
[ "$fail" -eq 0 ] && echo "PASS  nothing real left the machine" || echo "FAIL  see above"
exit $fail
