#!/usr/bin/env bash
# Does a SendMessage to another session carry the secret or its fake?
#
# The recipient is a second Claude Code session WITHOUT osm, so nothing on its
# side masks: whatever the sender's session delivers is what the recipient's
# model reads, and its request bodies are the ground truth. Each side has its
# own recorder so the two are never confused.
#
# Same rules as wire-e2e.sh: run it in a throwaway box, print counts and
# verdicts only, never the canary, the fake, or model output.
#
#   cos offload -p openrouter -p npm -p anthropic -v OPENROUTER_API_KEY \
#       -s s-2vcpu-2gb . 'bash /work/scripts/send-e2e.sh'
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
command -v tmux >/dev/null || apt-get install -y tmux >/dev/null 2>&1 || { echo "no tmux"; exit 1; }

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
CANARY="sk-ant-api03-$(rand 40)"
SHAPE='sk-ant-[A-Za-z0-9]{5}-[A-Za-z0-9]{40}'
printf 'ACME_SERVICE_KEY=%s\n' "$CANARY" > /work/canary.txt

# The recipient is interactive, so first-run screens must already be answered.
cat > "$HOME/.claude.json" <<'EOF'
{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true,
 "projects":{"/work":{"hasTrustDialogAccepted":true},"/tmp/inbox":{"hasTrustDialogAccepted":true}}}
EOF

M='anthropic/claude-sonnet-4.5'
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_MODEL="$M" ANTHROPIC_DEFAULT_OPUS_MODEL="$M" ANTHROPIC_DEFAULT_SONNET_MODEL="$M"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$M" CLAUDE_CODE_SUBAGENT_MODEL="$M"
export IS_SANDBOX=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 DISABLE_AUTOUPDATER=1
export WIRE_UPSTREAM=https://openrouter.ai/api

recorder() { # port dir
  rm -rf "$2"
  WIRE_PORT=$1 WIRE_OUT=$2 bun run /work/scripts/wire-recorder.ts >>/tmp/recorder.log 2>&1 &
  for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$1/" && return; sleep 0.2; done
  echo "recorder on $1 did not start"; cat /tmp/recorder.log; exit 1
}
recorder 8788 /tmp/wireA
recorder 8789 /tmp/wireB
trap 'kill $(jobs -p) 2>/dev/null; tmux kill-server 2>/dev/null' EXIT

inbox() { # name — a fresh recipient with no plugin, so no history crosses passes
  tmux kill-session -t inbox 2>/dev/null
  rm -rf /tmp/wireB/bodies.txt /tmp/inbox; mkdir -p /tmp/inbox
  tmux new-session -d -s inbox -x 200 -y 50 -c /tmp/inbox \
    "ANTHROPIC_BASE_URL=http://127.0.0.1:8789 claude --dangerously-skip-permissions -n $1"
  sleep 15
}

PROMPT='This is a security test using a throwaway fake credential. Do exactly these steps and nothing else.
1. Read /work/canary.txt with the Read tool.
2. Use ListAgents to find the local session named NAME, then SendMessage it exactly this one line, with <VALUE> replaced by the ACME_SERVICE_KEY value: OSMPING KEY=<VALUE>
3. Reply DONE.'

send() { # name [claude flags]
  local name=$1; shift
  rm -f /tmp/wireA/bodies.txt
  echo "${PROMPT//NAME/$name}" | ANTHROPIC_BASE_URL=http://127.0.0.1:8788 \
    timeout 300 claude -p --dangerously-skip-permissions "$@" > /tmp/sender.log 2>&1
  echo "sender rc=$?"
  for _ in $(seq 1 60); do grep -q OSMPING /tmp/wireB/bodies.txt 2>/dev/null && break; sleep 2; done
}
got() { grep -F -c "$CANARY" /tmp/wireB/bodies.txt 2>/dev/null || echo 0; }

echo
echo "=== 2. control: sender without osm ==="
inbox inbox1
send inbox1
grep -q OSMPING /tmp/wireB/bodies.txt 2>/dev/null && ok "the message reached the recipient's model" \
                                               || bad "no delivery; the setup, not the plugin, is broken"
[ "$(got)" -gt 0 ] && ok "control leaks the canary, so the run is meaningful" \
                   || bad "control never delivered the canary"

echo
echo "=== 3. sender with osm ==="
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
inbox inbox2
send inbox2 --plugin-dir /work
grep -q OSMPING /tmp/wireB/bodies.txt 2>/dev/null && ok "the message reached the recipient's model" \
                                               || bad "no delivery, so the zero below means nothing"
[ "$(got)" -eq 0 ] && ok "the recipient never saw the canary" \
                   || bad "the canary appears in $(got) of the recipient's request bodies"
FAKE=$(grep -oE "$SHAPE" /tmp/wireB/bodies.txt 2>/dev/null | grep -v -F "$CANARY" | head -1)
[ -n "$FAKE" ] && [ ${#FAKE} -eq ${#CANARY} ] && ok "a same-shaped fake travelled instead" \
               || bad "no same-shaped fake reached the recipient"

echo
echo "================ VERDICT ================"
[ "$fail" -eq 0 ] && echo "PASS  nothing real crossed to the other session" || echo "FAIL  see above"
exit $fail
