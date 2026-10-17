#!/usr/bin/env bash
# Do the doors that are not tool results leave the machine masked?
#
# `session.append` sees every row a conversation keeps. This plants one canary
# behind each of three doors that never pass through a tool result, then reads
# what went on the wire and what the transcript file kept:
#
#   NESTED  a CLAUDE.md in a subdirectory, attached when a file there is read
#   START   a classic SessionStart hook's additionalContext
#   SUBMIT  a classic UserPromptSubmit hook's additionalContext
#
# Three configurations: no plugin (the control, which must leak or the door is
# not live), OSM_BASELINE_DIR if set (osm before a change, to say what the
# change bought), and OSM_DIR. Same rules as wire-e2e.sh: run it in a throwaway
# box, and print counts only, never a canary, a fake or model output.
#
#   cos offload -p openrouter -p npm -p anthropic -v OPENROUTER_API_KEY \
#       -s s-2vcpu-2gb <dir> 'bash /work/scripts/append-e2e.sh'
set -uo pipefail
OSM_DIR=${OSM_DIR:-/work}
OSM_BASELINE_DIR=${OSM_BASELINE_DIR:-}

fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

echo "=== claude ==="
npm i -g @anthropic-ai/claude-code@latest >/tmp/npm.log 2>&1 || { echo "npm install FAILED"; tail -20 /tmp/npm.log; }
asdf reshim nodejs >/dev/null 2>&1 || true
hash -r
claude --version

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
DOORS=(NESTED START SUBMIT)
declare -A CANARY
for d in "${DOORS[@]}"; do CANARY[$d]="sk-ant-api03-$(rand 40)"; done
SHAPE='sk-ant-[A-Za-z0-9]{5}-[A-Za-z0-9]{40}'

FX=/tmp/fx
rm -rf "$FX"; mkdir -p "$FX/sub"
printf '# Notes for sub\n\nNESTED_KEY=%s\n' "${CANARY[NESTED]}" > "$FX/sub/CLAUDE.md"
printf 'nothing to see here\n' > "$FX/sub/notes.txt"
hook() { printf '{"hookSpecificOutput":{"hookEventName":"%s","additionalContext":"%s_KEY=%s"}}\n' "$1" "$2" "${CANARY[$2]}" > "/tmp/hook-$2.json"; }
hook SessionStart START
hook UserPromptSubmit SUBMIT
cat > /tmp/hooks.json <<'JSON'
{"hooks":{
  "SessionStart":[{"hooks":[{"type":"command","command":"cat /tmp/hook-START.json"}]}],
  "UserPromptSubmit":[{"hooks":[{"type":"command","command":"cat /tmp/hook-SUBMIT.json"}]}]
}}
JSON

export WIRE_OUT=/tmp/wire WIRE_UPSTREAM=https://openrouter.ai/api WIRE_PORT=8788
rm -rf "$WIRE_OUT"
bun run "$OSM_DIR/scripts/wire-recorder.ts" > /tmp/recorder.log 2>&1 &
RECORDER=$!
trap 'kill $RECORDER 2>/dev/null' EXIT
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$WIRE_PORT/" >/dev/null 2>&1 && break; sleep 0.2; done

M='anthropic/claude-sonnet-4.5'
export ANTHROPIC_BASE_URL="http://127.0.0.1:$WIRE_PORT" ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_MODEL="$M" ANTHROPIC_DEFAULT_OPUS_MODEL="$M" ANTHROPIC_DEFAULT_SONNET_MODEL="$M"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$M" CLAUDE_CODE_SUBAGENT_MODEL="$M"
export IS_SANDBOX=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 DISABLE_AUTOUPDATER=1

PROMPT='Read the file sub/notes.txt with the Read tool, then reply with exactly one word: done'

# One run, then one line per door: canary on the wire, label on the wire (the
# door was live), a same-shaped fake under the label, canary in the transcript.
# Sets LEAK[door] and SEEN[door] for the verdict.
declare -A LEAK SEEN FAKE
run() {
  local name=$1; shift
  : > "$WIRE_OUT/bodies.txt"
  rm -rf ~/.claude/projects
  (cd "$FX" && timeout 300 claude -p --dangerously-skip-permissions --settings /tmp/hooks.json "$@" <<< "$PROMPT" > "/tmp/$name.log" 2>&1)
  echo
  echo "=== $name (claude rc=$?) ==="
  printf '%-7s %6s %6s %5s %11s\n' door wire seen fake transcript
  for d in "${DOORS[@]}"; do
    local c=${CANARY[$d]}
    LEAK[$d]=$(grep -F -c "$c" "$WIRE_OUT/bodies.txt")
    SEEN[$d]=$(grep -c "${d}_KEY" "$WIRE_OUT/bodies.txt")
    FAKE[$d]=$(grep -oE "${d}_KEY=$SHAPE" "$WIRE_OUT/bodies.txt" | grep -v -F -c "$c")
    local disk; disk=$(grep -rF -c "$c" ~/.claude/projects 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')
    printf '%-7s %6s %6s %5s %11s\n' "$d" "${LEAK[$d]}" "${SEEN[$d]}" "${FAKE[$d]}" "$disk"
  done
}

run control
declare -A LIVE
for d in "${DOORS[@]}"; do
  [ "${LEAK[$d]}" -gt 0 ] && LIVE[$d]=1 && ok "control leaks $d, so the door is live" \
                          || echo "SKIP  $d never reached the wire without a plugin; not tested"
done

[ -n "$OSM_BASELINE_DIR" ] && run baseline --plugin-dir "$OSM_BASELINE_DIR"

run osm --plugin-dir "$OSM_DIR"
for d in "${DOORS[@]}"; do
  [ -n "${LIVE[$d]:-}" ] || continue
  [ "${LEAK[$d]}" -eq 0 ] && ok "$d: canary never reached the wire" || bad "$d: canary in ${LEAK[$d]} request bodies"
  [ "${FAKE[$d]}" -gt 0 ] && ok "$d: a same-shaped fake travelled instead" || bad "$d: no same-shaped fake on the wire"
done

echo
echo "================ VERDICT ================"
[ "${#LIVE[@]}" -gt 0 ] || bad "no door was live; nothing was tested"
[ "$fail" -eq 0 ] && echo "PASS  every live door left the machine masked" || echo "FAIL  see above"
exit $fail
