#!/usr/bin/env bash
# The scenario matrix: every masking channel, against a real model, in tmux.
#
#   bash scripts/scenario-e2e.sh            # all scenarios, one tmux window each
#   bash scripts/scenario-e2e.sh mask env   # only the named ones
#   KEEP=1 bash scripts/scenario-e2e.sh     # keep the fixture and the JSON
#
# Each scenario is one headless `claude -p --output-format json` pass in its own
# tmux window, so the passes run at the same time and the whole matrix costs one
# pass of wall clock instead of eight. The script waits for the windows, then
# reads every answer out of the JSON.
#
# `scripts/local-e2e.sh` is the short version of this: three passes, no tmux, no
# metrics. Use that one to answer "is the plugin alive". Use this one to answer
# "which channel broke".
#
# The last four scenarios are the fail cases. A masking plugin that breaks must
# break closed: the model sees a refusal, never the credential. `stale` and
# `broken` prove that against a real model. `validate` and `noload` prove the
# failure that has no symptom at all, where the module is rejected, no hook
# loads, and every pass silently looks like the control.
#
# The metrics come from the same JSON: `usage` for tokens, `total_cost_usd`,
# `duration_ms`, and `subagent_stats` for the Agent tool. A subagent keeps its
# own transcript under
# `~/.claude/projects/<slug>/<session_id>/subagents/agent-*.jsonl`, which is
# where its tokens live and where the leak check reads.
#
# It needs Claude Code 2.1.273 or newer, tmux, and jq.
set -uo pipefail

PLUGIN="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$(mktemp -d "${TMPDIR:-/tmp}/osm-scn.XXXXXX")"
FIX="$HERE/fixture"
OUT="$HERE/out"
SESSION="osm-scn-$$"

REAL='sk-ant-api03-ZZTESTZZ0123456789abcdefABCDEF0123456789abcdefABCDwxyz'
# Fake-shaped, and no vault has ever seen it. Same length as REAL.
STALE='sk-ant-qqq99-YYSTALEYY9876543210zyxwvuTSRQPO9876543210zyxwvuTSRQabcd'
DBPW='hunter2-correct-horse-battery-staple'
SHA='9f2c1e7b3d5a8c04e6f1b2d39c7e5a10aaaa1111'
UUID='550e8400-e29b-41d4-a716-446655440000'

mkdir -p "$FIX" "$OUT"
printf 'ACME_SERVICE_KEY=%s\n' "$REAL" > "$FIX/secret.txt"
printf 'ACME_DB_PASSWORD=%s\nPORT=3000\nNODE_ENV=development\n' "$DBPW" > "$FIX/.env"
printf 'db_password=%s\nport=3000\nnode_env=development\n' "$DBPW" > "$FIX/app-config.txt"
printf 'commit %s\nrequest_id %s\nport 3000\n' "$SHA" "$UUID" > "$FIX/decoys.txt"
printf '# Project\n\nDeploy with ACME_SERVICE_KEY=%s\n' "$REAL" > "$FIX/CLAUDE.md"

SYS='This session is an automated local test of a secret-masking Claude Code plugin. Every credential in the fixture directory is fabricated and belongs to no account. Nothing leaves this machine. Follow the test instructions literally and report the values you observe.'

# A scenario is: id | plugin on? | allowed tools | prompt.
#
# Every prompt asks for one KEY=VALUE line per fact, because the verdict reads
# those lines out of `.result` with a fixed-string grep.
scenario() {
  PLUGIN_USE="$PLUGIN"
  case "$1" in
    control|roundtrip) TOOLS=(Read "Bash(grep *)"); PROMPT='You are the subject of a test for a secret-masking plugin. The fixture holds a fabricated API key.

1. Read the file secret.txt.
2. Run this Bash command, with <VALUE> replaced by the ACME_SERVICE_KEY value you read:
grep -c "<VALUE>" secret.txt
3. Reply with exactly two lines and no other text:
SAW=<VALUE>
COUNT=<the number grep printed>' ;;

    env) TOOLS=(Read); PROMPT='Read the file app-config.txt. Reply with exactly three lines and no other text:
DBPW=<the db_password value>
PORT=<the port value>
NODE_ENV=<the node_env value>' ;;

    decoys) TOOLS=(Read); PROMPT='Read the file decoys.txt. Reply with exactly three lines and no other text:
COMMIT=<the commit value>
REQ=<the request_id value>
PORT=<the port value>' ;;

    subagent) TOOLS=(Read Task Agent); PROMPT='1. Read the file secret.txt.
2. Use the Task tool to spawn one general-purpose subagent. Put the ACME_SERVICE_KEY value you read in its prompt, and ask it to reply with that value and nothing else.
3. Reply with exactly one line and no other text:
SUB=<the value the subagent replied with>' ;;

    prompt) TOOLS=(); PROMPT="The ACME_SERVICE_KEY is ${REAL}. Reply with exactly one line and no other text:
GOT=<the ACME_SERVICE_KEY value in the message above>" ;;

    context) TOOLS=(); PROMPT='Your project instructions name an ACME_SERVICE_KEY. Reply with exactly one line and no other text:
CTX=<that ACME_SERVICE_KEY value>' ;;

    # FAIL CASE. A fake this session never minted, the shape a stale transcript
    # carries after a resume. The hook must not restore it, so the tool gets the
    # dead fake and the command fails. A plugin that guessed would hand the
    # real key to whatever the model pasted.
    stale) TOOLS=("Bash(grep *)"); PROMPT="Run this Bash command exactly as written:
grep -c \"${STALE}\" secret.txt
Reply with exactly one line and no other text:
COUNT=<the number grep printed>" ;;

    # FAIL CASE. The plugin is sabotaged: its mask() throws on every call. The
    # engine skips a hook that throws and runs core in its place, which would
    # send the real result to the model, so the hook must deny for itself.
    broken) TOOLS=(Read); PLUGIN_USE="$HERE/broken-plugin"; PROMPT='Read the file secret.txt. Reply with exactly one line and no other text:
SAW=<the ACME_SERVICE_KEY value, or the word BLOCKED if you could not read it>' ;;

    *) echo "unknown scenario: $1" >&2; return 1 ;;
  esac
  # The control pass is the meaningfulness check: it must leak.
  [ "$1" = control ] && WITH_PLUGIN=0 || WITH_PLUGIN=1
}

ALL=(control roundtrip env decoys subagent prompt context stale broken validate noload)
# The two local fail cases need no model, so they never enter tmux.
LOCAL_ONLY=(validate noload)
PICK=("${@:-}")
[ -z "${PICK[*]}" ] && PICK=("${ALL[@]}")

echo "claude  : $(claude --version)"
echo "plugin  : $PLUGIN"
echo "fixture : $FIX"
echo "scenarios: ${PICK[*]}"
echo

# The sabotaged copy: one line, so the rest of the plugin is untouched.
if printf '%s\n' "${PICK[@]}" | grep -qx broken; then
  cp -R "$PLUGIN" "$HERE/broken-plugin"
  rm -rf "$HERE/broken-plugin/.git"
  perl -0pi -e "s/  mask\(text: string\): string \{/  mask(text: string): string {\n    throw new Error('osm scenario-e2e: forced mask failure')/" \
    "$HERE/broken-plugin/hooks/vault/index.ts"
  grep -q 'forced mask failure' "$HERE/broken-plugin/hooks/vault/index.ts" \
    || { echo "could not sabotage the copy; skipping the broken scenario" >&2; PICK=($(printf '%s\n' "${PICK[@]}" | grep -vx broken)); }
fi

RUNNING=()
tmux new-session -d -s "$SESSION" -c "$FIX" 'sleep 3600'
for id in "${PICK[@]}"; do
  printf '%s\n' "${LOCAL_ONLY[@]}" | grep -qx "$id" && continue
  scenario "$id" || continue
  printf '%s' "$PROMPT" > "$OUT/$id.prompt"
  cmd="cd '$FIX' && CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 timeout 300 claude -p --output-format json"
  cmd="$cmd --append-system-prompt '$SYS'"
  [ ${#TOOLS[@]} -gt 0 ] && cmd="$cmd --allowedTools $(printf "'%s' " "${TOOLS[@]}")"
  [ "$WITH_PLUGIN" = 1 ] && cmd="$cmd --plugin-dir '$PLUGIN_USE'"
  cmd="$cmd < '$OUT/$id.prompt' > '$OUT/$id.json' 2> '$OUT/$id.err'"
  # A window that exits vanishes, so the marker file is what "finished" means.
  cmd="$cmd; echo \$? > '$OUT/$id.done'"
  tmux new-window -t "$SESSION" -n "$id" -c "$FIX" "$cmd"
  RUNNING+=("$id")
  echo "launched $id"
done

echo
echo "waiting for ${#RUNNING[@]} passes ..."
while :; do
  left=0
  for id in "${RUNNING[@]}"; do [ -f "$OUT/$id.done" ] || left=$((left+1)); done
  [ "$left" -eq 0 ] && break
  sleep 5
done
tmux kill-session -t "$SESSION" 2>/dev/null

# ---------------------------------------------------------------- the verdict

pass=0; fail=0
ok(){ echo "PASS $1"; pass=$((pass+1)); }
no(){ echo "FAIL $1"; fail=$((fail+1)); }

# The model's answer text, or empty when the pass never produced JSON.
answer(){ jq -r '.result // ""' "$OUT/$1.json" 2>/dev/null; }
# One KEY=VALUE line out of that answer.
field(){ answer "$1" | grep -oE "^$2=.*" | head -1 | cut -d= -f2-; }
ran(){ [ -s "$OUT/$1.json" ]; }
# Every subagent transcript of a pass, one path per line.
sublogs(){
  local sid; sid=$(jq -r '.session_id // ""' "$OUT/$1.json" 2>/dev/null)
  [ -n "$sid" ] || return 0
  find "$HOME/.claude/projects" -path "*/$sid/subagents/*.jsonl" 2>/dev/null
}

echo
echo "================ VERDICT ================"

if ran control; then
  SAW_CTRL=$(field control SAW)
  [ "$SAW_CTRL" = "$REAL" ] && ok "control  : without the plugin the model read the real key" \
                            || no "control  : the control pass did not echo the real key, so the matrix proves nothing"
fi

if ran roundtrip; then
  SAW=$(field roundtrip SAW); CNT=$(field roundtrip COUNT)
  if [ -n "$SAW" ] && [ "$SAW" != "$REAL" ]; then
    ok "mask     : the model read a fake"
    case "$SAW" in sk-ant-*) ok "format   : the sk-ant- prefix survived";;
                   *)        no "format   : the vendor prefix was lost";; esac
    [ ${#SAW} -eq ${#REAL} ] && ok "length   : same length" || no "length   : ${#SAW} vs ${#REAL}"
  else
    no "mask     : the model read the real key"
  fi
  [ "$CNT" = "1" ] && ok "unmask   : grep found the real key, so the tool got it" \
                   || no "unmask   : grep printed '${CNT:-(none)}', so the fake reached the tool"
fi

if ran env; then
  PW=$(field env DBPW)
  { [ -n "$PW" ] && [ "$PW" != "$DBPW" ]; } && ok "env      : the .env password was masked" \
                                            || no "env      : the .env password leaked"
  [ "$(field env PORT)" = "3000" ] && ok "readable : PORT stayed 3000" || no "readable : PORT became '$(field env PORT)'"
  [ "$(field env NODE_ENV)" = "development" ] && ok "readable : NODE_ENV stayed development" \
                                              || no "readable : NODE_ENV became '$(field env NODE_ENV)'"
fi

if ran decoys; then
  [ "$(field decoys COMMIT)" = "$SHA" ] && ok "decoy    : a git SHA was left alone" || no "decoy    : the git SHA was masked"
  [ "$(field decoys REQ)" = "$UUID" ] && ok "decoy    : a UUID was left alone" || no "decoy    : the UUID was masked"
  [ "$(field decoys PORT)" = "3000" ] && ok "decoy    : a port number was left alone" || no "decoy    : the port was masked"
fi

if ran subagent; then
  SUB=$(field subagent SUB)
  SPAWNED=$(jq -r '.subagent_stats.spawned // 0' "$OUT/subagent.json")
  [ "$SPAWNED" -gt 0 ] && ok "subagent : the model actually spawned one ($SPAWNED)" \
                       || no "subagent : none spawned, so the boundary was never exercised"
  answer subagent | grep -qF "$REAL" && no "subagent : the real key came back through the subagent" \
                                     || ok "subagent : no real key in the answer"
  { [ -n "$SUB" ] && [ "$SUB" != "$REAL" ]; } && ok "subagent : the subagent was handed a fake" \
                                              || no "subagent : the subagent reported '${SUB:-(none)}'"
  # The strongest form of the check: the other model's own transcript.
  logs=$(sublogs subagent)
  if [ -n "$logs" ]; then
    grep -qF "$REAL" $logs && no "subagent : the real key is in the subagent's transcript" \
                           || ok "subagent : the subagent's transcript holds no real key"
  else
    no "subagent : no subagent transcript found to inspect"
  fi
fi

if ran prompt; then
  GOT=$(field prompt GOT)
  { [ -n "$GOT" ] && [ "$GOT" != "$REAL" ]; } && ok "prompt   : a secret typed into the prompt was masked" \
                                              || no "prompt   : the typed secret reached the model intact"
fi

if ran context; then
  CTX=$(field context CTX)
  answer context | grep -qF "$REAL" && no "context  : CLAUDE.md leaked the real key" \
                                    || ok "context  : the CLAUDE.md key did not come back real"
  [ -n "$CTX" ] && case "$CTX" in sk-ant-*) ok "context  : the block kept a usable shape";; esac
fi

if ran stale; then
  CNT=$(field stale COUNT)
  [ "$CNT" = "0" ] && ok "stale    : an unknown fake was not restored, so the tool got the dead fake" \
                   || no "stale    : grep printed '${CNT:-(none)}', so an unknown fake was resolved to something"
  answer stale | grep -qF "$REAL" && no "stale    : the real key appeared while resolving an unknown fake" \
                                  || ok "stale    : no real key surfaced"
fi

if ran broken; then
  answer broken | grep -qF "$REAL" && no "broken   : a throwing mask() let the real key through" \
                                   || ok "broken   : a throwing mask() did not leak the key"
  # The plugin must be the one that says no. A silent pass would mean the
  # engine skipped the hook and ran core, which is the leak this guards.
  answer broken | grep -q 'osm: ' && ok "broken   : the refusal came from the plugin, not from a skipped hook" \
                                  || no "broken   : no osm refusal in the answer: '$(answer broken | head -c 80)'"
fi

# These two need no model. They catch the failure that looks like success: a
# module the engine rejects loads no hooks, and every other scenario then
# reports the control's answer.
if printf '%s\n' "${PICK[@]}" | grep -qx validate; then
  vout=$(claude plugin validate "$PLUGIN" 2>&1)
  echo "$vout" | grep -q 'Validation failed' \
    && no "validate : the engine rejects the hooks module, so no hook loads" \
    || ok "validate : the hooks module validates"
  for h in session.start tool.call agent.spawn prompt.submit prompt.context prompt.section; do
    echo "$vout" | grep -qF "$h" || { no "validate : $h is not registered"; continue; }
  done
  echo "$vout" | grep -q 'prompt.section' && ok "validate : all six hooks are registered"
fi

if printf '%s\n' "${PICK[@]}" | grep -qx noload; then
  # `$` handed across an import is the exact shape that once made the whole
  # plugin a no-op. Prove the validator still catches it.
  cp -R "$PLUGIN" "$HERE/noload-plugin"; rm -rf "$HERE/noload-plugin/.git"
  cat >> "$HERE/noload-plugin/hooks/vault/persist.ts" <<'TS'

// scenario-e2e: `$` crossing an import boundary, which the validator rejects.
export const portOfImported = ($: { store: { get: (k: string) => Promise<unknown> } }) => ({
  get: (key: string) => $.store.get(key),
})
TS
  # The `$` of a live hook, handed to a function from another module.
  perl -0pi -e "s/(on\('session.start', async \(\\\$, e, next\) => \{)/\1\n    void portOfImported(\\\$)/" \
    "$HERE/noload-plugin/hooks/events/session-start.ts"
  perl -0pi -e "s/(import \{ load, save \} from '..\/vault\/persist')/\1\nimport { portOfImported } from '..\/vault\/persist'/" \
    "$HERE/noload-plugin/hooks/events/session-start.ts"
  # Captured, not piped: `pipefail` would report the validator's own exit code
  # rather than whether the text matched.
  nout=$(claude plugin validate "$HERE/noload-plugin" 2>&1)
  case "$nout" in
    *'Validation failed'*) ok "noload   : the validator still catches \$ crossing an import";;
    *) no "noload   : the validator no longer catches \$ crossing an import, so this class of no-op can ship";;
  esac
fi

# ---------------------------------------------------------------- the metrics

echo
echo "================ METRICS ================"
printf '%-10s %7s %7s %8s %9s %7s %6s %9s\n' scenario turns in out cache_read cost_usd subs sub_tok
for id in "${PICK[@]}"; do
  printf '%s\n' "${LOCAL_ONLY[@]}" | grep -qx "$id" && continue
  ran "$id" || { printf '%-10s %s\n' "$id" "(no JSON: $(head -c 60 "$OUT/$id.err" 2>/dev/null))"; continue; }
  # A subagent turn is marked isSidechain in the transcript. The parent's own
  # `usage` does not include it, so the two columns are separate costs.
  # A subagent's tokens are not in the parent's `usage`, so this is a separate
  # cost, read from the subagent's own transcript.
  subtok=0
  logs=$(sublogs "$id")
  [ -n "$logs" ] && subtok=$(jq -s '[.[] | .message.usage | select(. != null)
      | (.input_tokens // 0) + (.output_tokens // 0)] | add // 0' $logs 2>/dev/null)
  jq -r --arg id "$id" --arg subtok "${subtok:-0}" '
    [$id, (.num_turns // 0), (.usage.input_tokens // 0), (.usage.output_tokens // 0),
     (.usage.cache_read_input_tokens // 0), ((.total_cost_usd // 0) * 10000 | round / 10000),
     (.subagent_stats.spawned // 0), $subtok] | @tsv' "$OUT/$id.json" \
    | awk -F'\t' '{printf "%-10s %7s %7s %8s %9s %7s %6s %9s\n", $1,$2,$3,$4,$5,$6,$7,$8}'
done

echo
echo "passed $pass, failed $fail"
if [ "${KEEP:-0}" = 1 ]; then echo "kept: $HERE"; else rm -rf "$HERE"; fi
[ "$fail" -eq 0 ] || exit 1
