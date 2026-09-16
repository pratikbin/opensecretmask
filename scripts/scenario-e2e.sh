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

    *) echo "unknown scenario: $1" >&2; return 1 ;;
  esac
  # The control pass is the meaningfulness check: it must leak.
  [ "$1" = control ] && WITH_PLUGIN=0 || WITH_PLUGIN=1
}

ALL=(control roundtrip env decoys subagent prompt context)
PICK=("${@:-}")
[ -z "${PICK[*]}" ] && PICK=("${ALL[@]}")

echo "claude  : $(claude --version)"
echo "plugin  : $PLUGIN"
echo "fixture : $FIX"
echo "scenarios: ${PICK[*]}"
echo

RUNNING=()
tmux new-session -d -s "$SESSION" -c "$FIX" 'sleep 3600'
for id in "${PICK[@]}"; do
  scenario "$id" || continue
  printf '%s' "$PROMPT" > "$OUT/$id.prompt"
  cmd="cd '$FIX' && CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 timeout 300 claude -p --output-format json"
  cmd="$cmd --append-system-prompt '$SYS'"
  [ ${#TOOLS[@]} -gt 0 ] && cmd="$cmd --allowedTools $(printf "'%s' " "${TOOLS[@]}")"
  [ "$WITH_PLUGIN" = 1 ] && cmd="$cmd --plugin-dir '$PLUGIN'"
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

# ---------------------------------------------------------------- the metrics

echo
echo "================ METRICS ================"
printf '%-10s %7s %7s %8s %9s %7s %6s %9s\n' scenario turns in out cache_read cost_usd subs sub_tok
for id in "${PICK[@]}"; do
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
