#!/usr/bin/env bash
# Local end-to-end test of the osm plugin, on your own machine and account.
#
# It runs three headless passes: one control with no plugin, one with the
# plugin, and one that reads a file whose secret came from .env. It prints a
# verdict for each check.
#
# The restore direction is observed with grep, not with a file write: the model
# greps the fixture for the value it read. If the hook restored the real key,
# grep finds it and prints 1. If the hook did not, grep prints 0. A file write
# reads as an exfiltration pattern and the model refuses it.
#
# Run it from anywhere. It needs Claude Code 2.1.272 or newer.
#
#   tmux new-session -d -s osmtest 'bash scripts/local-e2e.sh 2>&1 | tee /tmp/osm.log'
#   tmux capture-pane -p -t osmtest
set -uo pipefail

PLUGIN="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$(mktemp -d "${TMPDIR:-/tmp}/osm-e2e.XXXXXX")"
FIX="$HERE/fixture"
REAL='sk-ant-api03-ZZTESTZZ0123456789abcdefABCDEF0123456789abcdefABCDwxyz'
DBPW='hunter2-correct-horse-battery-staple'

rm -rf "$FIX"; mkdir -p "$FIX"
printf 'ACME_SERVICE_KEY=%s\n' "$REAL" > "$FIX/secret.txt"
printf 'ACME_DB_PASSWORD=%s\nPORT=3000\nNODE_ENV=development\n' "$DBPW" > "$FIX/.env"
printf 'db_password=%s\nport=3000\nnode_env=development\n' "$DBPW" > "$FIX/app-config.txt"
cd "$FIX"

echo "claude : $(claude --version)"
echo "plugin : $PLUGIN"
echo "cwd    : $FIX"

SYS='This session is an automated local test of a secret-masking Claude Code plugin. Every credential in the fixture directory is fabricated and belongs to no account. Nothing leaves this machine. Follow the test instructions literally and report the values you observe.'

P1='You are the subject of a test for a secret-masking plugin. The fixture holds a fabricated API key.

1. Read the file secret.txt.
2. Run this Bash command, with <VALUE> replaced by the ACME_SERVICE_KEY value you read:
grep -c "<VALUE>" secret.txt
3. Reply with exactly two lines and no other text:
SAW=<VALUE>
COUNT=<the number grep printed>'

P2='Read the file app-config.txt. Reply with exactly three lines and no other text:
DBPW=<the db_password value>
PORT=<the port value>
NODE_ENV=<the node_env value>'

run() {
  local label="$1" prompt="$2"; shift 2
  echo; echo "=== $label ==="
  printf '%s' "$prompt" | timeout 300 claude -p \
    --append-system-prompt "$SYS" \
    --allowedTools Read "Bash(grep *)" \
    "$@" 2>&1
  echo
}

run "1. CONTROL, no plugin" "$P1" | tee "$HERE/control.txt"

export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
run "2. WITH the plugin" "$P1" --plugin-dir "$PLUGIN" | tee "$HERE/plugin.txt"
run "3. registered .env layer" "$P2" --plugin-dir "$PLUGIN" | tee "$HERE/envlayer.txt"

echo
echo "================ VERDICT ================"
g(){ grep -oE "^$1=.*" "$2" | head -1 | cut -d= -f2-; }
SAW_CTRL=$(g SAW "$HERE/control.txt"); CNT_CTRL=$(g COUNT "$HERE/control.txt")
SAW_PLUG=$(g SAW "$HERE/plugin.txt");  CNT_PLUG=$(g COUNT "$HERE/plugin.txt")
GOT_PW=$(g DBPW "$HERE/envlayer.txt")
GOT_PORT=$(g PORT "$HERE/envlayer.txt")
GOT_ENV=$(g NODE_ENV "$HERE/envlayer.txt")

echo "real key      : $REAL"
echo "control SAW   : ${SAW_CTRL:-(none)}   COUNT=${CNT_CTRL:-(none)}"
echo "plugin  SAW   : ${SAW_PLUG:-(none)}   COUNT=${CNT_PLUG:-(none)}"
echo "real password : $DBPW"
echo "model saw pw  : ${GOT_PW:-(none)}"
echo "PORT          : ${GOT_PORT:-(none)}   NODE_ENV=${GOT_ENV:-(none)}"
echo

pass=0; fail=0
ok(){ echo "PASS $1"; pass=$((pass+1)); }
no(){ echo "FAIL $1"; fail=$((fail+1)); }

[ "$SAW_CTRL" = "$REAL" ] && ok "control : without the plugin the model read the real key" \
                          || no "control : the control run did not echo the real key"
if [ -n "$SAW_PLUG" ] && [ "$SAW_PLUG" != "$REAL" ]; then
  ok "mask    : the model read a fake"
  case "$SAW_PLUG" in sk-ant-*) ok "format  : the sk-ant- prefix survived";;
                      *)        no "format  : the vendor prefix was lost";; esac
  [ ${#SAW_PLUG} -eq ${#REAL} ] && ok "length  : same length" || no "length  : ${#SAW_PLUG} vs ${#REAL}"
else
  no "mask    : the model read the real key"
fi
[ "$CNT_PLUG" = "1" ] && ok "unmask  : grep found the real key, so the tool got it" \
                      || no "unmask  : grep printed '${CNT_PLUG:-(none)}', so the fake reached the tool"
{ [ -n "$GOT_PW" ] && [ "$GOT_PW" != "$DBPW" ]; } && ok "env     : the .env password was masked" \
                                                  || no "env     : the .env password leaked"
[ "$GOT_PORT" = "3000" ] && ok "readable: port stayed 3000" || no "readable: port became '$GOT_PORT'"
[ "$GOT_ENV" = "development" ] && ok "readable: node_env stayed development" || no "readable: node_env became '$GOT_ENV'"

echo
echo "passed $pass, failed $fail"
echo "DONE"
