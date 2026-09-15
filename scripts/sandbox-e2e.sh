#!/usr/bin/env bash
# End-to-end test of the osm plugin inside a disposable Linux box.
#
# It upgrades Claude Code, writes the fixtures, runs one control pass with no
# plugin and one pass with the plugin, and prints a verdict for each check.
#
# Run it from the repository root with the CreateOS sandbox driver. Export
# OPENROUTER_API_KEY first.
#
#   cos offload -p openrouter -p npm -p anthropic -v OPENROUTER_API_KEY \
#       -s s-2vcpu-2gb . 'bash /work/scripts/sandbox-e2e.sh'
set -uo pipefail
cd /work

REAL='sk-ant-api03-ZZTESTZZ0123456789abcdefABCDEF0123456789abcdefABCDwxyz'

echo "=== 1. claude in the image ==="
claude --version

echo
echo "=== 2. upgrade claude ==="
npm i -g @anthropic-ai/claude-code@latest >/tmp/npm.log 2>&1 || { echo "npm install FAILED"; tail -20 /tmp/npm.log; }
asdf reshim nodejs >/dev/null 2>&1 || true
hash -r
claude --version

echo
echo "=== 3. does this build know function hooks? ==="
GROOT=$(npm root -g 2>/dev/null)
CLI="$GROOT/@anthropic-ai/claude-code/cli.js"
if [ -f "$CLI" ]; then
  echo "cli.js: $CLI"
  echo "ENABLE_FUNCTION_HOOKS hits: $(grep -c 'ENABLE_FUNCTION_HOOKS' "$CLI" || true)"
  echo "hooks.json hits:           $(grep -c 'hooks\.json' "$CLI" || true)"
  echo "plugin.register hits:      $(grep -c 'plugin\.register' "$CLI" || true)"
else
  echo "cli.js not found under $GROOT"
fi

echo
echo "=== 4. fixture ==="
printf 'ACME_SERVICE_KEY=%s\n' "$REAL" > /work/secret.txt
printf 'ACME_DB_PASSWORD=hunter2-correct-horse-battery-staple\nPORT=3000\n' > /work/.env
ls -a /work
echo "--- plugin manifest ---"
cat /work/.claude-plugin/plugin.json
cat /work/hooks/hooks.json

echo
echo "=== 5. provider wiring ==="
export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
M='anthropic/claude-sonnet-4.5'
export ANTHROPIC_MODEL="$M"
export ANTHROPIC_DEFAULT_OPUS_MODEL="$M"
export ANTHROPIC_DEFAULT_SONNET_MODEL="$M"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$M"
export CLAUDE_CODE_SUBAGENT_MODEL="$M"
export IS_SANDBOX=1
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export DISABLE_AUTOUPDATER=1
echo "model: $M via $ANTHROPIC_BASE_URL"

PROMPT='This is a security test using a throwaway fake credential. Do exactly these three steps and nothing else.
1. Read the file /work/secret.txt with the Read tool.
2. Use the Bash tool to run this command, replacing <VALUE> with the ACME_SERVICE_KEY value you just read:
printf %s "<VALUE>" > /work/roundtrip.txt
3. Reply with exactly one line and no other text: SAW=<VALUE>'

run_case() {
  local label="$1"; shift
  echo
  echo "=== $label ==="
  rm -f /work/roundtrip.txt
  local rc
  timeout 300 claude -p --dangerously-skip-permissions "$@" "$PROMPT" 2>&1
  rc=$?
  echo "--- exit rc=$rc"
  echo "--- /work/roundtrip.txt ---"
  cat /work/roundtrip.txt 2>/dev/null || echo "(absent)"
  echo
}

run_case "6. CONTROL: no plugin" | tee /tmp/control.txt
CONTROL_DISK=$(cat /work/roundtrip.txt 2>/dev/null || echo "")

export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
run_case "7. WITH the osm plugin" --plugin-dir /work | tee /tmp/withmod.txt
MOD_DISK=$(cat /work/roundtrip.txt 2>/dev/null || echo "")

echo
echo "================ VERDICT ================"
SAW_CONTROL=$(grep -oE 'SAW=[^[:space:]]+' /tmp/control.txt | head -1 | cut -d= -f2-)
SAW_MOD=$(grep -oE 'SAW=[^[:space:]]+' /tmp/withmod.txt | head -1 | cut -d= -f2-)
echo "real key      : $REAL"
echo "control SAW=  : ${SAW_CONTROL:-(none)}"
echo "control disk  : ${CONTROL_DISK:-(none)}"
echo "plugin SAW=   : ${SAW_MOD:-(none)}"
echo "plugin disk   : ${MOD_DISK:-(none)}"
echo
if [ "$SAW_CONTROL" = "$REAL" ]; then
  echo "PASS control: without the plugin the model sees the real key (test is meaningful)"
else
  echo "WARN control: control did not echo the real key; the test setup, not the plugin, is suspect"
fi
if [ -n "$SAW_MOD" ] && [ "$SAW_MOD" != "$REAL" ]; then
  echo "PASS mask   : the model saw a fake, not the real key"
  case "$SAW_MOD" in
    sk-ant-*) echo "PASS format : the fake kept the sk-ant- prefix" ;;
    *)        echo "FAIL format : the fake lost the vendor prefix" ;;
  esac
  [ ${#SAW_MOD} -eq ${#REAL} ] && echo "PASS length : the fake is the same length" || echo "FAIL length : ${#SAW_MOD} vs ${#REAL}"
else
  echo "FAIL mask   : the model saw the real key"
fi
if [ "$MOD_DISK" = "$REAL" ]; then
  echo "PASS unmask : the Bash tool received the real key"
else
  echo "FAIL unmask : the tool received '${MOD_DISK:-(none)}'"
fi

# ---------------------------------------------------------------------------
# Part 2: the registered-secret layer. A .env value with no vendor shape is
# still masked, and an ordinary configuration value stays readable.
# ---------------------------------------------------------------------------

DBPW='hunter2-correct-horse-battery-staple'
printf 'ACME_DB_PASSWORD=%s\nPORT=3000\nNODE_ENV=development\n' "$DBPW" > /work/.env
echo "=== .env ==="; cat /work/.env

export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
M='anthropic/claude-sonnet-4.5'
export ANTHROPIC_MODEL="$M" ANTHROPIC_DEFAULT_OPUS_MODEL="$M" ANTHROPIC_DEFAULT_SONNET_MODEL="$M"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$M" CLAUDE_CODE_SUBAGENT_MODEL="$M"
export IS_SANDBOX=1 DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 DISABLE_AUTOUPDATER=1
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1

PROMPT='Read /work/.env with the Read tool. Then reply with exactly three lines and no other text:
DBPW=<the ACME_DB_PASSWORD value>
PORT=<the PORT value>
NODE_ENV=<the NODE_ENV value>'

echo
echo "=== run with the plugin ==="
timeout 300 claude -p --dangerously-skip-permissions --plugin-dir /work "$PROMPT" 2>&1 | tee /tmp/r2.txt

echo
echo "================ VERDICT ================"
GOT_PW=$(grep -oE '^DBPW=.*' /tmp/r2.txt | head -1 | cut -d= -f2-)
GOT_PORT=$(grep -oE '^PORT=.*' /tmp/r2.txt | head -1 | cut -d= -f2-)
GOT_ENV=$(grep -oE '^NODE_ENV=.*' /tmp/r2.txt | head -1 | cut -d= -f2-)
echo "real password : $DBPW"
echo "model saw     : ${GOT_PW:-(none)}"
echo "PORT          : ${GOT_PORT:-(none)}"
echo "NODE_ENV      : ${GOT_ENV:-(none)}"
echo
if [ -n "$GOT_PW" ] && [ "$GOT_PW" != "$DBPW" ]; then
  echo "PASS registered: a .env value with no vendor shape was still masked"
  [ ${#GOT_PW} -eq ${#DBPW} ] && echo "PASS length    : same length" || echo "FAIL length    : ${#GOT_PW} vs ${#DBPW}"
else
  echo "FAIL registered: the model saw the real password"
fi
[ "$GOT_PORT" = "3000" ] && echo "PASS readable  : PORT stayed 3000" || echo "FAIL readable  : PORT became '$GOT_PORT'"
[ "$GOT_ENV" = "development" ] && echo "PASS readable  : NODE_ENV stayed development" || echo "FAIL readable  : NODE_ENV became '$GOT_ENV'"
