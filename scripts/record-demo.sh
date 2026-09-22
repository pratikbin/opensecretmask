#!/usr/bin/env bash
# Records the README demo as a GIF, inside a throwaway CreateOS box.
#
# Run it from the host, not by hand in the box:
#
#   export OPENROUTER_API_KEY=…      # your own shell, never a prompt
#   cos offload -E -v OPENROUTER_API_KEY -o demo-out . 'bash scripts/record-demo.sh'
#
# `-v OPENROUTER_API_KEY` forwards the value without it ever reaching a command
# line. `-o demo-out` pulls `demo-out/osm-demo.gif` back.
#
# The recording is a real session: the plugin is installed from this checkout,
# a real model reads a file holding a synthetic credential, and `/osm-secrets`
# prints the pair. Nothing is staged or faked, which is the only reason the
# fake in the answer is worth showing.
#
# tmux supplies the pty that asciinema needs and `send-keys` types into it; agg
# turns the cast into the GIF. VHS is the obvious tool for this and does not
# work here — its headless-Chrome capture records zero frames against current
# Chrome.
set -euo pipefail

SRC="$PWD"
OUT="$SRC/demo-out"
COLS=104
ROWS=30
# An OpenRouter slug Claude Code does not recognise is displayed by its closest
# match, so `anthropic/claude-sonnet-4.5` renders as "Sonnet 4" and draws a
# retired-model warning across the recording. A current slug avoids it.
MODEL="${OSM_MODEL:-anthropic/claude-sonnet-5}"

# The credential the demo leaks on purpose. Synthetic, and shaped like the real
# thing so that `garble` has something to preserve.
FAKE_SECRET='sk-ant-api03-Kv8Tz2qRmXb4Ld7NpWc1Hf6JyGs3AeQu9ZrTvBnMxKdPoLiUhYgFcEwSaDjRt'

say() { printf '\n=== %s ===\n' "$1"; }

say "1. box packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq asciinema tmux jq fonts-jetbrains-mono curl >/tmp/apt.log 2>&1 \
  || { echo "apt failed:"; tail -20 /tmp/apt.log; exit 1; }
# agg ships one static binary; there is no apt package for it.
curl -fsSL -o /usr/local/bin/agg \
  https://github.com/asciinema/agg/releases/download/v1.9.0/agg-x86_64-unknown-linux-gnu
chmod 755 /usr/local/bin/agg
asciinema --version; agg --version; tmux -V

say "2. an unprivileged user"
# Claude Code wants IS_SANDBOX=1 to run as root, and a root prompt in a README
# GIF reads badly. A normal user avoids both.
id demo >/dev/null 2>&1 || useradd -m -s /bin/bash demo
HOME_DEMO=/home/demo

cat >> "$HOME_DEMO/.bashrc" <<EOF
export PATH="\$HOME/.local/bin:\$PATH"
export ANTHROPIC_BASE_URL=https://openrouter.ai/api
export ANTHROPIC_AUTH_TOKEN="${OPENROUTER_API_KEY:?OPENROUTER_API_KEY not forwarded; pass -v OPENROUTER_API_KEY}"
export ANTHROPIC_MODEL=$MODEL
export ANTHROPIC_DEFAULT_OPUS_MODEL=$MODEL
export ANTHROPIC_DEFAULT_SONNET_MODEL=$MODEL
export ANTHROPIC_DEFAULT_HAIKU_MODEL=$MODEL
export CLAUDE_CODE_SUBAGENT_MODEL=$MODEL
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export DISABLE_AUTOUPDATER=1
export DISABLE_NON_ESSENTIAL_MODEL_CALLS=1
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
export PS1='\[\033[36m\]demo\[\033[0m\]:\[\033[33m\]\w\[\033[0m\]\$ '
EOF

say "3. claude, at a version that has function hooks"
# The rootfs ships an older Claude Code under root's asdf, which the demo user
# cannot reach. The official installer puts a current one in ~/.local/bin.
su - demo -c 'curl -fsSL https://claude.ai/install.sh | bash' >/tmp/claude-install.log 2>&1 \
  || { echo "claude install failed:"; tail -20 /tmp/claude-install.log; exit 1; }
su - demo -c 'claude --version'

say "4. skip the first-run dialogs"
# Onboarding and the trust prompt are not what the GIF is about.
su - demo -c "jq '. + {hasCompletedOnboarding:true, theme:\"dark\", autoUpdates:false}
  | .projects[\"$HOME_DEMO\"] = ((.projects[\"$HOME_DEMO\"] // {})
    + {hasTrustDialogAccepted:true, hasCompletedProjectOnboarding:true})' \
  ~/.claude.json > /tmp/c.json && mv /tmp/c.json ~/.claude.json"

mkdir -p "$HOME_DEMO/.claude"
# Pre-approving Read keeps a permission dialog out of the recording. The point
# on screen is what the model reads, not whether it was allowed to.
cat > "$HOME_DEMO/.claude/settings.local.json" <<EOF
{ "permissions": { "allow": ["Read($HOME_DEMO/**)", "Bash(cat:*)"], "deny": [] } }
EOF
chown -R demo:demo "$HOME_DEMO"

say "5. the plugin source, readable by the demo user"
PLUGIN=/srv/osm
rm -rf "$PLUGIN"
cp -r "$SRC" "$PLUGIN"
rm -rf "$PLUGIN/demo-out"
chmod -R a+rX "$PLUGIN"

say "6. record"
cat > "$HOME_DEMO/drive.sh" <<DRIVE
#!/usr/bin/env bash
set -u
CAST="\$HOME/osm-demo.cast"
rm -f "\$CAST"
tmux kill-session -t rec 2>/dev/null

tmux new-session -d -s rec -x $COLS -y $ROWS "asciinema rec --overwrite -q \\"\$CAST\\" -c bash"
sleep 3

# One character at a time, so the recording reads as someone typing.
t() {
  local s="\$1" i
  for ((i=0; i<\${#s}; i++)); do tmux send-keys -t rec -l "\${s:i:1}"; sleep 0.035; done
  tmux send-keys -t rec Enter
}

t "clear"; sleep 1

t "# 1. install the plugin"; sleep 1
t "claude plugin marketplace add $PLUGIN"; sleep 5
t "claude plugin install osm@opensecretmask"; sleep 7
t "clear"; sleep 1

t "# 2. a file with a real credential in it"; sleep 1
t "cat > demo-credentials.txt <<EOF"
t "# acme-deploy service account"
t "ACME_API_KEY=$FAKE_SECRET"
t "EOF"; sleep 1
t "cat demo-credentials.txt"; sleep 4
t "clear"; sleep 1

t "# 3. now ask Claude to read it"; sleep 1
t "claude"; sleep 10
t "read demo-credentials.txt and tell me the ACME_API_KEY value"; sleep 35
t "/osm-secrets"; sleep 10

# Typing /exit one character at a time opens the slash-command menu, which
# sprays the whole command list over the payoff and is the last thing the GIF
# shows. Two Ctrl-Cs leave without drawing anything.
tmux send-keys -t rec C-c; sleep 1
tmux send-keys -t rec C-c; sleep 3
tmux send-keys -t rec -l "exit"; tmux send-keys -t rec Enter

for _ in \$(seq 1 30); do tmux has-session -t rec 2>/dev/null || break; sleep 1; done
# The session has usually ended on its own by here, and kill-session answers 1
# for a session that is already gone. Under \`set -e\` that reads as a failed
# recording and takes the whole run down before the GIF is made.
tmux kill-session -t rec 2>/dev/null || true
test -s "\$CAST"
DRIVE
chmod +x "$HOME_DEMO/drive.sh"
chown demo:demo "$HOME_DEMO/drive.sh"

mkdir -p "$OUT"
# Whatever happens next, the box is destroyed the moment this script returns,
# so the logs have to be inside the pulled directory rather than in /tmp.
trap 'cp /tmp/*.log "$OUT/" 2>/dev/null; true' EXIT
su - demo -c "$HOME_DEMO/drive.sh" >"$OUT/drive.log" 2>&1 || echo "drive.sh failed rc=$?"
tail -5 "$OUT/drive.log"

say "7. gif"
# --idle-time-limit collapses the waits for the model; without it most of the
# GIF is a still frame.
cp "$HOME_DEMO/osm-demo.cast" "$OUT/osm-demo.cast" 2>/dev/null || echo "no cast recorded"
if [ -s "$OUT/osm-demo.cast" ]; then
  su - demo -c "agg --font-family 'JetBrains Mono' --theme dracula \
    --idle-time-limit 2 --fps-cap 15 --last-frame-duration 4 \
    \$HOME/osm-demo.cast /tmp/osm-demo.gif"
  cp /tmp/osm-demo.gif "$OUT/osm-demo.gif"
fi
ls -lh "$OUT"
