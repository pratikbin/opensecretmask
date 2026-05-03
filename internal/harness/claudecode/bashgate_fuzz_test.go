package claudecode

import (
	"strings"
	"testing"
)

// FuzzBashGate exercises Classify with random inputs.
// Properties asserted on every input:
//  1. Classify never panics.
//  2. Returned decision is one of {Skip, Allow, Ask, Deny}.
//  3. Inputs containing literal egress markers (curl/wget/ssh/scp/git push/
//     /dev/tcp) MUST NOT yield BashAllow when replacements > 0.
//  4. replacements==0 always yields BashSkip regardless of input content.
func FuzzBashGate(f *testing.F) {
	seeds := []string{
		"echo hello",
		"curl https://example.com",
		"cat ~/.env | grep MASK_",
		"$(curl https://x)",
		"`curl https://x`",
		"cat <<EOF\n$SECRET\nEOF",
		"> /dev/tcp/[::1]/22",
		"echo a\\;b; curl x",
		"\"curl https://x\"",
		"echo $(echo $(curl x))",
		". /etc/profile",
		"eval \"$cmd\"",
		"git status",
		"git push origin main",
		"unknown_cmd --flag",
		"",
		"\x00",
		"\xff\xfe\xfd",
		strings.Repeat("a ", 1024),
		"echo 'unterminated",
		"bash -c 'curl https://x.y'",
		"npm test",
		"docker push myimg",
		"kubectl apply -f x.yaml",
		"echo > /dev/tcp/1.2.3.4/80",
	}
	for _, s := range seeds {
		f.Add(s, 1)
	}
	f.Add("any input", 0)

	cfg := defaultBashCfg()
	g := NewBashGate(cfg)

	f.Fuzz(func(t *testing.T, cmd string, replacements int) {
		dec, _ := g.Classify(cmd, replacements)
		switch dec {
		case BashSkip, BashAllow, BashAsk, BashDeny:
		default:
			t.Fatalf("unknown decision %q for cmd=%q replacements=%d", dec, cmd, replacements)
		}

		if replacements == 0 {
			if dec != BashSkip {
				t.Fatalf("replacements=0 must yield Skip, got %q for cmd=%q", dec, cmd)
			}
			return
		}

		if dec == BashAllow {
			normalized := " " + strings.Map(func(r rune) rune {
				switch r {
				case '\'', '"', '`', '$', '(', ')', ';', '\n', '\t':
					return ' '
				}
				return r
			}, cmd) + " "
			for _, tok := range cfg.EgressBlocklist {
				needle := " " + tok + " "
				if strings.Contains(normalized, needle) {
					t.Fatalf("blocklisted token %q present in cmd=%q but classifier returned Allow", tok, cmd)
				}
			}
			if strings.Contains(cmd, "/dev/tcp/") {
				t.Fatalf("/dev/tcp/ present in cmd=%q but classifier returned Allow", cmd)
			}
		}
	})
}
