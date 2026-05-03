package detector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuiltinRules_Count(t *testing.T) {
	rules := BuiltinRules()
	require.GreaterOrEqual(t, len(rules), 18, "need at least 18 builtin rules per plan")
}

func TestBuiltinRules_PositiveSamples(t *testing.T) {
	cases := map[string]string{
		"stripe-live":            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"stripe-test":            "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
		"stripe-restricted":      "rk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"aws-access-key":         "AKIAIOSFODNN7EXAMPLE",
		"aws-secret-key":         " wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ",
		"anthropic-key":          "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"openai-key":             "sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"github-pat-classic":     "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01234567890",
		"github-pat-finegrained": "github_pat_AbCdEfGhIjKlMnOpQrStUvWxYz01234567890123",
		"gitlab-pat":             "glpat-AbCdEfGhIjKlMnOpQrStUvWx",
		"slack-token":            "xoxb-1234567890-abcdef0123456789",
		"jwt":                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"db-conn-string":         "postgres://user:p%40ssw0rd@host:5432/dbname",
		"bearer-token-url":       "https://api.example.com/v1?access_token=AbCdEf0123456789xyz",
		"generic-bearer-header":  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"env-import":             "AbCdEf012345_-.~ZyXwVu",
		"entropy-high":           "AbCdEfGhIjKlMnOpQrStUvWxYz",
	}
	rules := BuiltinRules()
	byID := map[string]int{}
	for i, r := range rules {
		byID[r.ID] = i
	}
	for id, sample := range cases {
		t.Run(id, func(t *testing.T) {
			i, ok := byID[id]
			require.True(t, ok, "rule %s missing", id)
			r := rules[i]
			require.True(t, r.Pattern.MatchString(sample), "rule %s should match sample %q", id, sample)
		})
	}
}

func TestBuiltinRules_PEMandSSH(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtest\nAAAA==\n-----END RSA PRIVATE KEY-----"
	ssh := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAB\nAAAAAAA==\n-----END OPENSSH PRIVATE KEY-----"
	rules := BuiltinRules()
	var pemRule, sshRule int
	for i, r := range rules {
		if r.ID == "pem-private-key" {
			pemRule = i
		}
		if r.ID == "ssh-private-key" {
			sshRule = i
		}
	}
	require.True(t, rules[pemRule].Pattern.MatchString(pem), "pem-private-key should match")
	require.True(t, rules[sshRule].Pattern.MatchString(ssh), "ssh-private-key should match")
}

func TestBuiltinRules_Negative(t *testing.T) {
	cases := map[string]string{
		"stripe-live":        "not-a-secret",
		"aws-access-key":     "AKIASHORT",
		"github-pat-classic": "ghp_short",
		"jwt":                "not.a.jwt-too-short",
	}
	rules := BuiltinRules()
	byID := map[string]int{}
	for i, r := range rules {
		byID[r.ID] = i
	}
	for id, sample := range cases {
		t.Run(id, func(t *testing.T) {
			r := rules[byID[id]]
			require.False(t, r.Pattern.MatchString(sample), "rule %s should NOT match %q", id, sample)
		})
	}
}

func TestLoadUserRules_Missing(t *testing.T) {
	out, err := LoadUserRules("/nonexistent/path/rules.toml")
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestLoadUserRules_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rules.toml"
	content := `[[rules]]
id = "custom-foo"
pattern = "FOO_[A-Za-z0-9]{8,}"
prefix_len = 4
charset = "alphanumeric"
min_len = 12
max_len = 100
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	out, err := LoadUserRules(path)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "custom-foo", out[0].ID)
	require.True(t, out[0].Pattern.MatchString("FOO_AbCdEfGh"))
}
