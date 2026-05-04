package detector

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func repeat(s string, n int) string { return strings.Repeat(s, n) }

func TestBuiltinRules_Count(t *testing.T) {
	rules := BuiltinRules()
	// env-import and entropy-high removed: their patterns matched any 12+/24+
	// char identifier and over-masked Go symbols, env var names, model strings.
	// 17 original prefix-anchored rules + 18 infra/SaaS additions = 35.
	require.GreaterOrEqual(t, len(rules), 30)
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
		"gcp-api-key":            "AIzaSyA-AbCdEfGhIjKlMnOpQrStUvWxYz12345",
		"openai-key-project":     "sk-proj-AbCdEfGhIjKlMnOpQrSt-Uv_Wx",
		"vault-token":            "hvs.CAESIBcDEfGhIjKlMnOpQrStUvWx",
		"terraform-cloud":        "n9p9XYJ4tlIPwf.atlasv1." + repeat("A", 60),
		"digitalocean-token":     "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"sendgrid-key":           "SG.AbCdEfGhIjKlMnOpQrStUv.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj",
		"twilio-account-sid":     "AC0123456789abcdef0123456789abcdef",
		"newrelic-user-key":      "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXY12",
		"sentry-dsn":             "https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/1234567",
		"npm-token":              "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab",
		"docker-hub-pat":         "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxYz0",
		"pypi-token":             "pypi-AgEIcHlwaS5vcmcAbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn",
		"atlassian-api-token":    "ATATT" + repeat("A", 180),
		"linear-api-key":         "lin_api_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd",
		"notion-secret":          "secret_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhI",
		"groq-key":               "gsk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQr",
		"huggingface-token":      "hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"postman-key":            "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef0123",
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
