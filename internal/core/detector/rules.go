package detector

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"

	"github.com/BurntSushi/toml"
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

func BuiltinRules() []transformer.Rule {
	return []transformer.Rule{
		// 1. stripe-live
		{
			ID:        "stripe-live",
			Pattern:   regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			MinLen:    32, MaxLen: 4096,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
		// 2. stripe-test
		{
			ID:        "stripe-test",
			Pattern:   regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,}`),
			MinLen:    32, MaxLen: 4096,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
		// 3. stripe-restricted
		{
			ID:        "stripe-restricted",
			Pattern:   regexp.MustCompile(`rk_(?:live|test)_[A-Za-z0-9]{24,}`),
			MinLen:    32, MaxLen: 4096,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
		// 4. aws-access-key
		{
			ID:        "aws-access-key",
			Pattern:   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			MinLen:    20, MaxLen: 20,
			PrefixLen: 4, Charset: transformer.CharsetAlphaUpper,
		},
		// 5. aws-secret-key — length-40 base64-ish heuristic, no prefix
		{
			ID:      "aws-secret-key",
			Pattern: regexp.MustCompile(`(?:(?:^|[^A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$))`),
			MinLen:  40, MaxLen: 4096,
			PrefixLen: 0, Charset: transformer.CharsetBase64,
			Segments: []transformer.Segment{{Name: "aws-secret", Group: 1, Charset: transformer.CharsetBase64}},
		},
		// 6. anthropic-key
		{
			ID:        "anthropic-key",
			Pattern:   regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
			MinLen:    27, MaxLen: 4096,
			PrefixLen: 7, Charset: transformer.CharsetAlphanumeric,
		},
		// 7. openai-key
		{
			ID:        "openai-key",
			Pattern:   regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
			MinLen:    23, MaxLen: 4096,
			PrefixLen: 3, Charset: transformer.CharsetAlphanumeric,
		},
		// 8. github-pat-classic
		{
			ID:        "github-pat-classic",
			Pattern:   regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			MinLen:    40, MaxLen: 40,
			PrefixLen: 4, Charset: transformer.CharsetAlphanumeric,
		},
		// 9. github-pat-finegrained
		{
			ID:        "github-pat-finegrained",
			Pattern:   regexp.MustCompile(`github_pat_[A-Za-z0-9_]{40,}`),
			MinLen:    51, MaxLen: 4096,
			PrefixLen: 11, Charset: transformer.CharsetAlphanumeric,
		},
		// 10. gitlab-pat
		{
			ID:        "gitlab-pat",
			Pattern:   regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
			MinLen:    26, MaxLen: 4096,
			PrefixLen: 6, Charset: transformer.CharsetAlphanumeric,
		},
		// 11. slack-token
		{
			ID:        "slack-token",
			Pattern:   regexp.MustCompile(`xox[abp]-[A-Za-z0-9-]{10,}`),
			MinLen:    15, MaxLen: 4096,
			PrefixLen: 5, Charset: transformer.CharsetAlphanumeric,
		},
		// 12. jwt — segments 1 & 2 (header is kept; payload + signature masked)
		{
			ID:      "jwt",
			Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{10,})`),
			MinLen:  40, MaxLen: 4096,
			Segments: []transformer.Segment{
				{Name: "jwt-payload", Group: 1, Charset: transformer.CharsetBase64URL},
				{Name: "jwt-signature", Group: 2, Charset: transformer.CharsetBase64URL},
			},
		},
		// 13. pem-private-key
		{
			ID:          "pem-private-key",
			Pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END [A-Z ]*PRIVATE KEY-----`),
			MinLen:      80, MaxLen: 16384,
			BeginMarker: "-----BEGIN ",
			EndMarker:   "-----END ",
			Segments:    []transformer.Segment{{Name: "pem-body", Group: 1, Charset: transformer.CharsetBase64}},
		},
		// 14. db-conn-string
		{
			ID:      "db-conn-string",
			Pattern: regexp.MustCompile(`(?i)(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:/\s]+:([^@\s]+)@[^/\s]+(?:/\S+)?`),
			MinLen:  20, MaxLen: 4096,
			Segments: []transformer.Segment{{Name: "conn-password", Group: 1, Charset: transformer.CharsetAlphanumeric}},
		},
		// 15. bearer-token-url — masks query parameter value
		{
			ID:      "bearer-token-url",
			Pattern: regexp.MustCompile(`(?i)[?&](?:access_token|api_key|token|auth)=([A-Za-z0-9_.-]{16,})`),
			MinLen:  16, MaxLen: 4096,
			Segments: []transformer.Segment{{Name: "url-token", Group: 1, Charset: transformer.CharsetBase64URL}},
		},
		// 16. generic-bearer-header
		{
			ID:      "generic-bearer-header",
			Pattern: regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._~+/=-]{16,})`),
			MinLen:  16, MaxLen: 4096,
			Segments: []transformer.Segment{{Name: "bearer", Group: 1, Charset: transformer.CharsetBase64}},
		},
		// 17. ssh-private-key
		{
			ID:          "ssh-private-key",
			Pattern:     regexp.MustCompile(`(?s)-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END OPENSSH PRIVATE KEY-----`),
			MinLen:      80, MaxLen: 16384,
			BeginMarker: "-----BEGIN OPENSSH PRIVATE KEY-----",
			EndMarker:   "-----END OPENSSH PRIVATE KEY-----",
			Segments:    []transformer.Segment{{Name: "ssh-body", Group: 1, Charset: transformer.CharsetBase64}},
		},
		// 18. env-import — whole value, base64url (delimiter-safe)
		{
			ID:        "env-import",
			Pattern:   regexp.MustCompile(`[A-Za-z0-9_.~-]{12,}`),
			MinLen:    12, MaxLen: 4096,
			PrefixLen: 0, Charset: transformer.CharsetBase64URL,
		},
		// 19. entropy-high — whole value, base64url (delimiter-safe)
		{
			ID:        "entropy-high",
			Pattern:   regexp.MustCompile(`[A-Za-z0-9_+/=-]{24,}`),
			MinLen:    24, MaxLen: 4096,
			PrefixLen: 0, Charset: transformer.CharsetBase64URL,
		},
	}
}

type userRule struct {
	ID        string `toml:"id"`
	Pattern   string `toml:"pattern"`
	PrefixLen int    `toml:"prefix_len"`
	Charset   string `toml:"charset"`
	MinLen    int    `toml:"min_len"`
	MaxLen    int    `toml:"max_len"`
}

type userRulesFile struct {
	Rules []userRule `toml:"rules"`
}

// LoadUserRules reads rules.toml and appends to builtins. Missing file → (nil, nil).
func LoadUserRules(path string) ([]transformer.Rule, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var u userRulesFile
	if _, err := toml.Decode(string(data), &u); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]transformer.Rule, 0, len(u.Rules))
	for _, r := range u.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		cs, ok := transformer.ParseCharset(r.Charset)
		if !ok {
			return nil, fmt.Errorf("rule %q: unknown charset %q", r.ID, r.Charset)
		}
		max := r.MaxLen
		if max == 0 {
			max = 4096
		}
		min := r.MinLen
		if min == 0 {
			min = 1
		}
		out = append(out, transformer.Rule{
			ID:        r.ID,
			Pattern:   re,
			MinLen:    min,
			MaxLen:    max,
			PrefixLen: r.PrefixLen,
			Charset:   cs,
		})
	}
	return out, nil
}
