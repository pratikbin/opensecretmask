package detector

import (
	"regexp"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
	"github.com/stretchr/testify/require"
)

func mustAllowlist(t *testing.T, vals, pats, disabled []string) *AllowlistSet {
	t.Helper()
	a, err := NewAllowlistSet(vals, pats, disabled)
	require.NoError(t, err)
	return a
}

func TestDetect_RegisteredWinsOverRegex(t *testing.T) {
	reg := NewRegisteredSet([]string{"sk_live_ABCDEFGHIJKLMNOPQRSTUVWX"})
	rules := []transformer.Rule{
		{
			ID:      "stripe-live",
			Pattern: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			MinLen:  32, MaxLen: 4096,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
	}
	allow := mustAllowlist(t, nil, nil, nil)
	d := NewDetector(reg, rules, nil, allow)

	hits := d.Detect("use sk_live_ABCDEFGHIJKLMNOPQRSTUVWX here")
	require.Len(t, hits, 1)
	require.Equal(t, "registered", hits[0].Rule)
	require.Equal(t, 1.0, hits[0].Confidence)
	require.Equal(t, "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX", hits[0].Value)
}

func TestDetect_AllowlistSuppresses(t *testing.T) {
	rules := []transformer.Rule{
		{
			ID:      "host",
			Pattern: regexp.MustCompile(`localhost`),
			MinLen:  1, MaxLen: 4096,
		},
	}
	allow := mustAllowlist(t, []string{"localhost"}, nil, nil)
	d := NewDetector(nil, rules, nil, allow)

	hits := d.Detect("connect to localhost now")
	require.Empty(t, hits)
}

func TestDetect_EntropyOnlyAfterMiss(t *testing.T) {
	entropy := NewEntropyScanner(4.0, 8)
	allow := mustAllowlist(t, nil, nil, nil)
	d := NewDetector(nil, nil, entropy, allow)

	// 32 distinct chars yields ~5.0 bits/char; well above threshold.
	tok := "abcdefghijklmnopqrstuvwxyz012345"
	hits := d.Detect("token " + tok + " end")
	require.Len(t, hits, 1)
	require.Equal(t, "entropy-high", hits[0].Rule)
	require.Equal(t, tok, hits[0].Value)
}

func TestDetect_OverlapPrefersLonger(t *testing.T) {
	rules := []transformer.Rule{
		{
			ID:      "long",
			Pattern: regexp.MustCompile(`abcdef`),
			MinLen:  1, MaxLen: 4096,
		},
		{
			ID:      "short",
			Pattern: regexp.MustCompile(`abc`),
			MinLen:  1, MaxLen: 4096,
		},
	}
	allow := mustAllowlist(t, nil, nil, nil)
	d := NewDetector(nil, rules, nil, allow)

	hits := d.Detect("xx abcdef yy")
	require.Len(t, hits, 1)
	require.Equal(t, "long", hits[0].Rule)
	require.Equal(t, "abcdef", hits[0].Value)
}

func TestDetect_RuleDisabled(t *testing.T) {
	rules := []transformer.Rule{
		{
			ID:      "stripe-live",
			Pattern: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			MinLen:  32, MaxLen: 4096,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
	}
	allow := mustAllowlist(t, nil, nil, []string{"stripe-live"})
	d := NewDetector(nil, rules, nil, allow)

	hits := d.Detect("use sk_live_ABCDEFGHIJKLMNOPQRSTUVWX here")
	require.Empty(t, hits)
}

func TestRegisteredSet_NilSafe(t *testing.T) {
	var rs *RegisteredSet
	require.Nil(t, rs.scan("foo"))

	// Empty input also safe.
	rs2 := NewRegisteredSet(nil)
	require.Nil(t, rs2.scan("foo"))

	rs3 := NewRegisteredSet([]string{""})
	require.Nil(t, rs3.scan("foo"))
}
