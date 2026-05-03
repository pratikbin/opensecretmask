package transformer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCharsetLengths(t *testing.T) {
	require.Len(t, CharsetAlphanumeric.Bytes(), 62)
	require.Len(t, CharsetHex.Bytes(), 16)
	require.Len(t, CharsetBase64URL.Bytes(), 64)
	require.Len(t, CharsetAlphaUpper.Bytes(), 36)
	require.Len(t, CharsetBase64.Bytes(), 65)
}

func TestParseCharset_Roundtrip(t *testing.T) {
	cases := map[string]Charset{
		"alphanumeric": CharsetAlphanumeric,
		"hex":          CharsetHex,
		"base64url":    CharsetBase64URL,
		"alphaupper":   CharsetAlphaUpper,
		"base64":       CharsetBase64,
	}
	for s, want := range cases {
		got, ok := ParseCharset(s)
		require.True(t, ok, "ParseCharset(%q) ok", s)
		require.Equal(t, want, got, "ParseCharset(%q) value", s)
	}
}

func TestParseCharset_Unknown(t *testing.T) {
	_, ok := ParseCharset("bogus")
	require.False(t, ok)
}
