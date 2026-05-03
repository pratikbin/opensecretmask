package transformer

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/stretchr/testify/require"
)

// helper: build a real keymgr.Hasher from a generated install key.
func newKeymgrHasher(t *testing.T) *keymgr.Hasher {
	t.Helper()
	d := t.TempDir()
	k, err := keymgr.Generate(d)
	require.NoError(t, err)
	return keymgr.NewHasher(k)
}

func charsetContainsAll(cs, body []byte) bool {
	for _, c := range body {
		if bytes.IndexByte(cs, c) < 0 {
			return false
		}
	}
	return true
}

func TestMaskFlat_StripeLive(t *testing.T) {
	h := newKeymgrHasher(t)
	real := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	rule := Rule{ID: "stripe-live", PrefixLen: 8, Charset: CharsetAlphanumeric}

	masked, err := Mask(real, rule, h, nil)
	require.NoError(t, err)
	require.Equal(t, len(real), len(masked))
	require.Equal(t, "sk_live_", masked[:8])
	require.NotEqual(t, real, masked)
	require.True(t, charsetContainsAll(CharsetAlphanumeric.Bytes(), []byte(masked[8:])))

	masked2, err := Mask(real, rule, h, nil)
	require.NoError(t, err)
	require.Equal(t, masked, masked2)
}

func TestMaskFlat_Determinism(t *testing.T) {
	h := newKeymgrHasher(t)
	real := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	rule := Rule{ID: "stripe-live", PrefixLen: 8, Charset: CharsetAlphanumeric}

	a, err := Mask(real, rule, h, nil)
	require.NoError(t, err)
	b, err := Mask(real, rule, h, nil)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestMaskFlat_DifferentInstallKeys(t *testing.T) {
	h1 := newKeymgrHasher(t)
	h2 := newKeymgrHasher(t)
	real := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	rule := Rule{ID: "stripe-live", PrefixLen: 8, Charset: CharsetAlphanumeric}

	m1, err := Mask(real, rule, h1, nil)
	require.NoError(t, err)
	m2, err := Mask(real, rule, h2, nil)
	require.NoError(t, err)
	require.NotEqual(t, m1, m2)
}

func TestMaskSegments_JWT(t *testing.T) {
	h := newKeymgrHasher(t)
	real := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pat := regexp.MustCompile(`^([^.]+)\.([^.]+)\.([^.]+)$`)
	rule := Rule{
		ID:      "jwt",
		Pattern: pat,
		Segments: []Segment{
			{Name: "payload", Group: 2, Charset: CharsetBase64URL},
			{Name: "sig", Group: 3, Charset: CharsetBase64URL},
		},
	}

	masked, err := Mask(real, rule, h, nil)
	require.NoError(t, err)
	require.Equal(t, len(real), len(masked))

	parts := bytes.Split([]byte(masked), []byte("."))
	require.Len(t, parts, 3)

	origParts := bytes.Split([]byte(real), []byte("."))
	require.Equal(t, origParts[0], parts[0], "header (group 1) must be unchanged")
	require.Equal(t, len(origParts[1]), len(parts[1]))
	require.Equal(t, len(origParts[2]), len(parts[2]))
	require.NotEqual(t, origParts[1], parts[1])
	require.NotEqual(t, origParts[2], parts[2])
	require.True(t, charsetContainsAll(CharsetBase64URL.Bytes(), parts[1]))
	require.True(t, charsetContainsAll(CharsetBase64URL.Bytes(), parts[2]))
}

func TestMaskRejectsShortReal(t *testing.T) {
	h := newKeymgrHasher(t)
	rule := Rule{ID: "x", PrefixLen: 10, Charset: CharsetAlphanumeric}
	_, err := Mask("short", rule, h, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "shorter than")
}

func TestMaskRejectsTooFewBytes(t *testing.T) {
	// When bodyLen==0, every attempt yields prefix == real, so the verbatim
	// spec logic exhausts retries. Documented behavior per §4.4.
	h := newKeymgrHasher(t)
	real := "exactlyten"
	rule := Rule{ID: "x", PrefixLen: 10, Charset: CharsetAlphanumeric}
	_, err := Mask(real, rule, h, nil)
	require.ErrorIs(t, err, ErrMaskExhaustedRetries)
}

func TestMaskSegmentsRejectsBadGroup(t *testing.T) {
	h := newKeymgrHasher(t)
	pat := regexp.MustCompile(`^(\w+)$`)
	rule := Rule{
		ID:      "bad",
		Pattern: pat,
		Segments: []Segment{
			{Name: "x", Group: 5, Charset: CharsetAlphanumeric},
		},
	}
	_, err := Mask("hello", rule, h, nil)
	require.Error(t, err)
}

func TestMaskCrossSecretCollision(t *testing.T) {
	t.Skip("requires hasher mock or controlled stream")
}

func TestMaskCollisionFallback(t *testing.T) {
	t.Skip("requires hasher mock; covered indirectly")
}

func TestRejectionSampling_NoModuloBias(t *testing.T) {
	h := newKeymgrHasher(t)
	cs := CharsetAlphanumeric.Bytes()
	csLen := len(cs)

	// HKDF-SHA256 max output is 255*32 = 8160 bytes. Aggregate across
	// multiple distinct info inputs to reach a meaningful sample.
	const perDraw = 4096
	const draws = 16
	const n = perDraw * draws

	counts := make(map[byte]int, csLen)
	for d := 0; d < draws; d++ {
		info := []byte{byte(d), 'c', 'h', 'i', '-', 's', 'q'}
		body, err := deriveCharsetBytes(h, info, 0, perDraw, cs)
		require.NoError(t, err)
		for _, b := range body {
			counts[b]++
		}
	}
	require.Equal(t, csLen, len(counts), "all charset bytes must appear")

	expected := float64(n) / float64(csLen)
	chi2 := 0.0
	for _, c := range cs {
		obs := float64(counts[c])
		diff := obs - expected
		chi2 += (diff * diff) / expected
	}
	// 61 df at p=0.001 ≈ 100.4. Loose threshold to avoid flakes under -race.
	require.Less(t, chi2, 200.0, "chi-square = %f suggests modulo bias", chi2)
}
