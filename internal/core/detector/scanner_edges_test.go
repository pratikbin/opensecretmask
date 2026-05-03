package detector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Edge cases not exercised by scanner_test.go.

func TestStream_EmptyInput(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(""), &out))
	require.Equal(t, "", out.String())
}

func TestStream_SecretSplitAcrossManyChunks(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	r := &chunkReader{src: []byte(in), chunkSize: 1}
	var out bytes.Buffer
	require.NoError(t, s.Stream(r, &out))
	require.Equal(t, "before MASKED_stripe-live_32 after", out.String())
}

func TestStream_MultipleSecretsBackToBack(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := "sk_live_4eC39HqLyjWDarjtT1zdp7dc sk_live_AbCdEfGhIjKlMnOpQrStUvWx"
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Equal(t, "MASKED_stripe-live_32 MASKED_stripe-live_32", out.String())
}

func TestStream_ScanCapTruncate_NoSecretLeak(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 100, 1<<20, testMask)

	in := strings.Repeat("x", 100) + "OVERSIZE_REAL_PAYLOAD_sk_live_AbCdEfGhIjKlMnOpQrStUvWx"
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.NotContains(t, out.String(), "OVERSIZE_REAL_PAYLOAD",
		"truncate must not leak any bytes past the cap into the output")
	require.NotContains(t, out.String(), "sk_live_AbCdEfGhIjKlMnOpQrStUvWx",
		"truncate path must not leak the actual secret either")
	require.Contains(t, out.String(), "scan-cap exceeded")
}

func TestStream_ContainerOverflow_NoBodyOrEndMarkerLeak(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 64, testMask)

	body := strings.Repeat("Z", 200) + "RECOGNIZABLE_SENTINEL"
	in := "header\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\nfooter"
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.ErrorIs(t, err, ErrContainerOverflow)
	require.NotContains(t, out.String(), "RECOGNIZABLE_SENTINEL", "container body bytes must not flush on overflow")
	require.NotContains(t, out.String(), "-----BEGIN", "BEGIN marker bytes must not flush on overflow")
	require.NotContains(t, out.String(), "-----END", "END marker bytes must not flush on overflow")
}

func TestStream_UnclosedContainer_NoBodyLeak(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	body := "RECOGNIZABLE_SENTINEL_BODY_BYTES"
	in := "header\n-----BEGIN RSA PRIVATE KEY-----\n" + body
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.ErrorIs(t, err, ErrUnclosedContainer)
	require.NotContains(t, out.String(), body, "unclosed-container EOF must not leak body bytes")
}

func TestStream_ContainerImmediatelyClosed(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	// Empty body fails the rule's pattern regex (which requires non-empty
	// base64 body). Scanner should pass through the markers unmodified
	// rather than crash.
	in := "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----"
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Equal(t, in, out.String(), "empty body must passthrough markers without panic")
}
