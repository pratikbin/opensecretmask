package detector

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
	"github.com/stretchr/testify/require"
)

// chunkReader returns src in fixed-size chunks to exercise boundary handling.
type chunkReader struct {
	src       []byte
	chunkSize int
	pos       int
}

func (cr *chunkReader) Read(p []byte) (int, error) {
	if cr.pos >= len(cr.src) {
		return 0, io.EOF
	}
	end := cr.pos + cr.chunkSize
	if end > len(cr.src) {
		end = len(cr.src)
	}
	n := copy(p, cr.src[cr.pos:end])
	cr.pos += n
	if cr.pos >= len(cr.src) {
		return n, io.EOF
	}
	return n, nil
}

// testMask is identity-like for assertions: MASKED_<ruleID>_<len(value)>.
func testMask(value, ruleID string) (string, error) {
	return "MASKED_" + ruleID + "_" + strconv.Itoa(len(value)), nil
}

func stripeRules() []transformer.Rule {
	return []transformer.Rule{
		{
			ID:      "stripe-live",
			Pattern: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			MinLen:  32, MaxLen: 4096,
		},
	}
}

func pemRules() []transformer.Rule {
	return []transformer.Rule{
		{
			ID:          "pem-private-key",
			Pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END [A-Z ]*PRIVATE KEY-----`),
			MinLen:      40, MaxLen: 16384,
			BeginMarker: "-----BEGIN RSA PRIVATE KEY-----",
			EndMarker:   "-----END RSA PRIVATE KEY-----",
		},
	}
}

func newDet(t *testing.T, rules []transformer.Rule) *Detector {
	t.Helper()
	allow, err := NewAllowlistSet(nil, nil, nil)
	require.NoError(t, err)
	return NewDetector(nil, rules, nil, allow)
}

func TestStream_NoSecrets(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := strings.Repeat("lorem ipsum dolor sit amet ", 40) // ~1KB
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Equal(t, in, out.String())
}

func TestStream_SingleSecret(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Equal(t, "before MASKED_stripe-live_32 after", out.String())
}

func TestStream_StraddleBoundary(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	r := &chunkReader{src: []byte(in), chunkSize: 4}
	var out bytes.Buffer
	require.NoError(t, s.Stream(r, &out))
	require.Equal(t, "before MASKED_stripe-live_32 after", out.String())
}

func TestStream_PEM(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	body := "MIIEpAIBAAKCAQEAtest\nAAAA=="
	in := "prefix\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\nsuffix"
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))

	got := out.String()
	require.True(t, strings.HasPrefix(got, "prefix\n"), "prefix preserved: %q", got)
	require.True(t, strings.HasSuffix(got, "\nsuffix"), "suffix preserved: %q", got)
	require.Contains(t, got, "MASKED_pem-private-key_")
	// PEM body bytes must not appear raw in output.
	require.NotContains(t, got, body)
}

func TestStream_ContainerOverflow(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	// maxContainer small enough that PEM body overflows.
	s := NewScanner(det, rules, 1<<20, 64, testMask)

	body := strings.Repeat("A", 200)
	in := "prefix\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n"
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.ErrorIs(t, err, ErrContainerOverflow)

	// Writer must NOT contain any container body bytes; in particular not the BEGIN marker.
	require.NotContains(t, out.String(), "-----BEGIN")
	require.NotContains(t, out.String(), body)
}

func TestStream_EOFInContainer(t *testing.T) {
	rules := pemRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.ErrorIs(t, err, ErrUnclosedContainer)
	// No body bytes leaked.
	require.NotContains(t, out.String(), "-----BEGIN")
	require.NotContains(t, out.String(), "MIIEpAIBAAK")
}

func TestStream_ScanCap(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 128, 1<<20, testMask)

	in := strings.Repeat("x", 256)
	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Contains(t, out.String(), "[opensecretmask: scan-cap exceeded —")
	require.Contains(t, out.String(), "bytes withheld]")
}

func TestStream_ScanCapDeny(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	s := NewScanner(det, rules, 128, 1<<20, testMask)
	s.SetOnScanCap("deny")

	in := strings.Repeat("x", 256)
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.ErrorIs(t, err, ErrScanCapExceeded)
}

func TestStream_FlushOnEOF(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	// overlap=4096 > 200 — without EOF flush, secret in tail would be lost.
	s := NewScanner(det, rules, 1<<20, 1<<20, testMask)

	pad := strings.Repeat("a", 100)
	in := pad + " sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	require.LessOrEqual(t, len(in), 200)

	var out bytes.Buffer
	require.NoError(t, s.Stream(strings.NewReader(in), &out))
	require.Contains(t, out.String(), "MASKED_stripe-live_32")
	require.NotContains(t, out.String(), "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
}

func TestStream_MaskFuncError(t *testing.T) {
	rules := stripeRules()
	det := newDet(t, rules)
	bad := func(string, string) (string, error) { return "", errors.New("nope") }
	s := NewScanner(det, rules, 1<<20, 1<<20, bad)

	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	var out bytes.Buffer
	err := s.Stream(strings.NewReader(in), &out)
	require.Error(t, err)
}
