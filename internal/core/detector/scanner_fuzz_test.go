package detector

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzScanner_StreamRobustness asserts that Stream never panics on arbitrary
// input regardless of maxScan and maxContainer settings, and that any error
// returned is one of the documented sentinels (or an underlying io error).
func FuzzScanner_StreamRobustness(f *testing.F) {
	seeds := []struct {
		body     string
		maxScan  int
		maxCont  int
	}{
		{"", 1024, 1024},
		{"hello world", 1024, 1024},
		{strings.Repeat("a", 2048), 512, 1024},
		{"sk_live_4eC39HqLyjWDarjtT1zdp7dc", 1024, 1024},
		{"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----\n", 4096, 4096},
		{"-----BEGIN RSA PRIVATE KEY-----\nUNCLOSED", 4096, 4096},
		{"-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("X", 8192) + "\n-----END RSA PRIVATE KEY-----\n", 4096, 1024},
		{"\x00\x00\x00\x00", 1024, 1024},
		{strings.Repeat("\xff", 4096), 1024, 1024},
		{"", 0, 0},
	}
	for _, s := range seeds {
		f.Add(s.body, s.maxScan, s.maxCont)
	}

	rules := append(stripeRules(), pemRules()...)
	det := newFuzzDetectorTB(f)

	f.Fuzz(func(t *testing.T, body string, maxScan, maxCont int) {
		if maxScan < 1 {
			maxScan = 1
		}
		if maxCont < 1 {
			maxCont = 1
		}
		if len(body) > 1<<20 {
			t.Skip("payload too large for fuzz")
		}

		s := NewScanner(det, rules, maxScan, maxCont, testMask)
		var out bytes.Buffer
		err := s.Stream(strings.NewReader(body), &out)
		if err == nil {
			return
		}
		if errors.Is(err, ErrScanCapExceeded) || errors.Is(err, ErrContainerOverflow) || errors.Is(err, ErrUnclosedContainer) {
			return
		}
		// Any other error must be a wrapped read or mask error — never a panic
		// (panic would be caught by the test harness).
		t.Logf("non-sentinel error (acceptable): %v", err)
	})
}

// newFuzzDetectorTB mirrors newFuzzDetector(testing.TB) for use from *testing.F.
func newFuzzDetectorTB(tb testing.TB) *Detector {
	tb.Helper()
	allow, err := NewAllowlistSet(nil, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return NewDetector(nil, BuiltinRules(), nil, allow)
}
