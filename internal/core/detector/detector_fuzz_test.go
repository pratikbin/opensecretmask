package detector

import (
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

func newFuzzDetector(t testing.TB) *Detector {
	t.Helper()
	rules := BuiltinRules()
	al, _ := NewAllowlistSet(nil, nil, nil)
	ent := NewEntropyScanner(4.5, 24)
	return NewDetector(NewRegisteredSet(nil), rules, ent, al)
}

func FuzzDetector(f *testing.F) {
	f.Add([]byte("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
	f.Add([]byte(""))
	f.Add(make([]byte, 1024))
	d := newFuzzDetector(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = d.Detect(string(b))
		_ = transformer.Charset(0).Bytes() // touch transformer to keep import
	})
}
