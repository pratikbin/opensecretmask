package transformer

import (
	"regexp"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
)

func FuzzMaskUnmask(f *testing.F) {
	f.Add("sk_live_4eC39HqLyjWDarjtT1zdp7dc")
	f.Add("sk_live_AbCdEfGhIjKlMnOpQrStUvWx")
	d := f.TempDir()
	k, err := keymgr.Generate(d)
	if err != nil {
		f.Fatal(err)
	}
	hasher := keymgr.NewHasher(k)
	rule := Rule{
		ID:        "stripe-live",
		Pattern:   regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
		MinLen:    32, MaxLen: 4096,
		PrefixLen: 8, Charset: CharsetAlphanumeric,
	}
	f.Fuzz(func(t *testing.T, real string) {
		if !rule.Pattern.MatchString(real) || len(real) < 32 {
			t.Skip()
		}
		existing := map[string]string{}
		mask, err := Mask(real, rule, hasher, existing)
		if err != nil {
			t.Fatal(err)
		}
		if mask == real {
			t.Fatal("mask == real")
		}
		if len(mask) != len(real) {
			t.Fatalf("len mismatch %d vs %d", len(mask), len(real))
		}
		// Build reverse index with this single mapping; replace; assert recovery.
		idx := BuildReverseIndex(map[string]string{mask: real})
		text := "before " + mask + " after"
		out := idx.Replace(text)
		if out != "before "+real+" after" {
			t.Fatalf("roundtrip failed: %q", out)
		}
	})
}
