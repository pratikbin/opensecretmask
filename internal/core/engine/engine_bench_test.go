package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

// bootstrapEngineBench mirrors bootstrapEngine for use from *testing.B.
// House style is per-file inline helpers (no shared testutil package).
func bootstrapEngineBench(b *testing.B) (*Engine, string) {
	b.Helper()
	root := b.TempDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		b.Fatal(err)
	}
	keyBytes, err := keymgr.Generate(root)
	if err != nil {
		b.Fatal(err)
	}
	cfg := store.DefaultConfig()
	if err := store.SaveSecrets(filepath.Join(root, store.SecretsName), &store.Secrets{Version: 1}); err != nil {
		b.Fatal(err)
	}
	if err := store.SaveMappings(filepath.Join(root, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}); err != nil {
		b.Fatal(err)
	}
	al := &store.Allowlist{Values: cfg.Detector.Allowlist.Values}
	if err := store.SaveAllowlist(filepath.Join(root, store.AllowlistName), al); err != nil {
		b.Fatal(err)
	}
	lock, err := store.OpenLock(root)
	if err != nil {
		b.Fatal(err)
	}
	rules := detector.BuiltinRules()
	allow, err := detector.NewAllowlistSet(al.Values, al.Patterns, al.RulesDisabled)
	if err != nil {
		b.Fatal(err)
	}
	ent := detector.NewEntropyScanner(cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	det := detector.NewDetector(detector.NewRegisteredSet(nil), rules, ent, allow)
	return &Engine{
		Cfg: cfg, Hasher: keymgr.NewHasher(keyBytes), Lock: lock, Detector: det,
		Audit: store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo),
		Root:  root, Allowlist: al, Rules: rules,
	}, root
}

func BenchmarkMaskText_NewSecret(b *testing.B) {
	eng, _ := bootstrapEngineBench(b)
	payload := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secret := fmt.Sprintf("sk_live_%024dBenchNew", i)
		in := "before " + secret + " after"
		_, _, err := eng.MaskText(context.Background(), "s", "bench", in)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaskText_KnownSecret(b *testing.B) {
	eng, _ := bootstrapEngineBench(b)
	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	if _, _, err := eng.MaskText(context.Background(), "s", "seed", in); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := eng.MaskText(context.Background(), "s", "bench", in)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmaskText_LargeReverseIndex(b *testing.B) {
	eng, _ := bootstrapEngineBench(b)
	const seedCount = 200
	masks := make([]string, 0, seedCount)
	for i := 0; i < seedCount; i++ {
		secret := fmt.Sprintf("sk_live_%024dUnmaskBench", i)
		out, _, err := eng.MaskText(context.Background(), "s", "seed", secret)
		if err != nil {
			b.Fatal(err)
		}
		masks = append(masks, out)
	}
	doc := strings.Join(masks, "\n")
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := eng.UnmaskText(doc)
		if err != nil {
			b.Fatal(err)
		}
	}
}
