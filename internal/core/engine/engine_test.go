package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

func bootstrapEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(root, 0o700))

	keyBytes, err := keymgr.Generate(root)
	require.NoError(t, err)

	cfg := store.DefaultConfig()
	require.NoError(t, store.SaveSecrets(filepath.Join(root, store.SecretsName), &store.Secrets{Version: 1}))
	require.NoError(t, store.SaveMappings(filepath.Join(root, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}))
	al := &store.Allowlist{Values: cfg.Detector.Allowlist.Values}
	require.NoError(t, store.SaveAllowlist(filepath.Join(root, store.AllowlistName), al))

	lock, err := store.OpenLock(root)
	require.NoError(t, err)

	rules := detector.BuiltinRules()
	allow, err := detector.NewAllowlistSet(al.Values, al.Patterns, al.RulesDisabled)
	require.NoError(t, err)
	ent := detector.NewEntropyScanner(cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	det := detector.NewDetector(detector.NewRegisteredSet(nil), rules, ent, allow)

	eng := &Engine{
		Cfg:       cfg,
		Hasher:    keymgr.NewHasher(keyBytes),
		Lock:      lock,
		Detector:  det,
		Audit:     store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo),
		Root:      root,
		Allowlist: al,
		Rules:     rules,
	}
	return eng, root
}

func TestEngine_MaskText_StripeKey(t *testing.T) {
	eng, root := bootstrapEngine(t)
	in := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	out, hits, err := eng.MaskText(context.Background(), "sess1", "test", in)
	require.NoError(t, err)
	require.NotEmpty(t, hits)
	require.Contains(t, out, "before ")
	require.Contains(t, out, " after")
	require.Contains(t, out, "sk_live_")
	require.NotContains(t, out, "sk_live_4eC39HqLyjWDarjtT1zdp7dc")

	m, err := store.LoadMappings(filepath.Join(root, store.MappingsName))
	require.NoError(t, err)
	require.Len(t, m.ByMask, 1)
}

func TestEngine_MaskText_Idempotent(t *testing.T) {
	eng, _ := bootstrapEngine(t)
	in := "x sk_live_4eC39HqLyjWDarjtT1zdp7dc y"
	a, _, err := eng.MaskText(context.Background(), "s", "t", in)
	require.NoError(t, err)
	b, _, err := eng.MaskText(context.Background(), "s", "t", in)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestEngine_UnmaskText(t *testing.T) {
	eng, _ := bootstrapEngine(t)
	original := "x sk_live_4eC39HqLyjWDarjtT1zdp7dc y"
	masked, _, err := eng.MaskText(context.Background(), "s", "t", original)
	require.NoError(t, err)
	require.NotEqual(t, original, masked)

	out, n, err := eng.UnmaskText(masked)
	require.NoError(t, err)
	require.Equal(t, original, out)
	require.GreaterOrEqual(t, n, 1)
}

func TestEngine_PreloadEnv(t *testing.T) {
	eng, root := bootstrapEngine(t)
	envDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(envDir, ".env"), []byte("MY_TOKEN=secret123abcdef\n"), 0o600))

	n, err := eng.PreloadEnv(context.Background(), envDir)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	m, err := store.LoadMappings(filepath.Join(root, store.MappingsName))
	require.NoError(t, err)
	require.Len(t, m.ByMask, 1)

	for _, v := range m.ByMask {
		require.Equal(t, "secret123abcdef", v)
	}

	// idempotent: second preload registers nothing
	n2, err := eng.PreloadEnv(context.Background(), envDir)
	require.NoError(t, err)
	require.Equal(t, 0, n2)

	// silence unused
	_ = strings.Builder{}
}
