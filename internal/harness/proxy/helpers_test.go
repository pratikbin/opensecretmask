package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/engine"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

func bootstrapTestEngine(t *testing.T) *engine.Engine {
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

	return &engine.Engine{
		Cfg:       cfg,
		Hasher:    keymgr.NewHasher(keyBytes),
		Lock:      lock,
		Detector:  det,
		Audit:     store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo),
		Root:      root,
		Allowlist: al,
		Rules:     rules,
	}
}
