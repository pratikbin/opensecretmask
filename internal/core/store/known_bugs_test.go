package store

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Known issues regression tests gated by t.Skip. Removing the skip MUST make
// the test pass once the underlying production code is fixed. See CLAUDE.md.

// Bug #2: WriteAtomic in atomic.go:37 calls os.Rename(tmp, path) but never
// fsyncs the parent directory after the rename. On crash immediately after
// rename (before metadata flushes) the directory entry can be lost despite
// the in-file Sync. The test below exists as a TODO marker — verifying the
// fsync syscall directly from Go is impractical without a syscall mock or
// crash simulation, so the body is a no-op assertion of the contract that
// the production fix should satisfy.
func TestWriteAtomic_ParentDirSyncMissing_KnownBug(t *testing.T) {
	t.Skip("known: see CLAUDE.md known issues — atomic.go:37 os.Rename without parent dir fsync. " +
		"Fix: open the parent dir, call Sync(), close. Then this test can assert via " +
		"strace/ptrace or a syscall fake that fsync was invoked on the parent fd.")

	dir := t.TempDir()
	p := filepath.Join(dir, "atomic.json")
	require.NoError(t, WriteAtomic(p, []byte(`{"v":1}`), 0o600))
}

// Bug #5: Config.Validate() in config.go only checks > 0 lower bounds for
// numeric fields. It accepts pathologically large values (e.g. MaxScanBytes
// = 1<<40 which exceeds reasonable RAM, LockTimeoutMs = math.MaxInt32 which
// effectively disables timeout). Spec-locked per CLAUDE.md "no features
// beyond requested" — fix would require spec change.
func TestConfigValidate_AcceptsUnboundedNumeric_KnownBug(t *testing.T) {
	t.Skip("known: see CLAUDE.md known issues — Config.Validate() lacks upper-bound " +
		"checks on MaxScanBytes / LockTimeoutMs / MaxContainerBytes. Spec-locked.")

	cfg := DefaultConfig()
	cfg.Engine.MaxScanBytes = 1 << 40
	cfg.Engine.LockTimeoutMs = math.MaxInt32
	cfg.Engine.MaxContainerBytes = 1 << 40

	err := cfg.Validate()
	require.Error(t, err, "post-fix: Validate must reject unbounded numeric fields")
}

