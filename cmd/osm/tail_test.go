package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func writeAuditLine(t *testing.T, dir string, ev store.AuditEvent) {
	t.Helper()
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	b = append(b, '\n')
	require.NoError(t, os.WriteFile(filepath.Join(dir, store.AuditName), b, 0o600))
}

func TestTail_PrettyPrint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	writeAuditLine(t, dir, store.AuditEvent{
		TS:     ts,
		Action: "mask",
		Tool:   "Bash",
		Rule:   "stripe-key",
		Count:  3,
	})

	out, _, err := runOSM(t, "tail")
	require.NoError(t, err)
	require.Contains(t, out, "2025-01-02T03:04:05Z")
	require.Contains(t, out, "mask")
	require.Contains(t, out, "tool=Bash")
	require.Contains(t, out, "rule=stripe-key")
	require.Contains(t, out, "count=3")
}

func TestTail_RawJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	writeAuditLine(t, dir, store.AuditEvent{
		TS:     ts,
		Action: "mask",
		Tool:   "Bash",
		Rule:   "stripe-key",
		Count:  3,
	})

	out, _, err := runOSM(t, "tail", "--json")
	require.NoError(t, err)
	require.Contains(t, out, `"action":"mask"`)
	require.Contains(t, out, `"tool":"Bash"`)
}
