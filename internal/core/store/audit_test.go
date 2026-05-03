package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppend_TruncatesMask(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	w := NewAuditWriter(p, 4)
	require.NoError(t, w.Append(AuditEvent{Action: "mask", Mask: "ABCDEFGH"}))

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(b), `"mask":"ABCD…"`)
}

func TestAppend_Concurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	w := NewAuditWriter(p, 12)

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, w.Append(AuditEvent{Action: "x"}))
		}()
	}
	wg.Wait()

	f, err := os.Open(p)
	require.NoError(t, err)
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev AuditEvent
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		count++
	}
	require.NoError(t, sc.Err())
	require.Equal(t, n, count)
}

func TestAppend_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	w := NewAuditWriter(p, 0)
	big := strings.Repeat("x", 5000)
	err := w.Append(AuditEvent{Action: "x", Error: big})
	require.Error(t, err)
}
