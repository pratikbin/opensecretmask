package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/engine"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

// runHook builds a fresh root command, pipes stdin, and returns stdout.
func runHook(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(bytes.NewBufferString(stdin))
	root.SetOut(out)
	root.SetErr(errOut)
	err := root.Execute()
	return out.String(), err
}

func TestHook_PostToolUseRead_MaskStripeKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"session_id":      "s1",
		"tool_response": map[string]any{
			"content": "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after",
		},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PostToolUse")
	require.NoError(t, err)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	require.True(t, ok, "expected hookSpecificOutput, got: %s", out)
	updated, ok := hso["updatedToolOutput"].(map[string]any)
	require.True(t, ok)
	content, _ := updated["content"].(string)
	require.Contains(t, content, "sk_live_")
	require.NotContains(t, content, "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
}

func TestHook_PreToolUseEdit_UnmaskMask(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	// Pre-register a mask via the engine (same bootstrap as hook).
	eng := bootstrapForTest(t, dir)
	original := "x sk_live_4eC39HqLyjWDarjtT1zdp7dc y"
	masked, _, err := eng.MaskText(context.Background(), "s", "test", original)
	require.NoError(t, err)
	require.NotEqual(t, original, masked)

	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Edit",
		"session_id":      "s1",
		"tool_input": map[string]any{
			"old_string": masked,
			"new_string": "unrelated",
		},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PreToolUse")
	require.NoError(t, err)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	require.True(t, ok, "expected hookSpecificOutput, got: %s", out)
	updated, ok := hso["updatedInput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, original, updated["old_string"])
}

func TestHook_UserPromptSubmit_Warn(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	payload := map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"session_id":      "s1",
		"prompt":          "use sk_live_4eC39HqLyjWDarjtT1zdp7dc please",
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "UserPromptSubmit")
	require.NoError(t, err)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	require.True(t, ok, "expected hookSpecificOutput, got: %s", out)
	require.NotEmpty(t, hso["additionalContext"])
}

func TestHook_PostToolUseUninit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	// no init → no install.key

	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"session_id":      "s1",
		"tool_response":   map[string]any{"content": "hello"},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PostToolUse")
	require.NoError(t, err)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	require.Equal(t, "block", resp["decision"])
	require.Contains(t, resp["reason"], "opensecretmask")
}

// bootstrapForTest mirrors bootstrapEngine for test setup with a known root.
func bootstrapForTest(t *testing.T, root string) *engine.Engine {
	t.Helper()
	cfg, err := store.LoadConfig(filepath.Join(root, store.ConfigName))
	require.NoError(t, err)
	keyBytes, err := keymgr.LoadOrError(root)
	require.NoError(t, err)
	hasher := keymgr.NewHasher(keyBytes)
	lock, err := store.OpenLock(root)
	require.NoError(t, err)
	allow, err := store.LoadAllowlist(filepath.Join(root, store.AllowlistName))
	require.NoError(t, err)
	rules := detector.BuiltinRules()
	al, err := detector.NewAllowlistSet(allow.Values, allow.Patterns, allow.RulesDisabled)
	require.NoError(t, err)
	ent := detector.NewEntropyScanner(cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	det := detector.NewDetector(detector.NewRegisteredSet(nil), rules, ent, al)
	return &engine.Engine{
		Cfg: cfg, Hasher: hasher, Lock: lock, Detector: det,
		Audit: store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo),
		Root:  root, Allowlist: allow, Rules: rules,
	}
}
