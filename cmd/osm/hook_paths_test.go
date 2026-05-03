package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/internal/harness"
	"github.com/pratikbin/opensecretmask/internal/harness/claudecode"
)

// corruptMappings overwrites mappings.json with invalid JSON so that
// any LoadMappings call fails — used to drive runMask/runUnmask error paths.
func corruptMappings(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, store.MappingsName), []byte("{not-json"), 0o600))
}

func TestRunMask_DenyOnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	corruptMappings(t, dir)

	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"session_id":      "s1",
		"tool_response":   map[string]any{"content": "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PostToolUse")
	require.NoError(t, err)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	hso, _ := resp["hookSpecificOutput"].(map[string]any)
	if hso != nil {
		// claudecode-style block envelope
		if dec, ok := hso["permissionDecision"].(string); ok {
			require.Contains(t, []string{"deny"}, dec, "expected deny under default mask_on_error=deny; got %s", out)
			return
		}
	}
	if dec, ok := resp["decision"].(string); ok {
		require.Equal(t, "block", dec, "expected block decision; got %s", out)
		return
	}
	t.Fatalf("expected block/deny decision, got %s", out)
}

func TestRunMask_RedactAllOnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	cfgPath := filepath.Join(dir, store.ConfigName)
	cfg, err := store.LoadConfig(cfgPath)
	require.NoError(t, err)
	cfg.Hooks.MaskOnError = "redact-all"

	eng := bootstrapForTest(t, dir)
	eng.Cfg = cfg
	corruptMappings(t, dir)

	req := &harness.Request{
		EventName: "PostToolUse",
		ToolName:  "Read",
		SessionID: "s1",
		Direction: harness.DirMask,
		Targets:   []harness.Target{{Path: []string{"content"}, Content: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"}},
	}
	raw := json.RawMessage(`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"sk_live_4eC39HqLyjWDarjtT1zdp7dc"}}`)
	buf := &bytes.Buffer{}
	require.NoError(t, runMask(context.Background(), eng, claudecode.New(), req, raw, buf))

	out := buf.String()
	require.Contains(t, out, "[opensecretmask: redacted]", "expected redact-all placeholder; got %s", out)
	require.NotContains(t, out, "sk_live_4eC39HqLyjWDarjtT1zdp7dc", "real secret leaked under redact-all")
}

func TestRunUnmask_FailOpen_OnEngineError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)
	corruptMappings(t, dir)

	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Edit",
		"session_id":      "s1",
		"tool_input":      map[string]any{"old_string": "anything", "new_string": "x"},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PreToolUse")
	require.NoError(t, err)
	require.Equal(t, "{}", out, "unmask path must fail-open with empty object on engine error; got %s", out)
}

func TestRunObserve_SessionStart_PreloadEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	envDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(envDir, ".env"),
		[]byte("API_KEY=preload_value_xyz_secret_abc\n"), 0o600))

	payload := map[string]any{
		"hook_event_name": "SessionStart",
		"session_id":      "s1",
		"cwd":             envDir,
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "SessionStart")
	require.NoError(t, err)
	require.Equal(t, "{}", out)

	maps, err := store.LoadMappings(filepath.Join(dir, store.MappingsName))
	require.NoError(t, err)
	found := false
	for _, v := range maps.ByMask {
		if v == "preload_value_xyz_secret_abc" {
			found = true
		}
	}
	require.True(t, found, "SessionStart did not preload .env into mappings")
}

func TestRunObserve_UserPromptSubmit_NoSecretsNoNote(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	payload := map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"session_id":      "s1",
		"prompt":          "hello world without secrets",
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "UserPromptSubmit")
	require.NoError(t, err)
	require.Equal(t, "{}", out, "no secrets in prompt must emit empty object; got %s", out)
}

func TestEmitParseFailure_FailClosedShape(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitParseFailure(buf, nil))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &resp))
	require.Equal(t, "block", resp["decision"])
	require.Contains(t, resp["reason"], "opensecretmask")
	require.Contains(t, resp["reason"], "malformed")
}

func TestEmitPreconditionFailure_PostToolUseShape(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitPreconditionFailure("PostToolUse", buf, os.ErrNotExist))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &resp))
	require.Equal(t, "block", resp["decision"])
	require.Contains(t, resp["reason"], "opensecretmask")
}

func TestEmitPreconditionFailure_PreToolUseShape(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitPreconditionFailure("PreToolUse", buf, os.ErrNotExist))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &resp))
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	require.True(t, ok, "PreToolUse precondition failure must use hookSpecificOutput envelope; got %s", buf.String())
	require.Equal(t, "deny", hso["permissionDecision"])
	require.Contains(t, hso["permissionDecisionReason"], "opensecretmask")
}

func TestEmitPreconditionFailure_UnknownEventDefaultEmpty(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, emitPreconditionFailure("WeirdUnknownEvent", buf, os.ErrPermission))
	require.Equal(t, "{}", buf.String(), "unknown precondition event must emit empty object")
}

func TestHook_OSMRunningGuard(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)
	t.Setenv("OSM_RUNNING", "1")

	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"session_id":      "s1",
		"tool_response":   map[string]any{"content": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"},
	}
	raw, _ := json.Marshal(payload)
	out, err := runHook(t, string(raw), "hook", "PostToolUse")
	require.NoError(t, err)
	require.Equal(t, "{}", out, "re-entrancy guard must short-circuit to empty object; got %s", out)

	maps, err := store.LoadMappings(filepath.Join(dir, store.MappingsName))
	require.NoError(t, err)
	require.Empty(t, maps.ByMask, "engine must not run under OSM_RUNNING=1")
}
