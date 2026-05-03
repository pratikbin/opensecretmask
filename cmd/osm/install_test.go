package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstall_FreshProject(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	root := newRootCmd()
	root.SetArgs([]string{"install", "claude-code", "--project"})
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	var s map[string]any
	require.NoError(t, json.Unmarshal(data, &s))
	hooks := s["hooks"].(map[string]any)
	require.Len(t, hooks, 4) // PostToolUse, PreToolUse, UserPromptSubmit, SessionStart
}

func TestInstall_PreservesUserHook(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settingsPath), 0o755))
	pre := `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo user","description":"user-hook"}]}]}}`
	require.NoError(t, os.WriteFile(settingsPath, []byte(pre), 0o644))

	root := newRootCmd()
	root.SetArgs([]string{"install", "claude-code", "--project"})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "user-hook")
	require.Contains(t, string(data), "opensecretmask")
}

func TestInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	for i := 0; i < 2; i++ {
		root := newRootCmd()
		root.SetArgs([]string{"install", "claude-code", "--project"})
		require.NoError(t, root.Execute())
	}
	data, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	var s map[string]any
	require.NoError(t, json.Unmarshal(data, &s))
	hooks := s["hooks"].(map[string]any)
	pte := hooks["PostToolUse"].([]any)
	require.Len(t, pte, 1) // not duplicated
}

func TestInstall_DryRun(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	root := newRootCmd()
	root.SetArgs([]string{"install", "claude-code", "--project", "--dry-run"})
	out := &bytes.Buffer{}
	root.SetOut(out)
	require.NoError(t, root.Execute())

	_, err := os.Stat(filepath.Join(dir, ".claude", "settings.json"))
	require.True(t, os.IsNotExist(err))
	require.Contains(t, out.String(), "opensecretmask")
}

func TestResolveSettingsPath_MutuallyExclusive(t *testing.T) {
	_, err := resolveSettingsPath(installOpts{global: true, project: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestResolveSettingsPath_GlobalFlag(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home-resolveSettings")
	path, err := resolveSettingsPath(installOpts{global: true})
	require.NoError(t, err)
	require.Equal(t, filepath.Join("/tmp/fake-home-resolveSettings", ".claude", "settings.json"), path)
}

func TestResolveSettingsPath_DefaultProject(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	path, err := resolveSettingsPath(installOpts{})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, ".claude", "settings.json"), path)
}

func TestLoadSettings_MissingFile(t *testing.T) {
	dir := t.TempDir()
	out, err := loadSettings(filepath.Join(dir, "nonexistent.json"))
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Empty(t, out)
}

func TestLoadSettings_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(p, []byte{}, 0o644))
	out, err := loadSettings(p)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Empty(t, out)
}

func TestLoadSettings_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(p, []byte("{not json"), 0o644))
	_, err := loadSettings(p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse")
	require.Contains(t, err.Error(), p)
}

func TestLoadSettings_NullJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "null.json")
	require.NoError(t, os.WriteFile(p, []byte("null"), 0o644))
	out, err := loadSettings(p)
	require.NoError(t, err)
	require.NotNil(t, out, "null JSON must be normalized to empty map, not nil")
	require.Empty(t, out)
}

func TestUninstall_LeavesUserHookIntact(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	require.NoError(t, os.Chdir(dir))

	rootI := newRootCmd()
	rootI.SetArgs([]string{"install", "claude-code", "--project"})
	require.NoError(t, rootI.Execute())

	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	data, _ := os.ReadFile(settingsPath)
	var s map[string]any
	require.NoError(t, json.Unmarshal(data, &s))
	hooks := s["hooks"].(map[string]any)
	pte := hooks["PostToolUse"].([]any)
	pte = append(pte, map[string]any{
		"matcher": "Bash",
		"hooks": []any{map[string]any{
			"type": "command", "command": "echo user", "description": "user-hook",
		}},
	})
	hooks["PostToolUse"] = pte
	out, _ := json.MarshalIndent(s, "", "  ")
	require.NoError(t, os.WriteFile(settingsPath, out, 0o644))

	rootU := newRootCmd()
	rootU.SetArgs([]string{"uninstall", "claude-code", "--project"})
	require.NoError(t, rootU.Execute())

	data, _ = os.ReadFile(settingsPath)
	require.Contains(t, string(data), "user-hook")
	require.NotContains(t, string(data), "opensecretmask")
}
