package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

var osmBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "osmbin")
	if err != nil {
		panic(err)
	}
	osmBin = filepath.Join(tmp, "osm")
	build := exec.Command("go", "build", "-o", osmBin, "../../cmd/osm")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func initHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	_, err := keymgr.Generate(dir)
	require.NoError(t, err)
	cfg := store.DefaultConfig()
	require.NoError(t, store.SaveSecrets(filepath.Join(dir, store.SecretsName), &store.Secrets{Version: 1}))
	require.NoError(t, store.SaveMappings(filepath.Join(dir, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}))
	require.NoError(t, store.SaveAllowlist(filepath.Join(dir, store.AllowlistName), &store.Allowlist{Values: cfg.Detector.Allowlist.Values}))
	return dir
}

func runHook(t *testing.T, home, event string, stdin string) (string, int) {
	t.Helper()
	cmd := exec.Command(osmBin, "hook", "--harness=claudecode", event)
	cmd.Env = append(os.Environ(), "OPENSECRETMASK_HOME="+home)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	exit := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	}
	return out.String(), exit
}

func TestIntegration_PostToolUseRead_NoSecret(t *testing.T) {
	home := initHome(t)
	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"hello world"}}`
	out, exit := runHook(t, home, "PostToolUse", stdin)
	require.Equal(t, 0, exit, out)
	require.Equal(t, "{}", strings.TrimSpace(out))
}

func TestIntegration_PostToolUseRead_StripeKey(t *testing.T) {
	home := initHome(t)
	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"sk_live_4eC39HqLyjWDarjtT1zdp7dc"}}`
	out, exit := runHook(t, home, "PostToolUse", stdin)
	require.Equal(t, 0, exit, out)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	hso, _ := resp["hookSpecificOutput"].(map[string]any)
	utc, _ := hso["updatedToolOutput"].(map[string]any)
	content, _ := utc["content"].(string)
	require.NotContains(t, content, "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
	require.Contains(t, content, "sk_live_")
}

func TestIntegration_PreToolUseEdit_PassthroughWithoutMask(t *testing.T) {
	home := initHome(t)
	stdin := `{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"old_string":"plain","new_string":"text"}}`
	out, exit := runHook(t, home, "PreToolUse", stdin)
	require.Equal(t, 0, exit, out)
	require.Equal(t, "{}", strings.TrimSpace(out))
}

func TestIntegration_UserPromptSubmit_StripeKeyWarn(t *testing.T) {
	home := initHome(t)
	stdin := `{"hook_event_name":"UserPromptSubmit","prompt":"please use sk_live_4eC39HqLyjWDarjtT1zdp7dc"}`
	out, exit := runHook(t, home, "UserPromptSubmit", stdin)
	require.Equal(t, 0, exit, out)
	require.Contains(t, out, "additionalContext")
}

func TestIntegration_SessionStart_Empty(t *testing.T) {
	home := initHome(t)
	stdin := `{"hook_event_name":"SessionStart","cwd":"` + t.TempDir() + `"}`
	out, exit := runHook(t, home, "SessionStart", stdin)
	require.Equal(t, 0, exit, out)
	require.Equal(t, "{}", strings.TrimSpace(out))
}

func TestIntegration_PostToolUseUninit_DenyBlock(t *testing.T) {
	dir := t.TempDir()
	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"hello"}}`
	cmd := exec.Command(osmBin, "hook", "--harness=claudecode", "PostToolUse")
	cmd.Env = append(os.Environ(), "OPENSECRETMASK_HOME="+dir)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	require.NoError(t, cmd.Run())
	require.Contains(t, out.String(), "block")
}
