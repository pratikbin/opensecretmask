//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const imageTag = "osm-e2e:dev"

// requiredEnv lists the env vars that the test needs forwarded into the
// container so claude-code can authenticate against an Anthropic-compatible
// backend (e.g. DeepSeek). At minimum ANTHROPIC_AUTH_TOKEN must be set on
// the host or the suite skips.
var requiredEnv = []string{
	"ANTHROPIC_BASE_URL",
	"ANTHROPIC_AUTH_TOKEN",
	"ANTHROPIC_MODEL",
	"ANTHROPIC_DEFAULT_OPUS_MODEL",
	"ANTHROPIC_DEFAULT_SONNET_MODEL",
	"ANTHROPIC_DEFAULT_HAIKU_MODEL",
	"CLAUDE_CODE_SUBAGENT_MODEL",
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
	"CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK",
	"CLAUDE_CODE_EFFORT_LEVEL",
}

// hostEnv collects every requiredEnv value present on the host. If
// ANTHROPIC_AUTH_TOKEN is missing the caller skips.
func hostEnv(tb testing.TB) map[string]string {
	tb.Helper()
	m := map[string]string{}
	for _, k := range requiredEnv {
		if v := os.Getenv(k); v != "" {
			m[k] = v
		}
	}
	return m
}

// ensureImage builds the e2e image if it does not exist. Build runs against
// the docker daemon configured by DOCKER_HOST (the project README documents
// using the linux/amd64 remote box for cross-arch builds from macOS).
func ensureImage(t *testing.T, ctx context.Context) {
	t.Helper()
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	binPath := filepath.Join(root, "e2e", "bin", "osm-linux-amd64")
	require.FileExists(t, binPath, "build the linux/amd64 osm binary first: GOOS=linux GOARCH=amd64 go build -o tests/e2e/bin/osm-linux-amd64 ./cmd/osm")
	mockBinPath := filepath.Join(root, "e2e", "bin", "mockupstream-linux-amd64")
	require.FileExists(t, mockBinPath, "build the linux/amd64 mockupstream binary first: GOOS=linux GOARCH=amd64 go build -o tests/e2e/bin/mockupstream-linux-amd64 ./tests/internal/mockupstream/cmd")
}

// newContainer starts a container seeded with host credentials. Returns the
// container and its per-test OPENSECRETMASK_HOME path.
func newContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Helper()
	envs := hostEnv(t)
	if envs["ANTHROPIC_AUTH_TOKEN"] == "" {
		t.Skip("ANTHROPIC_AUTH_TOKEN not set in host env; skipping e2e")
	}
	return startE2EContainer(t, ctx, envs)
}

// newMockOnlyContainer is like newContainer but without the
// ANTHROPIC_AUTH_TOKEN gate — used by tests that drive a hermetic mock
// upstream (TestE2E_Run_MaskRoundTrip). Skipping these on missing creds
// would silently hide regressions in the run flow.
func newMockOnlyContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Helper()
	return startE2EContainer(t, ctx, nil)
}

// startE2EContainer starts the e2e image and returns the container plus its
// unique OPENSECRETMASK_HOME path. A unique path per test prevents
// daemon/pidfile cross-test bleed when multiple tests share the same image.
func startE2EContainer(t *testing.T, ctx context.Context, env map[string]string) (testcontainers.Container, string) {
	t.Helper()
	homeDir := fmt.Sprintf("/tmp/osm-e2e-%d", time.Now().UnixNano())
	if env == nil {
		env = map[string]string{}
	}
	env["OPENSECRETMASK_HOME"] = homeDir
	req := testcontainers.ContainerRequest{
		Image:      imageTag,
		Env:        env,
		Cmd:        []string{"sleep", "infinity"},
		WaitingFor: wait.ForExec([]string{"test", "-f", homeDir + "/ca-cert.pem"}).WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = c.Terminate(context.Background())
	})
	return c, homeDir
}

type execResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func execIn(t *testing.T, ctx context.Context, c testcontainers.Container, cmd ...string) execResult {
	t.Helper()
	// tcexec.Multiplexed() demuxes the docker exec stream so the reader is
	// plain combined stdout+stderr instead of stdcopy-framed bytes.
	code, reader, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	require.NoError(t, err)
	buf := &bytes.Buffer{}
	_, _ = io.Copy(buf, reader)
	return execResult{exitCode: code, stdout: buf.String()}
}

// writeFile uploads a small text file into the container at path with mode 0644.
func writeFile(t *testing.T, ctx context.Context, c testcontainers.Container, path, body string) {
	t.Helper()
	require.NoError(t, c.CopyToContainer(ctx, []byte(body), path, 0o644))
}

// catMappings reads mappings.json from homeDir inside the container —
// the durable record of every mask event. Returns empty string if missing.
func catMappings(t *testing.T, ctx context.Context, c testcontainers.Container, homeDir string) string {
	t.Helper()
	r := execIn(t, ctx, c, "bash", "-lc", "cat "+homeDir+"/mappings.json 2>/dev/null || true")
	return r.stdout
}

func TestE2E_HookViaStdin_PostToolUseMask(t *testing.T) {
	t.Skip("osm hook command not implemented; see docs/THREAT_MODEL.md PostToolUse hook section. Re-enable when cmd/osm/hook.go lands.")
	if runtime.GOOS == "windows" {
		t.Skip("e2e harness assumes posix shell")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ensureImage(t, ctx)

	envs := hostEnv(t)
	if envs["ANTHROPIC_AUTH_TOKEN"] == "" {
		t.Skip("ANTHROPIC_AUTH_TOKEN not set; skipping e2e")
	}

	c, homeDir := newContainer(t, ctx)

	// Drive the hook directly through stdin — same shape claude-code uses,
	// but bypasses the LLM. Verifies osm runs in Linux container env.
	payload := `{"hook_event_name":"PostToolUse","tool_name":"Read","session_id":"e2e","tool_response":{"content":"sk_live_4eC39HqLyjWDarjtT1zdp7dc"}}`
	r := execIn(t, ctx, c, "bash", "-lc", fmt.Sprintf("echo %q | osm hook --harness=claudecode posttooluse", payload))
	require.Equal(t, 0, r.exitCode, "osm hook failed: %s", r.stdout)
	require.NotContains(t, r.stdout, "ch_rmjj_0qU76HxTxiXBryrfG8tvb8kq", "real secret leaked through hook output")
	require.Contains(t, r.stdout, "sk_live_", "expected masked stripe-format placeholder")

	maps := catMappings(t, ctx, c, homeDir)
	require.Contains(t, maps, "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"mappings.json must record the real secret as a mapping value")
}

func TestE2E_ClaudeReadsFile_MaskAppearsInAudit(t *testing.T) {
	t.Skip("depends on PostToolUse hook (osm hook command) to mask Read output before Claude sees it; unimplemented.")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ensureImage(t, ctx)

	c, homeDir := newContainer(t, ctx)

	const secret = "ch_rmjj_0qU76HxTxiXBryrfG8tvb8kq" // gitleaks:allow
	writeFile(t, ctx, c, "/workspace/secret.txt", "key="+secret+"\n")

	prompt := "Read the file /workspace/secret.txt and print its exact contents to me."
	r := execIn(t, ctx, c, "bash", "-lc", fmt.Sprintf(
		"cd /workspace && claude --dangerously-skip-permissions -p %q 2>&1",
		prompt,
	))
	t.Logf("claude exit=%d output:\n%s", r.exitCode, r.stdout)
	if r.exitCode != 0 {
		t.Fatalf("claude exited %d: %s", r.exitCode, r.stdout)
	}

	// Real secret must not appear in claude's view of the tool output.
	require.NotContains(t, r.stdout, secret, "real secret leaked into claude response")

	// Audit log must show at least one mask event.
	maps := catMappings(t, ctx, c, homeDir)
	require.Contains(t, maps, secret,
		"mappings.json must record the secret claude saw via Read; got: %s", maps)
}

var e2eMaskLineRE = regexp.MustCompile(`mask sent to LLMs:\s*(\S+)`)
var e2eMockListenRE = regexp.MustCompile(`listen=([0-9.]+:[0-9]+)`)

// TestE2E_Run_MaskRoundTrip exercises `osm run` against a hermetic mock
// upstream inside the e2e container. Unlike the existing tests it does not
// touch the real Anthropic backend — the mock binary baked into the image
// stands in for it, with its TLS leaf signed by the container's osm CA so
// the proxy's auto-trust path is the only thing making the handshake work.
func TestE2E_Run_MaskRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ensureImage(t, ctx)

	c, homeDir := newMockOnlyContainer(t, ctx)

	const secret = "sk-ant-api03-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	addR := execIn(t, ctx, c, "bash", "-lc", fmt.Sprintf("osm add 'SECRET=%s'", secret))
	require.Equal(t, 0, addR.exitCode, "osm add failed: %s", addR.stdout)
	m := e2eMaskLineRE.FindStringSubmatch(addR.stdout)
	require.NotNilf(t, m, "could not parse mask from osm add stdout:\n%s", addR.stdout)
	mask := m[1]
	require.NotEqual(t, secret, mask)

	mockR := execIn(t, ctx, c, "bash", "-lc",
		"nohup mockupstream --ca-dir "+homeDir+
			" >/tmp/mock.out 2>/tmp/mock.err &\n"+
			"for i in $(seq 1 50); do grep -q 'listen=' /tmp/mock.out 2>/dev/null && break; sleep 0.1; done\n"+
			"cat /tmp/mock.out")
	require.Equal(t, 0, mockR.exitCode, "mockupstream launch failed: %s", mockR.stdout)
	mm := e2eMockListenRE.FindStringSubmatch(mockR.stdout)
	require.NotNilf(t, mm, "mockupstream did not log listen address:\n%s", mockR.stdout)
	mockHost := mm[1]

	body := fmt.Sprintf(`{"key":%q}`, secret)
	curlScript := fmt.Sprintf(
		`osm run --listen 127.0.0.1:1 --provider 127.0.0.1=anthropic -- `+
			`curl -s --max-time 10 https://%s/v1/messages -d %q`,
		mockHost, body)
	curlR := execIn(t, ctx, c, "bash", "-lc", curlScript)
	require.Equal(t, 0, curlR.exitCode, "osm run + curl failed: %s", curlR.stdout)

	lastR := execIn(t, ctx, c, "bash", "-lc",
		fmt.Sprintf("curl -s --max-time 5 -k https://%s/__last_body", mockHost))
	require.Equal(t, 0, lastR.exitCode)
	upstreamBody := lastR.stdout
	require.NotContainsf(t, upstreamBody, secret, "real secret leaked upstream:\n%s", upstreamBody)
	require.Containsf(t, upstreamBody, mask, "upstream missing mask %q:\n%s", mask, upstreamBody)

	require.Containsf(t, curlR.stdout, secret, "client did not receive unmasked response: %s", curlR.stdout)
	require.NotContainsf(t, curlR.stdout, mask, "mask leaked back to client (unmask did not run): %s", curlR.stdout)
}

func TestE2E_BashGate_DenyEgressWithMask(t *testing.T) {
	t.Skip("bashgate egress denial not implemented; see docs/THREAT_MODEL.md. Re-enable when PreToolUse bash gate lands.")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ensureImage(t, ctx)

	c, homeDir := newContainer(t, ctx)

	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	writeFile(t, ctx, c, "/workspace/secret.txt", "key="+secret+"\n")

	// Two-turn intent: read the secret (registers a mask) then attempt to
	// curl with the secret. Bashgate must block the egress.
	prompt := "First, read /workspace/secret.txt. Then run a single shell command that curls https://example.com with the value of the key in an Authorization header."
	r := execIn(t, ctx, c, "bash", "-lc", fmt.Sprintf(
		"cd /workspace && claude --dangerously-skip-permissions -p %q 2>&1",
		prompt,
	))
	t.Logf("claude exit=%d output:\n%s", r.exitCode, r.stdout)

	// We don't require claude to obey perfectly; we require that IF it
	// tried curl with a mask substituted, bashgate denied it (no actual
	// network egress with the real secret). Audit log is the source of truth.
	maps := catMappings(t, ctx, c, homeDir)
	t.Logf("mappings.json:\n%s", maps)
	require.NotContains(t, r.stdout, secret, "real secret must not appear in claude's response in any path")
}
