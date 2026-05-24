//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newIntegrationContainer builds the integration image (or reuses it via
// docker's layer cache) and starts a disposable container. `osm init
// --no-trust` runs inside the container so subsequent commands have a CA
// and key material. The container's lifetime is bound to the test via
// t.Cleanup.
//
// The image is built from tests/integration/Dockerfile with the repo root as
// build context, so the multi-stage builder compiles osm and mockupstream
// from current source — no manual cross-compile step needed.
func newIntegrationContainer(t *testing.T, ctx context.Context) testcontainers.Container {
	t.Helper()
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "../..",
			Dockerfile:    "tests/integration/Dockerfile",
			KeepImage:     true,
			PrintBuildLog: true,
		},
		Cmd:        []string{"sleep", "infinity"},
		WaitingFor: wait.ForExec([]string{"osm", "--help"}).WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start integration container")
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	r := runIn(t, ctx, c, "osm", "init", "--no-trust")
	require.Equal(t, 0, r.exitCode, "osm init failed: stdout=%s stderr=%s", r.stdout, r.stderr)
	return c
}

type runExecResult struct {
	exitCode int
	stdout   string
	stderr   string
}

// runIn runs cmd inside c. tcexec.Multiplexed() asks testcontainers to
// demultiplex the docker exec stream so the returned reader is plain text
// (combined stdout+stderr) instead of stdcopy-framed bytes — without it,
// the 8-byte frame headers bleed into parseable output and break naive
// line-based parsing.
func runIn(t *testing.T, ctx context.Context, c testcontainers.Container, cmd ...string) runExecResult {
	t.Helper()
	code, reader, err := c.Exec(ctx, cmd, tcexec.Multiplexed())
	require.NoError(t, err)
	buf := &bytes.Buffer{}
	_, _ = io.Copy(buf, reader)
	return runExecResult{exitCode: code, stdout: buf.String()}
}

// shellIn runs a bash -lc one-liner inside c.
func shellIn(t *testing.T, ctx context.Context, c testcontainers.Container, script string) runExecResult {
	t.Helper()
	return runIn(t, ctx, c, "bash", "-lc", script)
}

func TestIntegrationRun_EnvInjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := newIntegrationContainer(t, ctx)

	// --listen 127.0.0.1:1 forces the spawn-own-proxy path: port 1 is
	// reliably refused, so the daemon-probe miss is deterministic and the
	// test cannot silently flip into the reuse path.
	r := shellIn(t, ctx, c,
		`osm run --listen 127.0.0.1:1 -- sh -c 'env > /tmp/env.out' && cat /tmp/env.out`)
	require.Equal(t, 0, r.exitCode, "osm run failed: %s", r.stdout)

	envText := r.stdout
	wantKeys := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
		"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	}
	envMap := parseEnvDump(envText)
	for _, k := range wantKeys {
		require.NotEmptyf(t, envMap[k], "env var %s missing; dump:\n%s", k, envText)
	}

	caPath := envMap["NODE_EXTRA_CA_CERTS"]
	require.Equal(t, "/root/.opensecretmask/ca-cert.pem", caPath, "unexpected CA path")
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		require.Equalf(t, caPath, envMap[k], "%s should equal NODE_EXTRA_CA_CERTS", k)
	}

	statR := shellIn(t, ctx, c, "test -f "+caPath+" && echo OK")
	require.Equal(t, 0, statR.exitCode, "CA cert file not present at %s: %s", caPath, statR.stdout)
	require.Contains(t, statR.stdout, "OK")

	proxyURL := envMap["HTTPS_PROXY"]
	require.True(t, strings.HasPrefix(proxyURL, "http://127.0.0.1:"),
		"HTTPS_PROXY %q must be loopback http URL", proxyURL)
	port := strings.TrimPrefix(proxyURL, "http://127.0.0.1:")
	require.NotEmpty(t, port, "HTTPS_PROXY must include a port: %q", proxyURL)
	require.NotEqual(t, "0", port, "HTTPS_PROXY port must be non-zero: %q", proxyURL)
}

var maskLineRE = regexp.MustCompile(`mask sent to LLMs:\s*(\S+)`)

func TestIntegrationRun_MaskRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := newIntegrationContainer(t, ctx)

	const secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	addR := shellIn(t, ctx, c, fmt.Sprintf("osm add 'SECRET=%s'", secret))
	require.Equal(t, 0, addR.exitCode, "osm add failed: %s", addR.stdout)
	m := maskLineRE.FindStringSubmatch(addR.stdout)
	require.NotNilf(t, m, "could not parse mask from osm add stdout:\n%s", addR.stdout)
	mask := m[1]
	require.NotEqual(t, secret, mask, "mask must differ from real secret")

	mockR := shellIn(t, ctx, c,
		`nohup mockupstream --ca-dir /root/.opensecretmask >/tmp/mock.out 2>/tmp/mock.err & sleep 1; cat /tmp/mock.out`)
	require.Equal(t, 0, mockR.exitCode, "mockupstream launch failed: stdout=%s", mockR.stdout)
	mockListenRE := regexp.MustCompile(`listen=([0-9.]+:[0-9]+)`)
	mm := mockListenRE.FindStringSubmatch(mockR.stdout)
	require.NotNilf(t, mm, "mockupstream did not log listen address:\n%s", mockR.stdout)
	mockHost := mm[1]

	// curl gets no --cacert / -x — env injection is the contract under test.
	body := fmt.Sprintf(`{"key":%q}`, secret)
	curlScript := fmt.Sprintf(
		`osm run --listen 127.0.0.1:1 --provider 127.0.0.1=anthropic -- `+
			`curl -s --max-time 10 https://%s/v1/messages -d %q`,
		mockHost, body)
	curlR := shellIn(t, ctx, c, curlScript)
	require.Equal(t, 0, curlR.exitCode, "osm run + curl failed: stdout=%s stderr=%s", curlR.stdout, curlR.stderr)

	lastR := shellIn(t, ctx, c, fmt.Sprintf("curl -s --max-time 5 -k https://%s/__last_body", mockHost))
	require.Equal(t, 0, lastR.exitCode, "fetch /__last_body failed: %s", lastR.stdout)
	upstreamBody := lastR.stdout
	require.NotContainsf(t, upstreamBody, secret,
		"real secret leaked to upstream:\n%s", upstreamBody)
	require.Containsf(t, upstreamBody, mask,
		"upstream did not receive mask %q:\n%s", mask, upstreamBody)

	require.Containsf(t, curlR.stdout, secret,
		"unmask round-trip failed: client never saw the real secret. body=%s", curlR.stdout)
	require.NotContainsf(t, curlR.stdout, mask,
		"mask leaked back to client (unmask did not run): body=%s", curlR.stdout)
}

// parseEnvDump turns the output of `env` into a map. Values may contain `=`;
// only the first `=` per line is treated as the separator.
func parseEnvDump(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		m[line[:i]] = line[i+1:]
	}
	return m
}
