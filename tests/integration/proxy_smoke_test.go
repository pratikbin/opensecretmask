//go:build integration

package integration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegration_ProxySmoke(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	bin := filepath.Join(dir, "osm")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/osm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	if out, err := exec.Command(bin, "init").CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	secret := "sk-ant-api03-" + strings.Repeat("D", 90) + "-AA"
	if out, err := exec.Command(bin, "add", "API_KEY="+secret).CombinedOutput(); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}

	var seenBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Echo a content block containing the masked secret so the proxy
		// can verify response unmask too. We need to find the masked form by
		// reading the secrets file via subprocess; for this smoke test we
		// just echo back what we received in JSON form.
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"upstream ack"}]}`))
	}))
	defer upstream.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pcmd := exec.CommandContext(ctx, bin, "proxy",
		"--bind", "127.0.0.1:0",
		"--upstream", upstream.URL,
	)
	pcmd.Env = append(os.Environ(), "OPENSECRETMASK_HOME="+dir)
	stderr, err := pcmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr: %v", err)
	}
	if err := pcmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = pcmd.Process.Kill()
		_, _ = pcmd.Process.Wait()
	}()

	var addr string
	br := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := stderr.Read(br)
		if n > 0 {
			line := string(br[:n])
			if i := strings.Index(line, "listening on "); i >= 0 {
				rest := line[i+len("listening on "):]
				if j := strings.Index(rest, " "); j > 0 {
					addr = rest[:j]
					break
				}
			}
		}
	}
	if addr == "" {
		t.Fatalf("proxy never logged listen address")
	}

	body := `{"messages":[{"role":"user","content":"hello ` + secret + ` tail"}]}`
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	defer resp.Body.Close()

	if bytes.Contains(seenBody, []byte(secret)) {
		t.Fatalf("real secret leaked upstream: %s", seenBody)
	}
	if !bytes.Contains(seenBody, []byte("messages")) {
		t.Fatalf("upstream did not receive masked body: %s", seenBody)
	}
}
