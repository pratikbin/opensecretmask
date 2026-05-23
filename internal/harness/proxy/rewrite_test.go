package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDirector_MasksMessageStringContent(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("A", 90) + "-AA"
	if _, _, err := eng.MaskText(context.Background(), "sess", "proxy", secret); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"model":"claude-x","messages":[{"role":"user","content":"my key ` + secret + ` tail"}]}`
	up, _ := url.Parse("https://api.anthropic.com")
	rw := &Rewriter{Engine: eng, Upstream: up, SessionID: "sess"}

	req, _ := http.NewRequest("POST", "http://x/v1/messages", strings.NewReader(body))
	rw.Director(req)
	out, _ := io.ReadAll(req.Body)
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("real secret leaked: %s", out)
	}
	if req.URL.Host != "api.anthropic.com" {
		t.Fatalf("host: %q", req.URL.Host)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("body not json: %v", err)
	}
}

func TestDirector_MasksContentBlocks(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("B", 90) + "-AA"
	if _, _, err := eng.MaskText(context.Background(), "sess", "proxy", secret); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"hello ` + secret + `"}]}]}`
	up, _ := url.Parse("https://api.anthropic.com")
	rw := &Rewriter{Engine: eng, Upstream: up, SessionID: "sess"}

	req, _ := http.NewRequest("POST", "http://x/v1/messages", strings.NewReader(body))
	rw.Director(req)
	out, _ := io.ReadAll(req.Body)
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("secret leaked: %s", out)
	}
}

func TestDirector_LeavesUnknownPathsUntouched(t *testing.T) {
	eng := bootstrapTestEngine(t)
	body := `{"anything":"sk-ant-api03-AAAA"}`
	up, _ := url.Parse("https://api.anthropic.com")
	rw := &Rewriter{Engine: eng, Upstream: up, SessionID: "sess"}

	req, _ := http.NewRequest("POST", "http://x/v1/files", strings.NewReader(body))
	rw.Director(req)
	out, _ := io.ReadAll(req.Body)
	if string(out) != body {
		t.Fatalf("unknown path body changed: %s", out)
	}
	if req.URL.Host != "api.anthropic.com" {
		t.Fatalf("host: %q", req.URL.Host)
	}
}

func TestDirector_RewritesURLOnly_GET(t *testing.T) {
	eng := bootstrapTestEngine(t)
	up, _ := url.Parse("https://api.anthropic.com")
	rw := &Rewriter{Engine: eng, Upstream: up, SessionID: "sess"}

	req, _ := http.NewRequest("GET", "http://x/v1/models", nil)
	rw.Director(req)
	if req.URL.Host != "api.anthropic.com" {
		t.Fatalf("host: %q", req.URL.Host)
	}
	if req.URL.Scheme != "https" {
		t.Fatalf("scheme: %q", req.URL.Scheme)
	}
}
