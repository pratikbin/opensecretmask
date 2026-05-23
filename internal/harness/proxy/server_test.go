package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServer_RoundTrip_NonStreaming(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("C", 90) + "-AA"
	masked, _, err := eng.MaskText(context.Background(), "s", "proxy", secret)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}

	var receivedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		echo := map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": "echo " + masked + " end"},
			},
		}
		_ = json.NewEncoder(w).Encode(echo)
	}))
	defer upstream.Close()

	srv, err := New(eng, Options{Bind: "127.0.0.1:0", Upstream: upstream.URL})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	body := `{"messages":[{"role":"user","content":"hello ` + secret + ` tail"}]}`
	req, _ := http.NewRequest("POST", "http://"+srv.Addr()+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if bytes.Contains(receivedBody, []byte(secret)) {
		t.Fatalf("real secret leaked upstream: %s", receivedBody)
	}
	if !bytes.Contains(got, []byte(secret)) {
		t.Fatalf("client did not receive unmasked secret: %s", got)
	}
}

func TestServer_PassesUpstreamCredentialsThrough(t *testing.T) {
	eng := bootstrapTestEngine(t)
	var seenAuth, seenAPIKey, seenVersion string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenAPIKey = r.Header.Get("x-api-key")
		seenVersion = r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	srv, err := New(eng, Options{Bind: "127.0.0.1:0", Upstream: upstream.URL})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	req, _ := http.NewRequest("GET", "http://"+srv.Addr()+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("x-api-key", "sk-ant-real-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if seenAuth != "Bearer agent-token" {
		t.Fatalf("Authorization not forwarded: got %q", seenAuth)
	}
	if seenAPIKey != "sk-ant-real-key" {
		t.Fatalf("x-api-key not forwarded: got %q", seenAPIKey)
	}
	if seenVersion != "2023-06-01" {
		t.Fatalf("anthropic-version not forwarded: got %q", seenVersion)
	}
}

