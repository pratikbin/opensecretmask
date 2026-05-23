package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestResponder_UnmasksContentTextBlock(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("A", 90) + "-AA"
	masked, _, err := eng.MaskText(context.Background(), "sess", "proxy", secret)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	if masked == secret {
		t.Fatalf("not masked")
	}

	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(`{"content":[{"type":"text","text":"prefix ` + masked + ` suffix"}]}`)),
		Request: &http.Request{
			URL: &url.URL{Path: "/v1/messages"},
		},
	}
	rs := &Responder{Engine: eng}
	if err := rs.Modify(resp); err != nil {
		t.Fatalf("modify: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), secret) {
		t.Fatalf("unmask missing: %s", got)
	}
}

func TestResponder_LeavesUnknownPathsUntouched(t *testing.T) {
	eng := bootstrapTestEngine(t)
	body := `{"any":"thing"}`
	resp := &http.Response{
		Header:  http.Header{"Content-Type": []string{"application/json"}},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{URL: &url.URL{Path: "/v1/files"}},
	}
	rs := &Responder{Engine: eng}
	if err := rs.Modify(resp); err != nil {
		t.Fatalf("modify: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("body changed: %s", got)
	}
}

func TestResponder_MalformedJSONPassthrough(t *testing.T) {
	eng := bootstrapTestEngine(t)
	body := `not json`
	resp := &http.Response{
		Header:  http.Header{"Content-Type": []string{"application/json"}},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: &http.Request{URL: &url.URL{Path: "/v1/messages"}},
	}
	rs := &Responder{Engine: eng}
	if err := rs.Modify(resp); err != nil {
		t.Fatalf("modify: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("body changed: %s", got)
	}
}

func TestResponder_UnmasksToolUseInput(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("E", 90) + "-AA"
	masked, _, err := eng.MaskText(context.Background(), "sess", "proxy", secret)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}

	doc := map[string]any{
		"content": []any{
			map[string]any{"type": "tool_use", "input": map[string]any{"key": masked}},
		},
	}
	raw, _ := json.Marshal(doc)
	resp := &http.Response{
		Header:  http.Header{"Content-Type": []string{"application/json"}},
		Body:    io.NopCloser(strings.NewReader(string(raw))),
		Request: &http.Request{URL: &url.URL{Path: "/v1/messages"}},
	}
	rs := &Responder{Engine: eng}
	if err := rs.Modify(resp); err != nil {
		t.Fatalf("modify: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), secret) {
		t.Fatalf("tool_use input not unmasked: %s", got)
	}
}
