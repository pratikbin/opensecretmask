package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestSSE_SingleTextDeltaUnmasked(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("A", 90) + "-AA"
	masked, _, err := eng.MaskText(context.Background(), "s", "proxy", secret)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}

	// Suffix big enough to push the secret past the sseTailHold window so it flushes.
	suffix := strings.Repeat("y", sseTailHold+8)
	payload := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": "head " + masked + " " + suffix},
	}
	pb, _ := json.Marshal(payload)
	stream := []byte("event: content_block_delta\ndata: " + string(pb) + "\n\n")

	r := wrapSSEUnmask(io.NopCloser(bytes.NewReader(stream)), eng)
	got, _ := io.ReadAll(r)
	if !bytes.Contains(got, []byte(secret)) {
		t.Fatalf("secret not unmasked: %s", got)
	}
}

func TestSSE_NonStringPassthrough(t *testing.T) {
	eng := bootstrapTestEngine(t)
	stream := []byte("event: ping\ndata: {\"type\":\"ping\"}\n\n")
	r := wrapSSEUnmask(io.NopCloser(bytes.NewReader(stream)), eng)
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, stream) {
		t.Fatalf("ping mutated: %s", got)
	}
}

func TestSSE_ContentBlockStartTextUnmasked(t *testing.T) {
	eng := bootstrapTestEngine(t)
	secret := "sk-ant-api03-" + strings.Repeat("Q", 90) + "-AA"
	masked, _, err := eng.MaskText(context.Background(), "s", "proxy", secret)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	payload := map[string]any{
		"type":          "content_block_start",
		"index":         0,
		"content_block": map[string]any{"type": "text", "text": "hello " + masked + " world"},
	}
	pb, _ := json.Marshal(payload)
	stream := []byte("event: content_block_start\ndata: " + string(pb) + "\n\n")
	r := wrapSSEUnmask(io.NopCloser(bytes.NewReader(stream)), eng)
	got, _ := io.ReadAll(r)
	if !bytes.Contains(got, []byte(secret)) {
		t.Fatalf("secret not unmasked in content_block_start: %s", got)
	}
}

func TestSSE_MultipleEventsBoundary(t *testing.T) {
	eng := bootstrapTestEngine(t)
	stream := []byte(
		"event: ping\ndata: {\"type\":\"ping\"}\n\n" +
			"event: ping\ndata: {\"type\":\"ping\"}\n\n",
	)
	r := wrapSSEUnmask(io.NopCloser(bytes.NewReader(stream)), eng)
	got, _ := io.ReadAll(r)
	if bytes.Count(got, []byte("\n\n")) != 2 {
		t.Fatalf("event count wrong: %s", got)
	}
}
