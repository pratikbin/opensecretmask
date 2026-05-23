package mask

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func newMasker(t *testing.T) (*Masker, *store.Store) {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.InitCrypto(t.Context(),"test-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		t.Fatalf("detect.New: %v", err)
	}
	return NewMasker(st, det), st
}

func TestMaskUnmaskRoundTrip(t *testing.T) {
	m, _ := newMasker(t)
	secret := "sk-ant-api03-abcdef1234567890ABCDEFGH"
	orig := []byte(`{"content":"my key ` + secret + ` stays secret"}`)

	masked, used, err := m.MaskBody(t.Context(),orig)
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if bytes.Contains(masked, []byte(secret)) {
		t.Fatal("masked body still contains the real secret")
	}
	if len(used) != 1 {
		t.Fatalf("expected 1 used secret, got %d", len(used))
	}
	if used[0].Mask == secret || len(used[0].Mask) != len(secret) {
		t.Fatalf("mask not format-preserving: %q", used[0].Mask)
	}
	if used[0].Mask[:7] != "sk-ant-" {
		t.Fatalf("mask lost the recognizable prefix: %q", used[0].Mask)
	}

	back := m.UnmaskBody(masked, used)
	if !bytes.Equal(back, orig) {
		t.Fatalf("round-trip mismatch:\n got %s\nwant %s", back, orig)
	}
}

func TestMaskStableAcrossCalls(t *testing.T) {
	m, _ := newMasker(t)
	body := []byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")

	first, used1, err := m.MaskBody(t.Context(),body)
	if err != nil {
		t.Fatalf("MaskBody 1: %v", err)
	}
	second, used2, err := m.MaskBody(t.Context(),body)
	if err != nil {
		t.Fatalf("MaskBody 2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("same secret produced different masks: %q vs %q", first, second)
	}
	if used1[0].Mask != used2[0].Mask {
		t.Fatal("mask not stable across calls")
	}
}

func TestMaskRegisteredSecret(t *testing.T) {
	m, st := newMasker(t)
	const orig = "hunter2-plain-pw"
	const mask = "XXXXXXX-xxxxx-xx"
	if _, err := st.PutSecret(t.Context(),store.Secret{
		Name: "DB_PASSWORD", Source: "registered",
		Original: orig, Mask: mask, Shape: "aaaaaa9-aaaaa-aa",
	}); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	masked, used, err := m.MaskBody(t.Context(),[]byte("connect with " + orig + " now"))
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if bytes.Contains(masked, []byte(orig)) {
		t.Fatal("registered secret was not masked")
	}
	if len(used) != 1 || used[0].Source != "registered" {
		t.Fatalf("expected one registered secret used, got %+v", used)
	}
}

func TestMaskNothingToMask(t *testing.T) {
	m, _ := newMasker(t)
	body := []byte(`{"content":"just an ordinary sentence with no secrets"}`)
	masked, used, err := m.MaskBody(t.Context(),body)
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if !bytes.Equal(masked, body) || used != nil {
		t.Fatalf("clean body should pass through unchanged, got masked=%s used=%+v", masked, used)
	}
}

func TestMaskBodyJSONPreservesEscapes(t *testing.T) {
	m, _ := newMasker(t)
	const orig = "hunter2-very-secret-value"
	sec, err := m.Register(t.Context(),"DB_PASSWORD", orig)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A JSON string value carrying escape sequences around the secret. In the
	// raw request bytes these are \n \t \" \\ — byte-level masking corrupts
	// them; decoded masking must leave them intact.
	text := "line1\nline2\ttab \"quoted\" back\\slash " + orig + " end"
	body, err := json.Marshal(map[string]any{"content": text})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	masked, used, err := m.MaskBody(t.Context(),body)
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if !json.Valid(masked) {
		t.Fatalf("masked body is not valid JSON: %s", masked)
	}
	if bytes.Contains(masked, []byte(orig)) {
		t.Fatal("masked body still contains the real secret")
	}
	if len(used) != 1 || used[0].ID != sec.ID {
		t.Fatalf("expected the registered secret used, got %+v", used)
	}

	var got map[string]any
	if err := json.Unmarshal(masked, &got); err != nil {
		t.Fatalf("unmarshal masked: %v", err)
	}
	want := "line1\nline2\ttab \"quoted\" back\\slash " + sec.Mask + " end"
	if got["content"] != want {
		t.Errorf("decoded content = %q, want %q", got["content"], want)
	}
}

func TestMaskBodyJSONNested(t *testing.T) {
	m, _ := newMasker(t)
	secret := "sk-ant-api03-abcdef1234567890ABCDEFGH"
	body, err := json.Marshal(map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "key is " + secret},
			map[string]any{"role": "assistant", "content": "ok"},
		},
		"max_tokens": 64000,
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	masked, used, err := m.MaskBody(t.Context(),body)
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if !json.Valid(masked) {
		t.Fatalf("masked body is not valid JSON: %s", masked)
	}
	if bytes.Contains(masked, []byte(secret)) {
		t.Fatal("nested secret was not masked")
	}
	if len(used) != 1 {
		t.Fatalf("expected 1 used secret, got %d", len(used))
	}
	if !bytes.Contains(masked, []byte(`"max_tokens":64000`)) {
		t.Errorf("max_tokens did not round-trip exactly: %s", masked)
	}
}

func TestMaskerRegister(t *testing.T) {
	m, st := newMasker(t)

	sec, err := m.Register(t.Context(),"DB_PASSWORD", "hunter2-very-secret-value")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if sec.Source != "registered" {
		t.Fatalf("source = %q, want registered", sec.Source)
	}
	if sec.Mask == sec.Original || len(sec.Mask) != len(sec.Original) {
		t.Fatalf("mask not format-preserving: %q", sec.Mask)
	}

	again, err := m.Register(t.Context(),"DB_PASSWORD", "hunter2-very-secret-value")
	if err != nil {
		t.Fatalf("Register (repeat): %v", err)
	}
	if again.ID != sec.ID || again.Mask != sec.Mask {
		t.Fatal("Register is not idempotent for the same value")
	}

	reg, err := st.RegisteredSecrets(t.Context())
	if err != nil {
		t.Fatalf("RegisteredSecrets: %v", err)
	}
	if len(reg) != 1 || reg[0].Original != "hunter2-very-secret-value" {
		t.Fatalf("registered secret not stored correctly: %+v", reg)
	}
}

