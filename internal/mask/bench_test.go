package mask

import (
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/store"
)

// BenchmarkStreamUnmaskerNoMask streams chunks that contain none of the masks —
// the common SSE case the bytes.Contains gate in replace() accelerates.
func BenchmarkStreamUnmaskerNoMask(b *testing.B) {
	secrets := []store.Secret{
		{Mask: "sk-ant-aaaaaaaaaaaaaaaa", Original: "sk-ant-bbbbbbbbbbbbbbbb"},
		{Mask: "ghp_cccccccccccccccccccc", Original: "ghp_dddddddddddddddddddd"},
	}
	chunk := []byte(`data: {"type":"content_block_delta","index":0,` +
		`"delta":{"type":"text_delta","text":"some streamed model tokens"}}` + "\n\n")
	b.ReportAllocs()
	for b.Loop() {
		u := NewStreamUnmasker(secrets)
		for range 8 {
			u.Process(chunk)
		}
		u.Flush()
	}
}

func newBenchMasker(b *testing.B) *Masker {
	b.Helper()
	st, err := store.Open(b.Context(), filepath.Join(b.TempDir(), "m.db"))
	if err != nil {
		b.Fatalf("store.Open: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(b.Context(),"test-pass"); err != nil {
		b.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		b.Fatalf("detect.New: %v", err)
	}
	return NewMasker(st, det)
}

// BenchmarkMaskBodyNoSecret masks a realistic JSON request whose string leaves
// carry no credentials — the common case. Registered secrets are present, so
// the per-leaf registered-secret scan runs but never matches.
func BenchmarkMaskBodyNoSecret(b *testing.B) {
	m := newBenchMasker(b)
	for _, v := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_016c0d3c8e5f4a2b9d7e6f1a3c5b8d9e0f2a4c",
		"sk-ant-api03-FAKEEXAMPLEKEYVALUE1234567890",
	} {
		if _, err := m.Register(b.Context(),"bench", v); err != nil {
			b.Fatalf("Register: %v", err)
		}
	}
	body := []byte(`{"model":"claude-opus-4","max_tokens":2048,` +
		`"system":"You are a helpful assistant.","messages":[` +
		`{"role":"user","content":"Explain the Go memory model and how ` +
		`channels provide happens-before guarantees."},` +
		`{"role":"assistant","content":"The Go memory model defines when ` +
		`reads observe writes."},` +
		`{"role":"user","content":"Now show an example with a worker pool."}]}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := m.MaskBody(b.Context(),body); err != nil {
			b.Fatalf("MaskBody: %v", err)
		}
	}
}
