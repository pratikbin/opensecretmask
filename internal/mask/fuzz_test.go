package mask_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/store"
)

// FuzzGarbleShape asserts that Garble always produces output of the same
// length as its input, regardless of content.
func FuzzGarbleShape(f *testing.F) {
	f.Add("sk-ant-hrv15-yqrior7153981859DINTLNGA", 7)    // gitleaks:allow
	f.Add("ghu_xefvefbkdlundsleunghwanjqz6224981609", 4) // gitleaks:allow
	f.Add("", 0)
	f.Add("abc", 99)
	f.Fuzz(func(t *testing.T, in string, keepPrefix int) {
		out := mask.Garble(in, keepPrefix)
		if len(out) != len(in) {
			t.Fatalf("Garble(%q, %d): len(out)=%d, want %d", in, keepPrefix, len(out), len(in))
		}
	})
}

// FuzzStreamUnmaskerChunks asserts that feeding a fixed body in fuzzed chunk
// sizes produces the same final output as a single-chunk pass.
func FuzzStreamUnmaskerChunks(f *testing.F) {
	f.Add(uint8(1))
	f.Add(uint8(4))
	f.Add(uint8(15))
	f.Add(uint8(0))
	f.Fuzz(func(t *testing.T, rawChunkSize uint8) {
		// Clamp to ≥1 so we don't spin forever on zero-length chunks.
		chunkSize := max(int(rawChunkSize), 1)

		const (
			msk  = "fakemaskedDATA0"
			orig = "REALSECRETVALUE"
		)
		secrets := []store.Secret{{Mask: msk, Original: orig}}
		body := []byte("start " + msk + " middle " + msk + " end")

		// Reference: single-chunk pass.
		ref := mask.NewStreamUnmasker(secrets)
		refOut := append(ref.Process(body), ref.Flush()...)

		// Chunked pass with fuzzed chunk size.
		u := mask.NewStreamUnmasker(secrets)
		var got []byte
		for i := 0; i < len(body); i += chunkSize {
			end := min(i+chunkSize, len(body))
			got = append(got, u.Process(body[i:end])...)
		}
		got = append(got, u.Flush()...)

		if !bytes.Equal(got, refOut) {
			t.Fatalf("chunkSize=%d: got %q want %q", chunkSize, got, refOut)
		}
	})
}

// FuzzMaskBody asserts that after masking, the registered secret bytes do not
// appear in the output. The fuzzed bytes are appended as plain text *after*
// the fuzzed content so the secret always sits in a scannable context — not
// inside a blob-skip field — guaranteeing the invariant is testable.
//
// The masker is created once outside f.Fuzz so each seed iteration reuses
// the same store, avoiding re-initialization errors.
func FuzzMaskBody(f *testing.F) {
	f.Add([]byte(`{"model":"claude-opus-4","messages":[{"role":"user","content":"hello"}]}`))
	f.Add([]byte(`{"input":"just text"}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))

	// Create masker once — store lives for the lifetime of the fuzz function.
	st, err := store.Open(f.Context(), filepath.Join(f.TempDir(), "fuzz.db"))
	if err != nil {
		f.Fatalf("store.Open: %v", err)
	}
	f.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(f.Context(), "fuzz-pass"); err != nil {
		f.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		f.Fatalf("detect.New: %v", err)
	}
	m := mask.NewMasker(st, det)

	const secret = "hunter2-very-secret-value"
	if _, err := m.Register(f.Context(), "FUZZ_SECRET", secret); err != nil {
		f.Fatalf("Register: %v", err)
	}

	f.Fuzz(func(t *testing.T, fuzzed []byte) {
		// Append the secret in plain context after the fuzzed bytes so it is
		// never inside a blob-skip structure (image/source/data etc.) that
		// MaskBody intentionally ignores.
		body := append(append([]byte(nil), fuzzed...), []byte(" "+secret)...)

		masked, _, err := m.MaskBody(t.Context(), body)
		if err != nil {
			// Errors are valid outcomes for malformed input; the invariant is
			// only that if we get output, it must not contain the secret.
			return
		}
		if bytes.Contains(masked, []byte(secret)) {
			t.Fatalf("registered secret found in masked output for input %q", fuzzed)
		}
	})
}
