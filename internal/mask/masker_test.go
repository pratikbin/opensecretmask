package mask_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func newMasker(t *testing.T) (*mask.Masker, *store.Store) {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(t.Context(), "test-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		t.Fatalf("detect.New: %v", err)
	}
	return mask.NewMasker(st, det), st
}

func TestMaskUnmaskRoundTrip(t *testing.T) {
	m, _ := newMasker(t)
	secret := "sk-ant-sll98-subnvw7548641937JSXKPCHN" // gitleaks:allow
	orig := []byte(`{"content":"my key ` + secret + ` stays secret"}`)

	masked, used, err := m.MaskBody(t.Context(), orig)
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
	body := []byte("ghu_kgzuxbpugxmzbxkfrrdpqtqtyf1501231069") // gitleaks:allow

	first, used1, err := m.MaskBody(t.Context(), body)
	if err != nil {
		t.Fatalf("MaskBody 1: %v", err)
	}
	second, used2, err := m.MaskBody(t.Context(), body)
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
	const msk = "XXXXXXX-xxxxx-xx"
	if _, err := st.PutSecret(t.Context(), store.Secret{
		Name: "DB_PASSWORD", Source: "registered",
		Original: orig, Mask: msk, Shape: "aaaaaa9-aaaaa-aa",
	}); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	masked, used, err := m.MaskBody(t.Context(), []byte("connect with "+orig+" now"))
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
	masked, used, err := m.MaskBody(t.Context(), body)
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
	sec, err := m.Register(t.Context(), "DB_PASSWORD", orig)
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

	masked, used, err := m.MaskBody(t.Context(), body)
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
	secret := "sk-ant-lwn32-pebahu1155898630ODTBLIYW" // gitleaks:allow
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

	masked, used, err := m.MaskBody(t.Context(), body)
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

	sec, err := m.Register(t.Context(), "DB_PASSWORD", "hunter2-very-secret-value")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if sec.Source != "registered" {
		t.Fatalf("source = %q, want registered", sec.Source)
	}
	if sec.Mask == sec.Original || len(sec.Mask) != len(sec.Original) {
		t.Fatalf("mask not format-preserving: %q", sec.Mask)
	}

	again, err := m.Register(t.Context(), "DB_PASSWORD", "hunter2-very-secret-value")
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

// Each base64 payload below embeds a credential-shaped substring that the
// detector WOULD flag if the binary-blob skip failed — so a passing test
// proves the skip, not that the data simply happens not to match any rule.

// blobBody returns a JSON-marshalable request body with data placed at the
// field path described by name. The body functions are the single source of
// truth: embedded is set to data in each case, so the field value and the
// checked string are always identical.
func anthropicImageBlobBody(data string) any {
	return map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type": "image",
						"source": map[string]any{
							"type":       "base64",
							"media_type": "image/png",
							"data":       data,
						},
					},
				},
			},
		},
	}
}

func anthropicDocumentBlobBody(data string) any {
	return map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type": "document",
						"source": map[string]any{
							"type":       "base64",
							"media_type": "application/pdf",
							"data":       data,
						},
					},
				},
			},
		},
	}
}

// TestMaskBodyJSONSkipsBinaryBlobs asserts that multimodal attachment fields
// across Anthropic, OpenAI, and Gemini request shapes are never inspected for
// secrets. The embedded strings contain credential-shaped substrings; the skip
// is confirmed when MaskBody returns zero used secrets and leaves the field
// bytes unmodified.
func TestMaskBodyJSONSkipsBinaryBlobs(t *testing.T) {
	// imageData and pdfData are credential-shaped strings that the detector
	// would flag if the structural blob skip failed. They are used as both the
	// body field value and the check string — guaranteeing they are identical.
	imageData := "iVBORw0KGgoAAAANSUhEUghu_hjrvnkgmzppuhdyndxcnhayotn3905032884YTXB"                       // gitleaks:allow
	pdfData := "JVBERi0xLjcKghq_ixquqmnmmuoacwaiqpaatzttdt3676258512jryoxk"                                // gitleaks:allow
	imageURLData := "data:image/png;base64,iVBORw0KGghu_hjrvnkgmzppuhdyndxcnhayotn3905032884YTXB"          // gitleaks:allow
	jpegInputData := "data:image/jpeg;base64,/9j/4ghb_kgbthiukcfaygqvcvkbvvlfpuj4015602388OJ"              // gitleaks:allow
	pdfInputFileData := "data:application/pdf;base64,JVBERi0xLjcKghd_fhxefvefbkdlundsleunghwanj6224981608" // gitleaks:allow
	geminiCamelData := "iVBORghd_narbpgaxpzqbniywhphniqrksf6525815231FFESDI"                               // gitleaks:allow
	geminiSnakeData := "iVBORghe_dpmrsrdsthivgnqkuthozhwbki8220702920UKIWOV"
	anthropicURLData := "https://example.com/ghp_abcdefghijklmnopqrstuvwxyz0123456789AAAA.png"
	fileIDData := "file_ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	rawB64Data := "JVBERi0xLjcKghp_abcdefghijklmnopqrstuvwxyz0123456789AAAA"

	cases := []struct {
		name     string
		body     any
		embedded string
	}{
		{
			name:     "AnthropicImageBlob",
			embedded: imageData,
			body:     anthropicImageBlobBody(imageData),
		},
		{
			name:     "AnthropicDocumentBlob",
			embedded: pdfData,
			body:     anthropicDocumentBlobBody(pdfData),
		},
		{
			name:     "OpenAIChatImageURL",
			embedded: imageURLData,
			body: map[string]any{
				"messages": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{
								"type":      "image_url",
								"image_url": map[string]any{"url": imageURLData},
							},
						},
					},
				},
			},
		},
		{
			name:     "OpenAIResponsesInputImage",
			embedded: jpegInputData,
			body: map[string]any{
				"input": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{"type": "input_image", "image_url": jpegInputData},
						},
					},
				},
			},
		},
		{
			name:     "OpenAIInputFile",
			embedded: pdfInputFileData,
			body: map[string]any{
				"input": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{"type": "input_file", "file_data": pdfInputFileData},
						},
					},
				},
			},
		},
		{
			name:     "GeminiInlineData",
			embedded: geminiCamelData,
			body: map[string]any{
				"contents": []any{
					map[string]any{
						"parts": []any{
							map[string]any{
								"inlineData": map[string]any{
									"mimeType": "image/png",
									"data":     geminiCamelData,
								},
							},
						},
					},
				},
			},
		},
		{
			name:     "GeminiInlineDataSnakeCase",
			embedded: geminiSnakeData,
			body: map[string]any{
				"contents": []any{
					map[string]any{
						"parts": []any{
							map[string]any{
								"inline_data": map[string]any{
									"mime_type": "image/png",
									"data":      geminiSnakeData,
								},
							},
						},
					},
				},
			},
		},
		{
			// {type:"image", source:{type:"url", url:"..."}} — whole source skipped.
			name:     "AnthropicImageURLSource",
			embedded: anthropicURLData,
			body: map[string]any{
				"messages": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{
								"type":   "image",
								"source": map[string]any{"type": "url", "url": anthropicURLData},
							},
						},
					},
				},
			},
		},
		{
			// {type:"document", source:{type:"file", file_id:"..."}} — source skipped.
			name:     "AnthropicDocumentFileSource",
			embedded: fileIDData,
			body: map[string]any{
				"messages": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{
								"type":   "document",
								"source": map[string]any{"type": "file", "file_id": fileIDData},
							},
						},
					},
				},
			},
		},
		{
			name:     "OpenAIInputImageFileID",
			embedded: fileIDData,
			body: map[string]any{
				"input": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{"type": "input_image", "file_id": fileIDData},
						},
					},
				},
			},
		},
		{
			// OpenAI docs show input_file.file_data with raw base64 (no data: prefix).
			// Structural skip via type=="input_file" catches it.
			name:     "OpenAIInputFileRawBase64",
			embedded: rawB64Data,
			body: map[string]any{
				"input": []any{
					map[string]any{
						"role": "user",
						"content": []any{
							map[string]any{
								"type":      "input_file",
								"filename":  "x.pdf",
								"file_data": rawB64Data,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newMasker(t)
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			masked, used, err := m.MaskBody(t.Context(), body)
			if err != nil {
				t.Fatalf("MaskBody: %v", err)
			}
			if len(used) != 0 {
				t.Fatalf("expected no secrets in blob field, got %d: %+v", len(used), used)
			}
			if !bytes.Contains(masked, []byte(tc.embedded)) {
				t.Fatalf("blob field was altered: %s", masked)
			}
		})
	}
}

func TestMaskBodyJSONImageBlobAdjacentSecretStillMasked(t *testing.T) {
	m, _ := newMasker(t)
	secret := "sk-ant-lwn32-pebahu1155898630ODTBLIYW"                // gitleaks:allow
	imageData := "iVBORghu_hjrvnkgmzppuhdyndxcnhayotn3905032884YTXB" // gitleaks:allow
	body, err := json.Marshal(map[string]any{
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type": "image",
						"source": map[string]any{
							"type":       "base64",
							"media_type": "image/png",
							"data":       imageData,
						},
					},
					map[string]any{"type": "text", "text": "key=" + secret},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	masked, used, err := m.MaskBody(t.Context(), body)
	if err != nil {
		t.Fatalf("MaskBody: %v", err)
	}
	if bytes.Contains(masked, []byte(secret)) {
		t.Fatal("adjacent secret was not masked")
	}
	if !bytes.Contains(masked, []byte(imageData)) {
		t.Fatal("image data was altered while masking adjacent text")
	}
	if len(used) != 1 {
		t.Fatalf("expected exactly 1 secret used, got %d: %+v", len(used), used)
	}
}
