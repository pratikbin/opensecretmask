package proxy

import (
	"bytes"
	"testing"
)

// thinkingValues returns the signature and thinking text of the first thinking
// block in a request body, for assertions.
func thinkingValues(t *testing.T, body []byte) (sig, text string) {
	t.Helper()
	doc, err := decodeJSONObject(body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	blocks := opaqueBlocks(doc)
	if len(blocks) == 0 {
		t.Fatalf("no opaque blocks in body")
	}
	return stringValue(blocks[0]["signature"]), stringValue(blocks[0]["thinking"])
}

func TestPreserveOpaqueBlocksRestoresSignature(t *testing.T) {
	t.Parallel()
	original := []byte(`{"model":"claude","messages":[` +
		`{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"key is sk-ant-REALSECRET99","signature":"AbCdEf0123456789SIGNATURE+/=="}]}]}`)
	// Masking re-masks the thinking text (correct) and corrupts the signature
	// (a detection regex matched inside it).
	masked := []byte(`{"model":"claude","messages":[` +
		`{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"key is sk-ant-FAKEGARBLE11","signature":"AbCdEf0123456789CORRUPTED+/=="}]}]}`)

	out := preserveOpaqueBlocks(original, masked)

	sig, text := thinkingValues(t, out)
	if want := "AbCdEf0123456789SIGNATURE+/=="; sig != want {
		t.Errorf("signature = %q, want %q (original must be restored)", sig, want)
	}
	if want := "key is sk-ant-FAKEGARBLE11"; text != want {
		t.Errorf("thinking = %q, want %q (masked text must be kept)", text, want)
	}
}

func TestPreserveOpaqueBlocksRestoresRedactedData(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"assistant","content":[` +
		`{"type":"redacted_thinking","data":"ENCRYPTED-BLOB-original=="}]}]}`)
	masked := []byte(`{"messages":[{"role":"assistant","content":[` +
		`{"type":"redacted_thinking","data":"ENCRYPTED-BLOB-CORRUPTED=="}]}]}`)

	out := preserveOpaqueBlocks(original, masked)

	doc, err := decodeJSONObject(out)
	if err != nil {
		t.Fatalf("decode out: %v", err)
	}
	got := stringValue(opaqueBlocks(doc)[0]["data"])
	if want := "ENCRYPTED-BLOB-original=="; got != want {
		t.Errorf("data = %q, want %q", got, want)
	}
}

func TestPreserveOpaqueBlocksNoThinkingBlocks(t *testing.T) {
	t.Parallel()
	masked := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	if out := preserveOpaqueBlocks(masked, masked); string(out) != string(masked) {
		t.Errorf("body with no thinking blocks must pass through unchanged")
	}
}

func TestPreserveOpaqueBlocksNonJSON(t *testing.T) {
	t.Parallel()
	masked := []byte("not json at all")
	if out := preserveOpaqueBlocks(masked, masked); string(out) != string(masked) {
		t.Errorf("non-JSON body must pass through unchanged")
	}
}

func TestPreserveOpaqueBlocksPreservesUnknownFields(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"t","signature":"SIG"}]}],` +
		`"future_field":{"nested":[1,2,3]},"max_tokens":64000}`)
	masked := []byte(`{"messages":[{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"t","signature":"BAD"}]}],` +
		`"future_field":{"nested":[1,2,3]},"max_tokens":64000}`)

	out := preserveOpaqueBlocks(original, masked)

	doc, err := decodeJSONObject(out)
	if err != nil {
		t.Fatalf("decode out: %v", err)
	}
	if _, ok := doc["future_field"]; !ok {
		t.Errorf("unknown field future_field was dropped")
	}
	if !bytes.Contains(out, []byte(`"max_tokens":64000`)) {
		t.Errorf("max_tokens did not round-trip exactly: %s", out)
	}
}
