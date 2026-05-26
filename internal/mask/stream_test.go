package mask

import (
	"testing"

	"github.com/pratikbin/opensecretmask/internal/store"
)

func TestStreamUnmaskerSplitAcrossChunks(t *testing.T) {
	u := NewStreamUnmasker([]store.Secret{
		{Original: "REALSECRETVALUE", Mask: "fakemaskedDATA0"},
	})
	full := "prefix fakemaskedDATA0 suffix"

	var got []byte
	for i := 0; i < len(full); i += 4 { // 4-byte chunks split the mask
		end := min(i+4, len(full))
		got = append(got, u.Process([]byte(full[i:end]))...)
	}
	got = append(got, u.Flush()...)

	const want = "prefix REALSECRETVALUE suffix"
	if string(got) != want {
		t.Fatalf("stream unmask: got %q want %q", string(got), want)
	}
}

func TestStreamUnmaskerSingleChunk(t *testing.T) {
	u := NewStreamUnmasker([]store.Secret{
		{Original: "ORIGINALVALUE", Mask: "maskedVALUE00"},
	})
	out := append(u.Process([]byte("see maskedVALUE00 here")), u.Flush()...)
	if string(out) != "see ORIGINALVALUE here" {
		t.Fatalf("single chunk: got %q", string(out))
	}
}

func TestStreamUnmaskerPassthrough(t *testing.T) {
	u := NewStreamUnmasker(nil)
	got := append(u.Process([]byte("hello ")), u.Process([]byte("world"))...)
	got = append(got, u.Flush()...)
	if string(got) != "hello world" {
		t.Fatalf("passthrough: got %q", string(got))
	}
}
