package mask

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/pratikbin/opensecretmask/internal/store"
)

func TestUnmaskReader(t *testing.T) {
	secrets := []store.Secret{{Original: "REALSECRETVALUE", Mask: "fakemaskedDATA0"}}
	src := io.NopCloser(strings.NewReader("event: data\nmask=fakemaskedDATA0 end"))

	got, err := io.ReadAll(NewUnmaskReader(src, secrets))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	const want = "event: data\nmask=REALSECRETVALUE end"
	if string(got) != want {
		t.Fatalf("got %q want %q", string(got), want)
	}
}

func TestUnmaskReaderOneByteAtATime(t *testing.T) {
	secrets := []store.Secret{{Original: "REALSECRETVALUE", Mask: "fakemaskedDATA0"}}
	src := io.NopCloser(iotest.OneByteReader(strings.NewReader("x fakemaskedDATA0 y")))

	got, err := io.ReadAll(NewUnmaskReader(src, secrets))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "x REALSECRETVALUE y" {
		t.Fatalf("got %q want %q", string(got), "x REALSECRETVALUE y")
	}
}

func TestUnmaskReaderNoSecrets(t *testing.T) {
	src := io.NopCloser(strings.NewReader("plain passthrough body"))
	got, err := io.ReadAll(NewUnmaskReader(src, nil))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "plain passthrough body" {
		t.Fatalf("got %q", string(got))
	}
}
