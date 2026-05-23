package mask

import "testing"

func charClass(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 1
	case c >= 'a' && c <= 'z':
		return 2
	case c >= 'A' && c <= 'Z':
		return 3
	default:
		return 4
	}
}

func TestGarblePreservesShape(t *testing.T) {
	in := "sk-ant-api03-AbCd1234XyZ_woof"
	out := Garble(in, 0)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), len(out))
	}
	for i := range len(in) {
		ic, oc := in[i], out[i]
		if charClass(ic) != charClass(oc) {
			t.Fatalf("position %d: %q -> %q changed character class", i, ic, oc)
		}
		if charClass(ic) == 4 && ic != oc {
			t.Fatalf("position %d: structural byte %q -> %q must be preserved", i, ic, oc)
		}
	}
}

func TestGarblePrefixKept(t *testing.T) {
	in := "sk-ant-api03-SECRETVALUE1234567890"
	const keep = 13 // "sk-ant-api03-"
	out := Garble(in, keep)
	if out[:keep] != in[:keep] {
		t.Fatalf("prefix not kept verbatim: %q", out[:keep])
	}
}

func TestGarbleClampsPrefix(t *testing.T) {
	if got := Garble("abc", 99); got != "abc" {
		t.Fatalf("over-long keepPrefix should copy verbatim, got %q", got)
	}
	if got := Garble("", 0); got != "" {
		t.Fatalf("empty input should yield empty output, got %q", got)
	}
}

func TestGarbleRandomizes(t *testing.T) {
	in := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
	a, b := Garble(in, 0), Garble(in, 0)
	if a == b {
		t.Fatal("two garbles of a long secret were identical")
	}
}

