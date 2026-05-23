// Package mask turns detected secrets into format-preserving fakes and
// reverses the substitution on responses.
package mask

import (
	"crypto/rand"
	"math/big"
)

const (
	digits = "0123456789"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// Garble returns a format-preserving fake of value: the first keepPrefix
// bytes are copied verbatim; after that each digit becomes a random digit,
// each lowercase letter a random lowercase letter, each uppercase letter a
// random uppercase letter, and every other byte (structure such as -, _, .)
// is left in place. Length and shape are preserved so an LLM treats the fake
// the same as a real credential.
//
// The result is random — stability of a secret's mask comes from the store
// lookup, not from this function. Callers must ensure the result differs from
// value and collides with no existing mask.
func Garble(value string, keepPrefix int) string {
	b := []byte(value)
	if keepPrefix < 0 {
		keepPrefix = 0
	}
	if keepPrefix > len(b) {
		keepPrefix = len(b)
	}
	out := make([]byte, len(b))
	copy(out, b[:keepPrefix])
	for i := keepPrefix; i < len(b); i++ {
		switch c := b[i]; {
		case c >= '0' && c <= '9':
			out[i] = pick(digits)
		case c >= 'a' && c <= 'z':
			out[i] = pick(lower)
		case c >= 'A' && c <= 'Z':
			out[i] = pick(upper)
		default:
			out[i] = c
		}
	}
	return string(out)
}

func pick(set string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		panic("mask: crypto/rand failure: " + err.Error())
	}
	return set[n.Int64()]
}

