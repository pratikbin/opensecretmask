package keymgr

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Hasher wraps the per-install key for FPE derivation.
type Hasher struct {
	key []byte
}

func NewHasher(key []byte) *Hasher { return &Hasher{key: key} }

// MAC returns HMAC-SHA256(key, data). Use as keying material for HKDF-Expand.
func (h *Hasher) MAC(data []byte) []byte {
	m := hmac.New(sha256.New, h.key)
	m.Write(data)
	return m.Sum(nil)
}

// Stream returns an HKDF-Expand reader over the given info string. The reader
// produces an arbitrary-length pseudorandom byte stream deterministic in
// (h.key, info). Used by transformer for charset rejection sampling.
func (h *Hasher) Stream(info []byte) io.Reader {
	prk := h.MAC(info[:0]) // PRK derived from key alone; info supplied to Expand
	return hkdf.Expand(sha256.New, prk, info)
}
