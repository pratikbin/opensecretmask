package mask

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/pratikbin/opensecretmask/internal/store"
)

// StreamUnmasker reverses masks in a response that arrives in chunks (an SSE
// token stream). A mask can be split across chunk boundaries, so each Process
// call holds back a tail of up to maxMaskLen-1 bytes — long enough to contain
// any partial mask — and emits only the bytes that are safe to flush.
type StreamUnmasker struct {
	pairs []pair
	hold  int
	buf   []byte
}

type pair struct {
	mask []byte
	orig []byte
}

// NewStreamUnmasker builds a StreamUnmasker for the secrets used in a request.
func NewStreamUnmasker(secrets []store.Secret) *StreamUnmasker {
	u := &StreamUnmasker{pairs: make([]pair, 0, len(secrets))}
	maxLen := 0
	for _, s := range secrets {
		if s.Mask == "" {
			continue
		}
		u.pairs = append(u.pairs, pair{mask: []byte(s.Mask), orig: []byte(s.Original)})
		if len(s.Mask) > maxLen {
			maxLen = len(s.Mask)
		}
	}
	// Replace longest masks first to avoid partial overlaps.
	slices.SortFunc(u.pairs, func(a, b pair) int {
		return cmp.Compare(len(b.mask), len(a.mask))
	})
	if maxLen > 0 {
		u.hold = maxLen - 1
	}
	return u
}

// Process unmasks the next chunk and returns the bytes safe to forward now.
// Bytes that might be the start of a mask split into the next chunk are
// retained until Process or Flush is next called.
func (u *StreamUnmasker) Process(chunk []byte) []byte {
	u.buf = append(u.buf, chunk...)
	u.replace()
	if len(u.buf) <= u.hold {
		return nil
	}
	cut := len(u.buf) - u.hold
	out := make([]byte, cut)
	copy(out, u.buf[:cut])
	// Shift held tail to front of the existing backing array — no new alloc.
	u.buf = u.buf[:copy(u.buf, u.buf[cut:])]
	return out
}

// Flush returns any remaining buffered bytes. Call it once the stream ends.
func (u *StreamUnmasker) Flush() []byte {
	u.replace()
	out := u.buf
	u.buf = nil
	return out
}

func (u *StreamUnmasker) replace() {
	for _, p := range u.pairs {
		// bytes.ReplaceAll copies the whole buffer even with zero matches;
		// most stream chunks contain no mask, so gate on Contains.
		if bytes.Contains(u.buf, p.mask) {
			u.buf = bytes.ReplaceAll(u.buf, p.mask, p.orig)
		}
	}
}

