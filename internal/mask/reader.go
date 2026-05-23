package mask

import (
	"io"

	"github.com/pratikbin/opensecretmask/internal/store"
)

const readChunk = 32 * 1024

// unmaskReader wraps a response body, reversing masks in the stream as it is
// read. It uses StreamUnmasker so a mask split across reads is still caught.
type unmaskReader struct {
	src     io.ReadCloser
	u       *StreamUnmasker
	buf     []byte
	pending []byte
	srcEOF  bool
	done    bool
}

// NewUnmaskReader returns a ReadCloser that yields src with every mask in
// secrets reversed to its original. Closing it closes src.
func NewUnmaskReader(src io.ReadCloser, secrets []store.Secret) io.ReadCloser {
	return &unmaskReader{
		src: src,
		u:   NewStreamUnmasker(secrets),
		buf: make([]byte, readChunk),
	}
}

func (r *unmaskReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 && !r.done {
		if r.srcEOF {
			r.pending = r.u.Flush()
			r.done = true
			break
		}
		n, err := r.src.Read(r.buf)
		if n > 0 {
			r.pending = r.u.Process(r.buf[:n])
		}
		switch {
		case err == io.EOF:
			r.srcEOF = true
		case err != nil:
			return 0, err
		}
	}
	if len(r.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *unmaskReader) Close() error { return r.src.Close() }
