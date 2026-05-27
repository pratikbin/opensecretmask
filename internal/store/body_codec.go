package store

import (
	"fmt"
)

// Body codec constants for the requests log. Compression is internal to the
// store: callers see decoded bytes only.
const (
	bodyCodecZstd = "zstd"
	// bodyCompressionThreshold skips compression for tiny bodies where the
	// zstd frame overhead would dominate any size win.
	bodyCompressionThreshold = 1 << 10 // 1 KiB
	// maxLoggedBodyDecoded caps decoded body size on read. Sits above the
	// proxy's 256 KiB store cap so legitimate rows decode without trouble
	// while malformed/adversarial rawLen values are rejected fast.
	maxLoggedBodyDecoded = 1 << 20 // 1 MiB
)

// loggedBody is the encoded form of a request/response body destined for the
// requests table: the raw stored bytes, a codec tag ("" or "zstd"), and the
// original (decoded) length so decode can pre-size and sanity-check.
type loggedBody struct {
	data   []byte
	codec  string
	rawLen int64
}

// encodeLoggedBody compresses body with zstd when it is large enough and
// compression actually wins. Otherwise it returns the original bytes with an
// empty codec. rawLen always reflects the input length.
func (s *Store) encodeLoggedBody(body []byte) loggedBody {
	rawLen := int64(len(body))
	if len(body) < bodyCompressionThreshold {
		return loggedBody{data: body, codec: "", rawLen: rawLen}
	}
	// EncodeAll appends to dst and is safe for concurrent use.
	// https://pkg.go.dev/github.com/klauspost/compress/zstd#Encoder.EncodeAll
	compressed := s.bodyEncoder.EncodeAll(body, make([]byte, 0, len(body)))
	if len(compressed) < len(body) {
		return loggedBody{data: compressed, codec: bodyCodecZstd, rawLen: rawLen}
	}
	return loggedBody{data: body, codec: "", rawLen: rawLen}
}

// decodeLoggedBody reverses encodeLoggedBody. An empty codec returns data
// unchanged. The zstd codec decodes into a buffer pre-sized to rawLen and
// verifies the decoded length matches. Unknown codecs are rejected.
func (s *Store) decodeLoggedBody(data []byte, codec string, rawLen int64) ([]byte, error) {
	switch codec {
	case "":
		return data, nil
	case bodyCodecZstd:
		if rawLen < 0 {
			return nil, fmt.Errorf("store: decode body: negative rawLen %d", rawLen)
		}
		if rawLen > maxLoggedBodyDecoded {
			return nil, fmt.Errorf("store: decode body: rawLen %d exceeds cap %d", rawLen, maxLoggedBodyDecoded)
		}
		// DecodeAll appends decoded bytes to dst; safe for concurrent use.
		// https://pkg.go.dev/github.com/klauspost/compress/zstd#Decoder.DecodeAll
		decoded, err := s.bodyDecoder.DecodeAll(data, make([]byte, 0, rawLen))
		if err != nil {
			return nil, fmt.Errorf("store: decode body: %w", err)
		}
		if int64(len(decoded)) != rawLen {
			return nil, fmt.Errorf("store: decode body: length mismatch, got %d want %d", len(decoded), rawLen)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("store: decode body: unknown codec %q", codec)
	}
}
