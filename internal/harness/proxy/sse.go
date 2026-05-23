package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"github.com/pratikbin/opensecretmask/internal/core/engine"
)

const sseTailHold = 256

func wrapSSEUnmask(body io.ReadCloser, eng *engine.Engine) io.ReadCloser {
	pr, pw := io.Pipe()
	s := &sseStream{
		src:  body,
		out:  pw,
		eng:  eng,
		tail: map[string][]byte{},
	}
	go s.run()
	return pr
}

type sseStream struct {
	src  io.ReadCloser
	out  *io.PipeWriter
	eng  *engine.Engine
	mu   sync.Mutex
	tail map[string][]byte
}

func (s *sseStream) run() {
	defer s.src.Close()
	defer s.out.Close()

	br := bufio.NewReaderSize(s.src, 64*1024)
	var buf bytes.Buffer
	tmp := make([]byte, 8*1024)
	for {
		n, err := br.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			for {
				ev, ok := splitSSEEvent(&buf)
				if !ok {
					break
				}
				out := s.processEvent(ev)
				if _, werr := s.out.Write(out); werr != nil {
					return
				}
			}
		}
		if err != nil {
			if buf.Len() > 0 {
				if _, werr := s.out.Write(buf.Bytes()); werr != nil {
					return
				}
			}
			if err != io.EOF {
				_ = s.out.CloseWithError(err)
			}
			return
		}
	}
}

func splitSSEEvent(buf *bytes.Buffer) ([]byte, bool) {
	data := buf.Bytes()
	i := bytes.Index(data, []byte("\n\n"))
	if i < 0 {
		return nil, false
	}
	end := i + 2
	ev := make([]byte, end)
	copy(ev, data[:end])
	buf.Next(end)
	return ev, true
}

func (s *sseStream) processEvent(ev []byte) []byte {
	dataPrefix := []byte("data: ")
	idx := bytes.Index(ev, dataPrefix)
	if idx < 0 {
		return ev
	}
	payloadStart := idx + len(dataPrefix)
	payloadEnd := bytes.IndexByte(ev[payloadStart:], '\n')
	if payloadEnd < 0 {
		return ev
	}
	payload := ev[payloadStart : payloadStart+payloadEnd]

	rewritten, ok := s.rewritePayload(payload)
	if !ok {
		return ev
	}

	out := make([]byte, 0, len(ev)+len(rewritten))
	out = append(out, ev[:payloadStart]...)
	out = append(out, rewritten...)
	out = append(out, ev[payloadStart+payloadEnd:]...)
	return out
}

func (s *sseStream) rewritePayload(payload []byte) ([]byte, bool) {
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, false
	}
	tp, _ := doc["type"].(string)
	switch tp {
	case "content_block_start":
		if cb, ok := doc["content_block"].(map[string]any); ok {
			if s.unmaskBlock(cb, doc) {
				out, err := json.Marshal(doc)
				if err != nil {
					return nil, false
				}
				return out, true
			}
		}
	case "content_block_delta":
		if delta, ok := doc["delta"].(map[string]any); ok {
			dtp, _ := delta["type"].(string)
			key := streamKey(doc, "delta")
			switch dtp {
			case "text_delta":
				if s2, ok := delta["text"].(string); ok {
					delta["text"] = s.unmaskWithTailHold(s2, key)
				}
			case "input_json_delta":
				if s2, ok := delta["partial_json"].(string); ok {
					delta["partial_json"] = s.unmaskWithTailHold(s2, key)
				}
			}
			out, err := json.Marshal(doc)
			if err != nil {
				return nil, false
			}
			return out, true
		}
	case "message_delta", "message_start", "message_stop", "content_block_stop", "ping", "error":
		return nil, false
	}
	return nil, false
}

func (s *sseStream) unmaskBlock(cb map[string]any, doc map[string]any) bool {
	switch cb["type"] {
	case "text":
		if s2, ok := cb["text"].(string); ok {
			if out, _, err := s.eng.UnmaskText(s2); err == nil {
				cb["text"] = out
				return true
			}
		}
	case "tool_use":
		if in, ok := cb["input"].(map[string]any); ok {
			unmaskJSONMap(in, s.eng)
			return true
		}
	}
	_ = doc
	return false
}

func streamKey(doc map[string]any, sub string) string {
	idx, _ := doc["index"].(float64)
	return sub + ":" + jsonNumber(idx)
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func (s *sseStream) unmaskWithTailHold(in, key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	combined := append([]byte{}, s.tail[key]...)
	combined = append(combined, in...)
	holdAt := len(combined) - sseTailHold
	if holdAt < 0 {
		holdAt = 0
	}
	emit := string(combined[:holdAt])
	s.tail[key] = combined[holdAt:]
	out, _, err := s.eng.UnmaskText(emit)
	if err != nil {
		out = emit
	}
	return out
}
