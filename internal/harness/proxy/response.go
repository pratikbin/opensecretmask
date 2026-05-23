package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/pratikbin/opensecretmask/internal/core/engine"
)

type Responder struct {
	Engine *engine.Engine
}

func (rs *Responder) Modify(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		resp.Body = wrapSSEUnmask(resp.Body, rs.Engine)
		resp.Header.Del("Content-Length")
		return nil
	}

	if resp.Request == nil || !pathScopedForUnmask(resp.Request.URL.Path) {
		return nil
	}
	if resp.Body == nil {
		return nil
	}

	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return nil
	}
	out := unmaskJSONBody(raw, rs.Engine)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

func unmaskJSONBody(body []byte, eng *engine.Engine) []byte {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	if blocks, ok := doc["content"].([]any); ok {
		unmaskBlocks(blocks, eng)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

func unmaskBlocks(blocks []any, eng *engine.Engine) {
	for _, b := range blocks {
		blk, ok := b.(map[string]any)
		if !ok {
			continue
		}
		switch blk["type"] {
		case "text":
			if s, ok := blk["text"].(string); ok {
				if out, _, err := eng.UnmaskText(s); err == nil {
					blk["text"] = out
				}
			}
		case "tool_use":
			if in, ok := blk["input"].(map[string]any); ok {
				unmaskJSONMap(in, eng)
			}
		}
	}
}

func unmaskJSONMap(m map[string]any, eng *engine.Engine) {
	for k, v := range m {
		switch vv := v.(type) {
		case string:
			if out, _, err := eng.UnmaskText(vv); err == nil {
				m[k] = out
			}
		case map[string]any:
			unmaskJSONMap(vv, eng)
		case []any:
			for i, e := range vv {
				if s, ok := e.(string); ok {
					if out, _, err := eng.UnmaskText(s); err == nil {
						vv[i] = out
					}
				} else if mm, ok := e.(map[string]any); ok {
					unmaskJSONMap(mm, eng)
				}
			}
		}
	}
}
