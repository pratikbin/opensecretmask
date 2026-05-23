package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pratikbin/opensecretmask/internal/core/engine"
)

type Rewriter struct {
	Engine    *engine.Engine
	Upstream  *url.URL
	SessionID string
}

func (r *Rewriter) Director(req *http.Request) {
	req.URL.Scheme = r.Upstream.Scheme
	req.URL.Host = r.Upstream.Host
	req.Host = r.Upstream.Host
	if r.Upstream.Path != "" && r.Upstream.Path != "/" {
		req.URL.Path = singleJoiningSlash(r.Upstream.Path, req.URL.Path)
	}

	if !pathScopedForMask(req.URL.Path) || req.Body == nil {
		return
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
		req.ContentLength = 0
		req.Header.Set("Content-Length", "0")
		return
	}

	masked, ok := r.maskBody(req.Context(), body)
	if !ok {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(masked))
	req.ContentLength = int64(len(masked))
	req.Header.Set("Content-Length", strconv.Itoa(len(masked)))
}

func (r *Rewriter) maskBody(ctx context.Context, body []byte) ([]byte, bool) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	msgs, ok := doc["messages"].([]any)
	if !ok {
		return nil, false
	}
	for _, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		switch c := mm["content"].(type) {
		case string:
			if out, _, err := r.Engine.MaskText(ctx, r.SessionID, "proxy", c); err == nil {
				mm["content"] = out
			}
		case []any:
			r.maskBlocks(ctx, c)
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

func (r *Rewriter) maskBlocks(ctx context.Context, blocks []any) {
	for _, b := range blocks {
		blk, ok := b.(map[string]any)
		if !ok {
			continue
		}
		switch blk["type"] {
		case "text":
			if s, ok := blk["text"].(string); ok {
				if out, _, err := r.Engine.MaskText(ctx, r.SessionID, "proxy", s); err == nil {
					blk["text"] = out
				}
			}
		case "tool_use":
			if in, ok := blk["input"].(map[string]any); ok {
				r.maskJSON(ctx, in)
			}
		case "tool_result":
			switch cc := blk["content"].(type) {
			case string:
				if out, _, err := r.Engine.MaskText(ctx, r.SessionID, "proxy", cc); err == nil {
					blk["content"] = out
				}
			case []any:
				r.maskBlocks(ctx, cc)
			}
		}
	}
}

func (r *Rewriter) maskJSON(ctx context.Context, m map[string]any) {
	for k, v := range m {
		switch vv := v.(type) {
		case string:
			if out, _, err := r.Engine.MaskText(ctx, r.SessionID, "proxy", vv); err == nil {
				m[k] = out
			}
		case map[string]any:
			r.maskJSON(ctx, vv)
		case []any:
			for i, e := range vv {
				if s, ok := e.(string); ok {
					if out, _, err := r.Engine.MaskText(ctx, r.SessionID, "proxy", s); err == nil {
						vv[i] = out
					}
				} else if mm, ok := e.(map[string]any); ok {
					r.maskJSON(ctx, mm)
				}
			}
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := len(a) > 0 && a[len(a)-1] == '/'
	bslash := len(b) > 0 && b[0] == '/'
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
