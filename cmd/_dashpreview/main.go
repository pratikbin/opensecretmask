// Command _dashpreview is a throwaway runner that boots the dashboard with
// seeded data for local visual verification. Not part of the build (dir is
// underscore-prefixed, so `go ./...` skips it).
package main

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func main() {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "osmdash")
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "d.db"))
	if err != nil {
		log.Fatal(err)
	}
	if err := st.InitCrypto(ctx, "pass"); err != nil {
		log.Fatal(err)
	}

	type seed struct {
		name, source, original, mask, shape string
	}
	seeds := []seed{
		{"ANTHROPIC_API_KEY", "registered", "sk-ant-ayxp-fslh-bsrf-eaah-8484", "sk-ant-wwcpympprjrtnfxw2529185", "sk-ant-api03-{32}"},
		{"OPENAI_API_KEY", "registered", "sk-proj-realopenaikeyvalue9876", "sk-proj-maskedopenaikeyvaluexyz9", "sk-proj-{40}"},
		{"GITHUB_TOKEN", "detected", "ghp_realtokenvalue1234567890abcdEF", "ghp_fakefakefakefakefakefake00abcd", "ghp_{36}"},
		{"SLACK_WEBHOOK", "detected", "https://hooks.slack.com/services/T01ABC/B02XYZ/realtokenzz", "https://hooks.slack.com/services/T0X1/B0Y2/maskedzz", "hooks.slack.com/{T}/{B}/{z}"},
		{"AWS_ACCESS_KEY_ID", "detected", "AKIAIOSFODNN7EXAMPLE", "AKIAFAKEEXAMPLEXMASKD", "AKIA{16}"},
		{"PERPLEXITY_API_KEY", "registered", "pplx-realperplexitytoken1234567", "pplx-maskedperplexityzz0000000", "pplx-{32}"},
	}
	ids := make([]int64, len(seeds))
	for i, s := range seeds {
		id, err := st.PutSecret(ctx, store.Secret{Name: s.name, Source: s.source, Original: s.original, Mask: s.mask, Shape: s.shape})
		if err != nil {
			log.Fatal(err)
		}
		ids[i] = id
	}

	reqAnthropic := []byte(`{"model":"claude-opus-4-7","max_tokens":1024,"messages":[{"role":"user","content":"deploy using sk-ant-wwcpympprjrtnfxw2529185 and token ghp_fakefakefakefakefakefake00abcd; notify https://hooks.slack.com/services/T0X1/B0Y2/maskedzz"}]}`)
	respAnthropic := []byte(`{"id":"msg_01XYZ","type":"message","role":"assistant","content":[{"type":"text","text":"Deploying with ghp_fakefakefakefakefakefake00abcd — done."}],"usage":{"input_tokens":42,"output_tokens":12}}`)

	reqOpenAI := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"check bucket using AKIAFAKEEXAMPLEXMASKD and key sk-proj-maskedopenaikeyvaluexyz9"}]}`)
	respOpenAI := []byte(`{"id":"chatcmpl-abc","choices":[{"message":{"role":"assistant","content":"Checked. Used AKIAFAKEEXAMPLEXMASKD."}}]}`)

	reqPerplexity := []byte(`{"model":"llama-3.1-sonar-large","messages":[{"role":"user","content":"summarise with pplx-maskedperplexityzz0000000"}]}`)

	type traffic struct {
		provider, host, method, path string
		status                       int
		sse                          bool
		masked                       int
		duration                     int64
		req, resp                    []byte
		err                          string
		secretIDs                    []int64
	}
	mix := []traffic{
		{"anthropic", "api.anthropic.com", "POST", "/v1/messages", 200, true, 3, 847, reqAnthropic, respAnthropic, "", []int64{ids[0], ids[2], ids[3]}},
		{"openai", "api.openai.com", "POST", "/v1/chat/completions", 200, false, 2, 412, reqOpenAI, respOpenAI, "", []int64{ids[1], ids[4]}},
		{"anthropic", "api.anthropic.com", "POST", "/v1/messages", 200, true, 5, 1203, reqAnthropic, respAnthropic, "", []int64{ids[0], ids[2], ids[3]}},
		{"perplexity", "api.perplexity.ai", "POST", "/chat/completions", 429, false, 0, 88, reqPerplexity, nil, "upstream rate limited", []int64{ids[5]}},
		{"anthropic", "api.anthropic.com", "POST", "/v1/messages", 200, false, 2, 934, reqAnthropic, respAnthropic, "", []int64{ids[0], ids[2]}},
		{"groq", "api.groq.com", "POST", "/openai/v1/chat/completions", 200, false, 1, 221, reqOpenAI, respOpenAI, "", []int64{ids[4]}},
		{"openai", "api.openai.com", "POST", "/v1/chat/completions", 200, true, 1, 612, reqOpenAI, respOpenAI, "", []int64{ids[1]}},
		{"anthropic", "api.anthropic.com", "POST", "/v1/messages", 200, true, 4, 1102, reqAnthropic, respAnthropic, "", []int64{ids[0], ids[2], ids[3], ids[4]}},
	}
	// Inflate to ~40 rows total so the list pane has scroll content.
	for cycle := 0; cycle < 5; cycle++ {
		for _, t := range mix {
			if _, err := st.LogRequest(ctx, store.RequestRecord{
				Provider: t.provider, Host: t.host, Method: t.method, Path: t.path,
				Status: t.status, SSE: t.sse, Masked: t.masked, DurationMS: t.duration,
				ErrMsg: t.err, ReqBody: t.req, RespBody: t.resp,
			}, t.secretIDs); err != nil {
				log.Fatal(err)
			}
		}
	}

	srv, err := dashboard.NewServer(st, nil)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:8799")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("dashboard preview on http://127.0.0.1:8799")
	log.Fatal(srv.Serve(ln))
}
