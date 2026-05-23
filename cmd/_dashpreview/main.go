// Command _dashpreview is a throwaway runner that boots the dashboard with
// seeded data for local visual verification. Not part of the build (dir is
// underscore-prefixed, so `go ./...` skips it).
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func main() {
	dir, err := os.MkdirTemp("", "osmdash")
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "d.db"))
	if err != nil {
		log.Fatal(err)
	}
	if err := st.InitCrypto("pass"); err != nil {
		log.Fatal(err)
	}

	id1, err := st.PutSecret(store.Secret{
		Name: "ANTHROPIC_API_KEY", Source: "registered",
		Original: "sk-ant-ayxp-fslh-bsrf-eaah-8484",
		Mask:     "sk-ant-wwcpympprjrtnfxw2529185", Shape: "sk-ant-api03-{32}",
	})
	if err != nil {
		log.Fatal(err)
	}
	id2, err := st.PutSecret(store.Secret{
		Name: "GITHUB_TOKEN", Source: "detected",
		Original: "ghp_realtokenvalue1234567890abcdEF",
		Mask:     "ghp_fakefakefakefakefakefake00abcd", Shape: "ghp_{36}",
	})
	if err != nil {
		log.Fatal(err)
	}

	reqBody := []byte(`{"model":"claude-3-5-sonnet-20241022","max_tokens":1024,"messages":[{"role":"user","content":"deploy with key sk-ant-fakefakefakefake1234560 and token ghp_fakefakefakefakefakefake00abcd please"}]}`)
	respBody := []byte(`{"id":"msg_01XYZ","type":"message","role":"assistant","content":[{"type":"text","text":"Done."}],"usage":{"input_tokens":42,"output_tokens":8}}`)

	for i := 0; i < 30; i++ {
		if _, err := st.LogRequest(store.RequestRecord{
			Provider: "anthropic", Host: "api.anthropic.com", Method: "POST",
			Path: "/v1/messages", Status: 200, Masked: 2, DurationMS: 842,
			ReqBody: reqBody, RespBody: respBody,
		}, []int64{id1, id2}); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := st.LogRequest(store.RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", Status: 429, SSE: true, Masked: 1, DurationMS: 55,
		ReqBody: reqBody, ErrMsg: "upstream rate limited",
	}, []int64{id1}); err != nil {
		log.Fatal(err)
	}

	srv, err := dashboard.NewServer(st, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("dashboard preview on http://127.0.0.1:8799")
	log.Fatal(srv.ListenAndServe("127.0.0.1:8799"))
}
