package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/store"
)

const testSecret = "sk-ant-api03-supersecretvalue1234567890ABCDEF"

type proxyHarness struct {
	client      *http.Client
	upstreamURL string
}

// newProxyHarness wires a fake upstream, the osm proxy, and a client that
// trusts the proxy CA and routes through it. When paths is non-empty the
// intercepted provider scopes masking to those path patterns.
func newProxyHarness(t *testing.T, upstream http.Handler, paths ...string) *proxyHarness {
	t.Helper()

	up := httptest.NewTLSServer(upstream)
	t.Cleanup(up.Close)

	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(t.Context(), "test-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		t.Fatalf("detect.New: %v", err)
	}

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	upURL, err := url.Parse(up.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(up.Certificate())

	srv := NewServer(Config{
		Providers:   []Provider{{Host: hostOnly(upURL.Host), Dialect: "anthropic", Paths: paths}},
		CA:          ca,
		Masker:      mask.NewMasker(st, det),
		Store:       st,
		UpstreamTLS: &tls.Config{RootCAs: upstreamPool, MinVersion: tls.VersionTLS12},
	})
	proxySrv := httptest.NewServer(srv.Handler())
	t.Cleanup(proxySrv.Close)

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("could not load osm CA into client trust pool")
	}
	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
	}}

	return &proxyHarness{client: client, upstreamURL: up.URL}
}

func TestProxyMasksJSONRoundTrip(t *testing.T) {
	saw := make(chan string, 1)
	h := newProxyHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		saw <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) // echo the masked body back
	}))

	reqBody := `{"messages":[{"content":"my key ` + testSecret + ` here"}]}`
	resp, err := h.client.Post(h.upstreamURL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	upstreamSaw := <-saw
	if strings.Contains(upstreamSaw, testSecret) {
		t.Fatalf("real secret leaked to upstream: %s", upstreamSaw)
	}
	if !strings.Contains(upstreamSaw, "sk-ant-") {
		t.Fatalf("mask lost the credential prefix: %s", upstreamSaw)
	}
	if !strings.Contains(string(got), testSecret) {
		t.Fatalf("response not unmasked — client did not see the original secret: %s", got)
	}
}

func TestProxyMasksSSERoundTrip(t *testing.T) {
	saw := make(chan string, 1)
	h := newProxyHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		saw <- string(body)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter is not a Flusher")
			return
		}
		// Write byte-at-a-time so the mask is split across stream chunks.
		for _, c := range []byte("data: " + string(body) + "\n\n") {
			_, _ = w.Write([]byte{c})
			flusher.Flush()
		}
	}))

	reqBody := `{"messages":[{"content":"streamed key ` + testSecret + `"}]}`
	resp, err := h.client.Post(h.upstreamURL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read SSE response: %v", err)
	}

	upstreamSaw := <-saw
	if strings.Contains(upstreamSaw, testSecret) {
		t.Fatalf("real secret leaked to upstream over the SSE path: %s", upstreamSaw)
	}
	if !strings.Contains(string(got), testSecret) {
		t.Fatalf("SSE response not unmasked: %s", got)
	}
}

func TestProxyPathFilterScopesMasking(t *testing.T) {
	saw := make(chan string, 1)
	h := newProxyHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		saw <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}), `^/v1/messages`)

	reqBody := `{"messages":[{"content":"key ` + testSecret + `"}]}`

	// Path in scope: the secret is masked before reaching upstream.
	resp, err := h.client.Post(h.upstreamURL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("client POST /v1/messages: %v", err)
	}
	_ = resp.Body.Close()
	if got := <-saw; strings.Contains(got, testSecret) {
		t.Fatalf("scoped path: real secret leaked to upstream: %s", got)
	}

	// Path out of scope: the body is intercepted but forwarded unmasked.
	resp, err = h.client.Post(h.upstreamURL+"/v1/admin/log", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("client POST /v1/admin/log: %v", err)
	}
	_ = resp.Body.Close()
	if got := <-saw; !strings.Contains(got, testSecret) {
		t.Fatalf("unscoped path should be forwarded unmasked, got %q", got)
	}
}

func TestProxyTunnelsNonLLMHostUntouched(t *testing.T) {
	// An upstream the proxy is NOT configured to intercept: its body must
	// pass through unmasked (tunneled, never MITM'd).
	saw := make(chan string, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		saw <- string(body)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)

	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	det, err := detect.New(detect.Config{})
	if err != nil {
		t.Fatalf("detect.New: %v", err)
	}
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	// No providers configured -> nothing is intercepted.
	srv := NewServer(Config{
		Providers: []Provider{{Host: "api.anthropic.com", Dialect: "anthropic"}},
		CA:        ca,
		Masker:    mask.NewMasker(st, det),
		Store:     st,
	})
	proxySrv := httptest.NewServer(srv.Handler())
	t.Cleanup(proxySrv.Close)

	proxyURL, _ := url.Parse(proxySrv.URL)
	upPool := x509.NewCertPool()
	upPool.AddCert(up.Certificate())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: upPool, MinVersion: tls.VersionTLS12},
	}}

	resp, err := client.Post(up.URL, "application/json",
		strings.NewReader(`{"content":"`+testSecret+`"}`))
	if err != nil {
		t.Fatalf("client POST: %v", err)
	}
	_ = resp.Body.Close()

	if got := <-saw; !strings.Contains(got, testSecret) {
		t.Fatalf("non-LLM host should be tunneled untouched, got %q", got)
	}
}
