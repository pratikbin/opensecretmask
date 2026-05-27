package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/store"
)

// Provider is an LLM API host the proxy intercepts. Dialect is informational
// (dashboard labelling) — masking is byte-level and dialect-agnostic.
type Provider struct {
	Host    string
	Dialect string
	// Paths restricts masking to request paths matching one of these regexp
	// patterns. Empty — or a single "*" — masks every path (the default and
	// the safe fallback). A request whose path matches no pattern is still
	// intercepted and logged, but its body is forwarded unmasked.
	Paths []string
}

// hostRule is the compiled interception rule for one provider host.
type hostRule struct {
	dialect string
	paths   []*regexp.Regexp // nil masks every path
}

// maskPath reports whether a request path falls in this host's masking scope.
func (r hostRule) maskPath(path string) bool {
	if r.paths == nil {
		return true
	}
	for _, re := range r.paths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// DefaultProviders are the LLM API hosts intercepted when none are configured.
// Hosts are matched exact — cloud platforms with per-resource or per-region
// hostnames (Azure OpenAI, AWS Bedrock, watsonx, Databricks, OCI) are not
// listed; intercept those with `--provider <host>`.
//
// All hosts mask every path; out-of-scope paths are forwarded unmasked only
// when an explicit `Paths` allowlist is configured per provider.
var DefaultProviders = []Provider{
	// Proprietary / frontier
	{Host: "api.anthropic.com", Dialect: "anthropic"},
	{Host: "api.openai.com", Dialect: "openai"},
	{Host: "generativelanguage.googleapis.com", Dialect: "gemini"},
	{Host: "aiplatform.googleapis.com", Dialect: "vertex"},
	{Host: "api.x.ai", Dialect: "xai"},
	{Host: "api.mistral.ai", Dialect: "mistral"},
	{Host: "api.cohere.com", Dialect: "cohere"},
	{Host: "api.cohere.ai", Dialect: "cohere"},
	{Host: "api.perplexity.ai", Dialect: "perplexity"},
	{Host: "api.ai21.com", Dialect: "ai21"},
	{Host: "api.reka.ai", Dialect: "reka"},
	{Host: "api.deepseek.com", Dialect: "deepseek"},
	{Host: "api.moonshot.ai", Dialect: "moonshot"},
	{Host: "api.moonshot.cn", Dialect: "moonshot"},
	{Host: "open.bigmodel.cn", Dialect: "zhipu"},
	{Host: "api.z.ai", Dialect: "zhipu"},
	{Host: "qianfan.baidubce.com", Dialect: "baidu"},
	{Host: "dashscope-intl.aliyuncs.com", Dialect: "qwen"},
	{Host: "dashscope.aliyuncs.com", Dialect: "qwen"},
	// Open-weight inference / aggregators
	{Host: "api.together.xyz", Dialect: "together"},
	{Host: "api.fireworks.ai", Dialect: "fireworks"},
	{Host: "api.groq.com", Dialect: "groq"},
	{Host: "api.replicate.com", Dialect: "replicate"},
	{Host: "router.huggingface.co", Dialect: "huggingface"},
	{Host: "openrouter.ai", Dialect: "openrouter"},
	{Host: "api.deepinfra.com", Dialect: "deepinfra"},
	{Host: "api.cerebras.ai", Dialect: "cerebras"},
	{Host: "api.sambanova.ai", Dialect: "sambanova"},
	{Host: "api.novita.ai", Dialect: "novita"},
	{Host: "api.hyperbolic.xyz", Dialect: "hyperbolic"},
	{Host: "api.tokenfactory.nebius.com", Dialect: "nebius"},
	{Host: "integrate.api.nvidia.com", Dialect: "nvidia"},
	{Host: "api.cloudflare.com", Dialect: "cloudflare"},
	{Host: "models.github.ai", Dialect: "github"},
	{Host: "ai-gateway.vercel.sh", Dialect: "vercel"},
}

// Config configures a proxy Server.
type Config struct {
	Listen      string
	Providers   []Provider
	CA          *CA
	Masker      *mask.Masker
	Store       *store.Store
	UpstreamTLS *tls.Config // upstream verification; nil verifies via system roots
	Logger      *slog.Logger
}

// Server is the CA-MITM masking proxy.
type Server struct {
	cfg    Config
	proxy  *goproxy.ProxyHttpServer
	hosts  map[string]hostRule // bare host -> interception rule
	srv    *http.Server
	logSem chan struct{}  // bounded semaphore: max concurrent log goroutines
	logWg  sync.WaitGroup // tracks in-flight log goroutines for drain on shutdown
}

// exchange carries per-request state from the request handler to the response
// handler via ProxyCtx.UserData. reqBody and respBody hold the masked bodies
// captured for the dashboard's per-request debug view.
type exchange struct {
	start    time.Time
	host     string
	dialect  string
	used     []store.Secret
	reqBody  []byte
	respBody []byte
}

// maxStoredBody caps the bytes persisted per captured body, keeping the
// request log from bloating on long conversations.
const maxStoredBody = 256 << 10

// maxRequestBody caps the request and response bodies read into memory.
// LLM payloads can carry multiple PDFs and images; 512 MiB accommodates
// them while preventing OOM from adversarially large bodies.
const maxRequestBody = 512 << 20 // 512 MiB

// capBody truncates b to maxStoredBody for storage.
func capBody(b []byte) []byte {
	if len(b) > maxStoredBody {
		b = b[:maxStoredBody]
	}
	return bytes.Clone(b)
}

// compilePaths turns a provider's path patterns into compiled regexps. An
// empty list, or any "*" entry, yields nil — meaning every path is masked. An
// invalid pattern is logged and the host falls back to masking every path, so
// a config typo fails safe (more masking) rather than open (a leak).
func compilePaths(p Provider, logger *slog.Logger) []*regexp.Regexp {
	if len(p.Paths) == 0 {
		return nil
	}
	res := make([]*regexp.Regexp, 0, len(p.Paths))
	for _, pat := range p.Paths {
		if pat == "*" {
			return nil
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			logger.Error("invalid provider path pattern, masking all paths for host",
				"host", p.Host, "pattern", pat, "err", err)
			return nil
		}
		res = append(res, re)
	}
	return res
}

// NewServer wires a goproxy MITM server to the masking pipeline.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	providers := cfg.Providers
	if len(providers) == 0 {
		providers = DefaultProviders
	}
	hosts := make(map[string]hostRule, len(providers))
	for _, p := range providers {
		hosts[p.Host] = hostRule{dialect: p.Dialect, paths: compilePaths(p, cfg.Logger)}
	}
	s := &Server{cfg: cfg, hosts: hosts}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	proxy.Logger = goproxyLogger{logger: cfg.Logger}
	// Connect directly to upstreams. The client points HTTPS_PROXY at us, so
	// an env-derived proxy would route our own upstream calls back into us.
	proxy.Tr = &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true, // plaintext bodies for masking
		TLSClientConfig:       upstreamTLSConfig(cfg),
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       600 * time.Second,
		ResponseHeaderTimeout: 600 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	proxy.ConnectDial = nil
	proxy.ConnectDialWithReq = nil

	caCert := cfg.CA.TLSCertificate()
	mitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&caCert),
	}
	tunnel := &goproxy.ConnectAction{Action: goproxy.ConnectHijack, Hijack: s.tunnelConnect}
	proxy.OnRequest().HandleConnectFunc(
		func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if _, ok := hosts[hostOnly(host)]; ok {
				return mitm, host
			}
			return tunnel, host // tunnel non-LLM hosts untouched
		})
	proxy.OnRequest().DoFunc(s.onRequest)
	proxy.OnResponse().DoFunc(s.onResponse)

	s.proxy = proxy
	s.logSem = make(chan struct{}, 32)
	// WriteTimeout is left at 0: proxy responses include long-lived SSE
	// streams that a short write deadline would sever.
	s.srv = &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s
}

// Handler returns the proxy as an http.Handler.
func (s *Server) Handler() http.Handler { return s.proxy }

// ListenAndServe runs the proxy on cfg.Listen until the process exits or
// Shutdown is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve runs the proxy on an already-bound listener until Shutdown is called.
// It lets the caller pick the socket — and read the chosen address — before the
// server starts, which ListenAndServe cannot do for an ephemeral (:0) port.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(ln)
}

// Shutdown gracefully drains in-flight requests and stops the proxy.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	err := s.srv.Shutdown(ctx)
	s.logWg.Wait() // drain in-flight log writes before store closes
	return err
}

func (s *Server) onRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	host := hostOnly(req.URL.Host)
	if host == "" {
		host = hostOnly(req.Host)
	}
	rule, isLLM := s.hosts[host]
	if !isLLM {
		return req, nil
	}
	ex := &exchange{start: time.Now(), host: host, dialect: rule.dialect}
	ctx.UserData = ex

	if !rule.maskPath(req.URL.Path) {
		// Path outside the masking scope — forward unmasked, still logged.
		return req, nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	lr := &io.LimitedReader{R: req.Body, N: maxRequestBody + 1}
	body, err := io.ReadAll(lr)
	_ = req.Body.Close()
	if err != nil {
		s.cfg.Logger.Error("read request body", "host", host, "err", err)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
			http.StatusBadGateway, "opensecretmask: could not read request body")
	}
	if lr.N == 0 {
		s.cfg.Logger.Error("request body exceeds limit", "host", host, "limit", maxRequestBody)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
			http.StatusRequestEntityTooLarge, "opensecretmask: request body too large")
	}
	masked, used, err := s.cfg.Masker.MaskBody(req.Context(), body)
	if err != nil {
		// Fail closed: never forward a body that could not be masked.
		s.cfg.Logger.Error("masking failed, request blocked", "host", host, "err", err)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
			http.StatusBadGateway, "opensecretmask: masking failed, request blocked")
	}
	if len(used) > 0 {
		// Masking can corrupt the cryptographic signature inside an Anthropic
		// thinking block; restore those opaque fields byte-for-byte.
		masked = preserveOpaqueBlocks(body, masked)
	}
	ex.used = used
	ex.reqBody = capBody(masked)
	req.Body = io.NopCloser(bytes.NewReader(masked))
	req.ContentLength = int64(len(masked))
	req.Header.Del("Content-Length")
	return req, nil
}

func (s *Server) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	ex, ok := ctx.UserData.(*exchange)
	if !ok || ex == nil {
		return resp
	}
	if resp == nil {
		s.logExchange(ctx, ex, 0, false)
		return resp
	}
	sse := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
	if len(ex.used) > 0 {
		if sse {
			resp.Body = mask.NewUnmaskReader(resp.Body, ex.used)
		} else {
			lr := &io.LimitedReader{R: resp.Body, N: maxRequestBody + 1}
			body, err := io.ReadAll(lr)
			_ = resp.Body.Close()
			if err != nil {
				s.cfg.Logger.Error("read response body", "host", ex.host, "err", err)
			} else if lr.N == 0 {
				s.cfg.Logger.Error("response body exceeds limit, returning 502",
					"host", ex.host, "limit", maxRequestBody)
				resp.StatusCode = http.StatusBadGateway
				resp.Body = io.NopCloser(bytes.NewReader(
					[]byte("opensecretmask: response body too large")))
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
			} else {
				ex.respBody = capBody(body)
				unmasked := s.cfg.Masker.UnmaskBody(body, ex.used)
				resp.Body = io.NopCloser(bytes.NewReader(unmasked))
				resp.ContentLength = int64(len(unmasked))
				resp.Header.Del("Content-Length")
			}
		}
	}
	s.logExchange(ctx, ex, resp.StatusCode, sse)
	return resp
}

func (s *Server) logExchange(ctx *goproxy.ProxyCtx, ex *exchange, status int, sse bool) {
	ids := make([]int64, 0, len(ex.used))
	for _, sec := range ex.used {
		ids = append(ids, sec.ID)
	}
	dur := time.Since(ex.start)
	rec := store.RequestRecord{
		Provider:   ex.dialect,
		Host:       ex.host,
		Method:     ctx.Req.Method,
		Path:       ctx.Req.URL.Path,
		Status:     status,
		SSE:        sse,
		Masked:     len(ex.used),
		DurationMS: dur.Milliseconds(),
		ReqBody:    ex.reqBody,
		RespBody:   ex.respBody,
	}
	if ctx.Error != nil {
		rec.ErrMsg = ctx.Error.Error()
	}
	select {
	case s.logSem <- struct{}{}:
		s.logWg.Go(func() {
			defer func() { <-s.logSem }()
			if _, err := s.cfg.Store.LogRequest(context.Background(), rec, ids); err != nil {
				s.cfg.Logger.Error("log request to store", "err", err)
			}
		})
	default:
		s.cfg.Logger.Warn("log queue full, dropping request log",
			"host", ex.host, "path", ctx.Req.URL.Path)
	}

	attrs := make([]any, 0, 10)
	attrs = append(attrs,
		"host", ex.host,
		"dialect", ex.dialect,
		"method", ctx.Req.Method,
		"path", ctx.Req.URL.Path,
		"status", status,
		"masked", len(ex.used),
		"sse", sse,
		"dur", dur.Round(time.Millisecond).String(),
	)
	if ctx.Error != nil {
		s.cfg.Logger.Error("request failed", append(attrs, "err", ctx.Error)...)
	} else {
		s.cfg.Logger.Info("request", attrs...)
	}
}

// tunnelConnect handles a CONNECT to a non-LLM host. We reply HTTP/1.1 and
// pipe the bytes ourselves; goproxy's built-in tunnel emits an HTTP/1.0 status
// line, which strict upstream proxies (e.g. npm safe-chain) reject when osm is
// chained behind them. No MITM happens here — osm never sees the plaintext.
func (s *Server) tunnelConnect(req *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	upstream, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(req.Context(), "tcp", target)
	if err != nil {
		s.cfg.Logger.Error("connect tunnel dial", "host", target, "err", err)
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = client.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = client.Close()
		_ = upstream.Close()
	}
	go pipe(upstream, client)
	go pipe(client, upstream)

	// Force both conns closed when the client request context is cancelled so
	// the io.Copy calls unblock instead of leaking until TCP drains.
	done := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			_ = client.Close()
			_ = upstream.Close()
		case <-done:
		}
	}()
	wg.Wait()
	close(done)
}

// upstreamTLSConfig returns the TLS config used to verify upstream LLM
// endpoints. A nil cfg.UpstreamTLS keeps the prior default (system roots) and
// additionally trusts cfg.CA — upstream certs signed by the local osm CA are
// always accepted, so the same mock-upstream pattern used by internal tests
// works for integration/e2e suites without exposing a CLI knob.
//
// An explicit cfg.UpstreamTLS is returned unchanged: callers wiring a custom
// pool are responsible for including (or excluding) the osm CA themselves.
func upstreamTLSConfig(cfg Config) *tls.Config {
	if cfg.UpstreamTLS != nil {
		return cfg.UpstreamTLS
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CA != nil && cfg.CA.Cert != nil {
		pool.AddCert(cfg.CA.Cert)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// hostOnly strips a :port suffix from a host[:port] string.
func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
