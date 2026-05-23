// Package dashboard serves the embedded realtime web UI: a tabbed local view of
// the secret store and the proxied request history with per-request debugging.
package dashboard

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"html"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pratikbin/opensecretmask/internal/store"
)

//go:embed templates/*.html assets/*
var content embed.FS

// requestRetention is how long captured requests are kept before the dashboard
// purges them — the masked bodies are debug data, not a permanent record.
const requestRetention = 7 * 24 * time.Hour

// Server is the dashboard HTTP server.
type Server struct {
	store  *store.Store
	tmpl   *template.Template
	mux    *http.ServeMux
	srv    *http.Server
	logger *slog.Logger
	done   chan struct{}
	stop   sync.Once
}

// NewServer parses the embedded templates and wires the dashboard routes.
func NewServer(st *store.Store, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, err
	}
	assetFS, err := fs.Sub(content, "assets")
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, tmpl: tmpl, mux: http.NewServeMux(), logger: logger, done: make(chan struct{})}
	s.mux.HandleFunc("GET /{$}", s.handleOverview)
	s.mux.HandleFunc("GET /requests", s.handleRequests)
	s.mux.HandleFunc("GET /secrets", s.handleSecrets)
	s.mux.HandleFunc("GET /fragments/requests", s.handleRequestsRows)
	s.mux.HandleFunc("GET /fragments/secrets", s.handleSecretsRows)
	s.mux.HandleFunc("GET /requests/{id}", s.handleRequestDetail)
	s.mux.HandleFunc("GET /requests/{id}/reveal", s.handleRequestReveal)
	s.mux.HandleFunc("GET /secrets/{id}/reveal", s.handleReveal)
	s.mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetFS))))
	s.srv = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	return s, nil
}

// Handler returns the dashboard as an http.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Serve runs the dashboard on ln until the listener is closed or Stop is
// called. The caller binds ln so a bind failure surfaces synchronously.
func (s *Server) Serve(ln net.Listener) error {
	go s.purgeLoop()
	return s.srv.Serve(ln)
}

// Shutdown gracefully stops the dashboard HTTP server and the purge loop.
func (s *Server) Shutdown(ctx context.Context) error {
	s.Stop()
	return s.srv.Shutdown(ctx)
}

// Stop signals purgeLoop to exit. Safe to call more than once.
func (s *Server) Stop() { s.stop.Do(func() { close(s.done) }) }

// purgeLoop drops requests older than requestRetention, once at startup and
// hourly thereafter, until Stop is called.
func (s *Server) purgeLoop() {
	purge := func() {
		n, err := s.store.PurgeRequestsOlderThan(context.Background(), requestRetention)
		if err != nil {
			s.logger.Error("purge old requests", "err", err)
			return
		}
		if n > 0 {
			s.logger.Info("purged old requests", "count", n, "retention", requestRetention.String())
		}
	}
	purge()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			purge()
		case <-s.done:
			return
		}
	}
}

// servePage renders a tab. An in-page htmx swap gets the bare #dash fragment; a
// real browser navigation — first load, refresh, or history restore — gets the
// full HTML page, so the current tab survives a reload.
func (s *Server) servePage(w http.ResponseWriter, r *http.Request, tab string, data any) {
	htmxSwap := r.Header.Get("HX-Request") == "true" &&
		r.Header.Get("HX-History-Restore-Request") != "true"
	if htmxSwap {
		s.render(w, tab, data)
		return
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, tab, data); err != nil {
		s.logger.Error("render template", "template", tab, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// #nosec G203 -- buf holds our own freshly rendered, trusted template output
	s.render(w, "page", template.HTML(buf.String()))
}

type overviewVM struct {
	Stats  store.Stats
	Recent []store.RequestRow
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	recent, err := s.store.ListRequests(r.Context(), 8)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.servePage(w, r, "overview", overviewVM{Stats: st, Recent: recent})
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListRequests(r.Context(), 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.servePage(w, r, "requests", rows)
}

// handleRequestsRows serves the requests table on its own — polled in place so
// the surrounding scroll position is preserved.
func (s *Server) handleRequestsRows(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListRequests(r.Context(), 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "requests_rows", rows)
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.servePage(w, r, "secrets", secrets)
}

// handleSecretsRows serves the secrets table on its own for in-place polling.
func (s *Server) handleSecretsRows(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "secrets_rows", secrets)
}

func (s *Server) handleRequestDetail(w http.ResponseWriter, r *http.Request) {
	s.renderDetail(w, r, false)
}

func (s *Server) handleRequestReveal(w http.ResponseWriter, r *http.Request) {
	s.renderDetail(w, r, true)
}

type detailVM struct {
	R        *store.RequestDetail
	ReqBody  template.HTML
	RespBody template.HTML
	HasReq   bool
	HasResp  bool
	Revealed bool
}

// renderDetail builds the per-request debug view. When reveal is set the
// captured masked bodies are unmasked back to plaintext for inspection.
func (s *Server) renderDetail(w http.ResponseWriter, r *http.Request, reveal bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetRequest(r.Context(), id)
	if err != nil {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	originals := make(map[string]string, len(d.Secrets))
	if reveal {
		for _, sec := range d.Secrets {
			orig, err := s.store.RevealSecret(r.Context(), sec.ID)
			if err != nil {
				s.fail(w, err)
				return
			}
			originals[sec.Mask] = orig
		}
	}
	vm := detailVM{R: d, Revealed: reveal}
	vm.ReqBody, vm.HasReq = bodyHTML(d.ReqBody, d.Secrets, originals, reveal)
	vm.RespBody, vm.HasResp = bodyHTML(d.RespBody, d.Secrets, originals, reveal)
	s.servePage(w, r, "request_detail", vm)
}

// bodyHTML pretty-prints a captured body, HTML-escapes it, and wraps every
// secret occurrence in a <mark> so the masking is visible at a glance. When
// reveal is set, masks are first swapped back to their plaintext originals.
func bodyHTML(raw []byte, secrets []store.SecretMeta, originals map[string]string, reveal bool) (template.HTML, bool) {
	if len(raw) == 0 {
		return "", false
	}
	text := raw
	if reveal {
		swapped := string(raw)
		for _, sec := range secrets {
			if orig := originals[sec.Mask]; orig != "" {
				swapped = strings.ReplaceAll(swapped, sec.Mask, orig)
			}
		}
		text = []byte(swapped)
	}
	if json.Valid(text) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, text, "", "  "); err == nil {
			text = buf.Bytes()
		}
	}
	out := html.EscapeString(string(text))
	for _, sec := range secrets {
		needle, cls := sec.Mask, "mark-mask"
		if reveal {
			needle, cls = originals[sec.Mask], "mark-orig"
		}
		if needle == "" {
			continue
		}
		esc := html.EscapeString(needle)
		out = strings.ReplaceAll(out, esc, `<mark class="`+cls+`">`+esc+`</mark>`)
	}
	return template.HTML(out), true // #nosec G203 -- out is HTML-escaped; only hardcoded <mark> tags are injected
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad secret id", http.StatusBadRequest)
		return
	}
	value, err := s.store.RevealSecret(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "reveal", value)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("render template", "template", name, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.logger.Error("request handler failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

