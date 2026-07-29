// Package dashboard serves the embedded realtime web UI: a three-pane local
// view of the secret store and the proxied request history with per-request
// debugging.
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pratikbin/opensecretmask/internal/history"
	"github.com/pratikbin/opensecretmask/internal/store"
)

//go:embed templates/*.html assets/*
var content embed.FS

// recentRequestsLimit caps how many recent requests the list pane shows.
const recentRequestsLimit = 200

// topSecretsLimit caps how many secrets the left rail's hot-list shows.
const topSecretsLimit = 6

// Server is the dashboard HTTP server.
type Server struct {
	store   *store.Store
	history *history.Recorder
	tmpl    *template.Template
	mux     *http.ServeMux
	srv     *http.Server
	logger  *slog.Logger
}

// NewServer parses the embedded templates and wires the dashboard routes. rec
// may be nil; it is read only for the dropped-record count. Retention is not
// the dashboard's business — the history recorder enforces it for as long as
// the process runs, whether or not anyone has this page open.
func NewServer(st *store.Store, rec *history.Recorder, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	tmpl, err := template.New("dashboard").Funcs(template.FuncMap{
		"providerDot": providerDot,
	}).ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, err
	}
	assetFS, err := fs.Sub(content, "assets")
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, history: rec, tmpl: tmpl, mux: http.NewServeMux(), logger: logger}
	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.HandleFunc("GET /requests", s.handleHome)
	s.mux.HandleFunc("GET /requests/{id}", s.handleRequest)
	s.mux.HandleFunc("GET /requests/{id}/reveal", s.handleRequestReveal)
	s.mux.HandleFunc("GET /fragments/requests", s.handleListRows)
	s.mux.HandleFunc("GET /fragments/detail/{id}", s.handleDetailPane)
	s.mux.HandleFunc("GET /fragments/detail/{id}/reveal", s.handleDetailPaneReveal)
	s.mux.HandleFunc("GET /secrets", s.handleSecrets)
	s.mux.HandleFunc("GET /fragments/secrets", s.handleSecretsRows)
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

// Serve runs the dashboard on ln until the listener is closed or Shutdown is
// called. The caller binds ln so a bind failure surfaces synchronously.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(ln)
}

// Shutdown gracefully stops the dashboard HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// servePage renders a tab. An in-page htmx swap gets the bare #dash fragment;
// a real browser navigation — first load, refresh, or history restore — gets
// the full HTML page, so deep-links and refreshes survive.
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

// providerCount is one provider's traffic count derived from the most recent
// request list — loose live aggregation that needs no new SQL.
type providerCount struct {
	Name  string
	Count int
}

// providerDot maps a provider name to a Tailwind background colour class so
// the rail and list rows can carry a tiny consistent colour marker per
// provider without spilling style into templates.
func providerDot(name string) string {
	switch name {
	case "anthropic":
		return "bg-primary"
	case "openai":
		return "bg-success"
	case "perplexity":
		return "bg-warning"
	case "groq":
		return "bg-error"
	case "google", "gemini":
		return "bg-info"
	case "":
		return "bg-base-content/30"
	default:
		return "bg-secondary"
	}
}

func providerCountsFrom(rows []store.RequestRow) []providerCount {
	m := map[string]int{}
	for _, r := range rows {
		m[r.Provider]++
	}
	out := make([]providerCount, 0, len(m))
	for k, v := range m {
		out = append(out, providerCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// inspectorVM is the full view-model for the 3-pane inspector page.
type inspectorVM struct {
	Stats      store.Stats
	Requests   []store.RequestRow
	Providers  []providerCount
	TopSecrets []store.SecretMeta
	Detail     *detailVM
	// Dropped is history discarded under write saturation, counted in this
	// process. It is shown only when non-zero — a silent gap in the log would
	// otherwise read as "nothing happened".
	Dropped int64
}

// detailVM is the right-pane content for one request.
type detailVM struct {
	R         *store.RequestDetail
	ReqBody   template.HTML
	RespBody  template.HTML
	HasReq    bool
	HasResp   bool
	Revealed  bool
	Originals map[string]string // mask → plaintext; populated only when Revealed
}

func (s *Server) buildInspectorVM(ctx context.Context) (*inspectorVM, error) {
	st, err := s.store.Stats(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListRequests(ctx, recentRequestsLimit)
	if err != nil {
		return nil, err
	}
	secrets, err := s.store.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].Hits != secrets[j].Hits {
			return secrets[i].Hits > secrets[j].Hits
		}
		return secrets[i].Name < secrets[j].Name
	})
	if len(secrets) > topSecretsLimit {
		secrets = secrets[:topSecretsLimit]
	}
	return &inspectorVM{
		Stats:      st,
		Requests:   rows,
		Providers:  providerCountsFrom(rows),
		TopSecrets: secrets,
		Dropped:    s.history.Dropped(),
	}, nil
}

func (s *Server) buildDetailVM(ctx context.Context, id int64, reveal bool) (*detailVM, error) {
	d, err := s.store.GetRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	originals := make(map[string]string, len(d.Secrets))
	if reveal {
		for _, sec := range d.Secrets {
			orig, err := s.store.RevealSecret(ctx, sec.ID)
			if err != nil {
				return nil, err
			}
			originals[sec.Mask] = orig
		}
	}
	vm := &detailVM{R: d, Revealed: reveal, Originals: originals}
	vm.ReqBody, vm.HasReq = bodyHTML(d.ReqBody, d.Secrets, originals, reveal)
	vm.RespBody, vm.HasResp = bodyHTML(d.RespBody, d.Secrets, originals, reveal)
	return vm, nil
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	vm, err := s.buildInspectorVM(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.servePage(w, r, "inspector", vm)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.renderRequest(w, r, false)
}

func (s *Server) handleRequestReveal(w http.ResponseWriter, r *http.Request) {
	s.renderRequest(w, r, true)
}

// renderRequest serves /requests/{id} (and its reveal variant) as a full
// inspector page with the right pane populated. Used for deep-links, refreshes,
// and the htmx full-#dash swap path; row clicks use the lighter /fragments/detail
// route below.
func (s *Server) renderRequest(w http.ResponseWriter, r *http.Request, reveal bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	d, err := s.buildDetailVM(r.Context(), id, reveal)
	if err != nil {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	vm, err := s.buildInspectorVM(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	vm.Detail = d
	s.servePage(w, r, "inspector", vm)
}

func (s *Server) handleDetailPane(w http.ResponseWriter, r *http.Request) {
	s.renderDetailPane(w, r, false)
}

func (s *Server) handleDetailPaneReveal(w http.ResponseWriter, r *http.Request) {
	s.renderDetailPane(w, r, true)
}

// renderDetailPane serves the right-pane content only — used by row clicks so
// the surrounding rail / list / scroll position are untouched.
func (s *Server) renderDetailPane(w http.ResponseWriter, r *http.Request, reveal bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	d, err := s.buildDetailVM(r.Context(), id, reveal)
	if err != nil {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	s.render(w, "detail_pane", d)
}

func (s *Server) handleListRows(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListRequests(r.Context(), recentRequestsLimit)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "list_rows", rows)
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.servePage(w, r, "secrets", secrets)
}

func (s *Server) handleSecretsRows(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.store.ListSecrets(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "secrets_rows", secrets)
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
