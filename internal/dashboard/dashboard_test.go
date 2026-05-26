package dashboard_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func newTestServer(t *testing.T) (*dashboard.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	srv, err := dashboard.NewServer(st, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, st
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// getHX issues a request that looks like an in-page htmx swap.
func getHX(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("HX-Request", "true")
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestDashboardIndex(t *testing.T) {
	srv, _ := newTestServer(t)
	code, body := get(t, srv.Handler(), "/")
	if code != http.StatusOK {
		t.Fatalf("index status = %d", code)
	}
	if !strings.Contains(body, "opensecretmask") {
		t.Fatal("index missing title")
	}
	if !strings.Contains(body, "hx-get") {
		t.Fatal("index missing htmx wiring")
	}
}

// TestDashboardTabPersistence verifies that a real browser navigation (no
// HX-Request header) gets a full page so a refresh keeps the current tab,
// while an in-page htmx swap gets only the #dash fragment.
func TestDashboardTabPersistence(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()

	for _, path := range []string{"/", "/requests", "/secrets"} {
		_, full := get(t, h, path)
		if !strings.Contains(full, "<!doctype html>") {
			t.Fatalf("browser GET %s should return a full page", path)
		}
		_, frag := getHX(t, h, path)
		if strings.Contains(frag, "<!doctype html>") {
			t.Fatalf("htmx GET %s should return only the fragment", path)
		}
		if !strings.Contains(frag, `id="dash"`) {
			t.Fatalf("htmx GET %s fragment missing #dash root", path)
		}
	}
}

func TestDashboardTabsAndDebug(t *testing.T) {
	srv, st := newTestServer(t)
	const original = "sk-ant-jjhg-joiibe-ljioc-8088"
	const masked = "sk-ant-bteyavngogmphqri2758983"
	secID, err := st.PutSecret(t.Context(), store.Secret{
		Name: "ANTHROPIC_API_KEY", Source: "registered",
		Original: original, Mask: masked, Shape: "shape",
	})
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	body := []byte(`{"messages":[{"content":"my key ` + masked + ` here"}]}`)
	reqID, err := st.LogRequest(t.Context(), store.RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com",
		Method: "POST", Path: "/v1/messages", Status: 200, Masked: 1,
		ReqBody: body, RespBody: body,
	}, []int64{secID})
	if err != nil {
		t.Fatalf("LogRequest: %v", err)
	}

	h := srv.Handler()

	if code, b := get(t, h, "/"); code != 200 || !strings.Contains(b, "Secrets") {
		t.Fatalf("overview: code=%d body=%s", code, b)
	}
	if _, b := get(t, h, "/requests"); !strings.Contains(b, "/v1/messages") {
		t.Fatalf("requests tab missing the logged request: %s", b)
	}
	// The polled rows fragment carries the table without a page shell.
	if _, b := get(t, h, "/fragments/requests"); !strings.Contains(b, "/v1/messages") ||
		strings.Contains(b, "<!doctype html>") {
		t.Fatalf("requests rows fragment wrong: %s", b)
	}

	// The secrets tab must show the mask but never the plaintext original.
	_, secrets := get(t, h, "/secrets")
	if !strings.Contains(secrets, masked) {
		t.Fatalf("secrets tab missing the mask: %s", secrets)
	}
	if strings.Contains(secrets, original) {
		t.Fatal("secrets tab leaked the plaintext original")
	}

	idStr := strconv.FormatInt(reqID, 10)

	// The masked request detail shows the masked body, never the original.
	code, detail := get(t, h, "/requests/"+idStr)
	if code != 200 {
		t.Fatalf("request detail status = %d", code)
	}
	if !strings.Contains(detail, masked) {
		t.Fatalf("detail missing the masked body: %s", detail)
	}
	if strings.Contains(detail, original) {
		t.Fatal("masked detail leaked the plaintext original")
	}

	// Reveal explicitly unmasks the captured body back to the original.
	code, revealed := get(t, h, "/requests/"+idStr+"/reveal")
	if code != 200 {
		t.Fatalf("request reveal status = %d", code)
	}
	if !strings.Contains(revealed, original) {
		t.Fatalf("request reveal did not unmask the body: %s", revealed)
	}

	// The per-secret reveal endpoint still returns the original.
	code, secReveal := get(t, h, "/secrets/"+strconv.FormatInt(secID, 10)+"/reveal")
	if code != 200 || !strings.Contains(secReveal, original) {
		t.Fatalf("secret reveal: code=%d body=%s", code, secReveal)
	}
}

func TestDashboardBadRequestID(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	if code, _ := get(t, h, "/requests/not-a-number"); code != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", code)
	}
	if code, _ := get(t, h, "/requests/99999"); code != http.StatusNotFound {
		t.Fatalf("missing request status = %d, want 404", code)
	}
}

// TestDashboardServeShutdown verifies that Serve + Shutdown terminates cleanly
// with no goroutine leaks (purgeLoop must exit via the done channel).
func TestDashboardServeShutdown(t *testing.T) {
	srv, _ := newTestServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*000_000_000) // 5 s
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if err := <-serveErr; err != http.ErrServerClosed {
		t.Fatalf("Serve returned %v, want http.ErrServerClosed", err)
	}
}
