// Package mockupstream is a hermetic TLS upstream used by the integration
// and e2e suites to stand in for an LLM API. Its leaf certificate is signed
// by the supplied osm CA so an osm proxy that auto-trusts its own CA
// upstream accepts the handshake without any extra wiring.
package mockupstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/pratikbin/opensecretmask/internal/proxy"
)

// Server is the mock upstream. Every request that is not for the diagnostic
// `/__last_body` endpoint has its body recorded and echoed back as the
// response, so a test can assert both what the proxy forwarded (mask check)
// and what the client received after unmasking (round-trip check).
type Server struct {
	URL  string
	Host string

	srv *http.Server

	mu       sync.Mutex
	lastBody []byte
}

// New binds 127.0.0.1:port (0 picks an ephemeral port), mints a TLS leaf for
// 127.0.0.1, ::1 and "localhost" signed by ca, and starts serving in a
// background goroutine. The returned Server's Host is the bound listen
// address.
func New(ca *proxy.CA, port int) (*Server, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, errors.New("mockupstream: nil CA")
	}
	tlsCert, err := mintLeaf(ca)
	if err != nil {
		return nil, err
	}

	rawLn, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	ln := tls.NewListener(rawLn, tlsCfg)

	s := &Server{
		Host: rawLn.Addr().String(),
		URL:  "https://" + rawLn.Addr().String(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__last_body", s.handleLastBody)
	mux.HandleFunc("/", s.handleEcho)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func mintLeaf(ca *proxy.CA) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mockupstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}, nil
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	s.mu.Lock()
	s.lastBody = body
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleLastBody(w http.ResponseWriter, _ *http.Request) {
	body := s.LastBody()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

// LastBody returns a copy of the most recent echo-handler request body, or
// nil if none have arrived.
func (s *Server) LastBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastBody == nil {
		return nil
	}
	out := make([]byte, len(s.lastBody))
	copy(out, s.lastBody)
	return out
}

// Close drains in-flight requests and stops the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}
