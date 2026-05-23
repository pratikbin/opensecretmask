package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/engine"
)

type Options struct {
	Bind      string
	Upstream  string
	SessionID string
}

type Server struct {
	eng    *engine.Engine
	opts   Options
	revrxy *httputil.ReverseProxy
	upURL  *url.URL
	listen net.Listener
}

func New(eng *engine.Engine, opts Options) (*Server, error) {
	if opts.Upstream == "" {
		return nil, errors.New("proxy: Upstream required")
	}
	u, err := url.Parse(opts.Upstream)
	if err != nil {
		return nil, err
	}
	if opts.SessionID == "" {
		opts.SessionID = "proxy"
	}

	rw := &Rewriter{Engine: eng, Upstream: u, SessionID: opts.SessionID}
	rs := &Responder{Engine: eng}

	rev := &httputil.ReverseProxy{
		Director:       rw.Director,
		ModifyResponse: rs.Modify,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			IdleConnTimeout:   90 * time.Second,
		},
		FlushInterval: -1,
	}

	return &Server{eng: eng, opts: opts, revrxy: rev, upURL: u}, nil
}

func (s *Server) Listen() error {
	bind := s.opts.Bind
	if bind == "" {
		bind = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	s.listen = l
	return nil
}

func (s *Server) Addr() string {
	if s.listen == nil {
		return ""
	}
	return s.listen.Addr().String()
}

func (s *Server) Serve(ctx context.Context) error {
	if s.listen == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	srv := &http.Server{
		Handler:           s.revrxy,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(s.listen); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
