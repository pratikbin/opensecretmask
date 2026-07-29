// Package proxyproc owns the proxy process's runtime: it constructs, binds,
// serves, drains, and tears down everything 'osm proxy' needs, in one place
// with one ordering.
//
// The package deliberately does not own daemon state. internal/daemon is the
// sole writer of the pidfile; this package receives Publish/Unpublish
// callbacks and decides only when they fire — after the listeners are bound,
// and after serving has stopped.
package proxyproc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/store"
)

// Config is everything the runtime needs from its caller.
type Config struct {
	// Home is $OPENSECRETMASK_HOME: the CA and the encrypted store live there.
	Home string
	// Listen and Dash are the proxy and dashboard bind addresses. ":0" is
	// supported — the bound address is reported back through Publish.
	Listen string
	Dash   string
	// ExtraProviders are additional hosts to intercept, "host" or
	// "host=dialect".
	ExtraProviders []string
	// Entropy enables high-entropy token detection alongside the rule set.
	Entropy bool
	// Logger receives runtime events; nil discards them.
	Logger *slog.Logger

	// Passphrase supplies the store key. It is a callback, not a string, so
	// the terminal prompt happens only after the cheap failures — a missing CA,
	// an uninitialized store — have been ruled out.
	Passphrase func() (string, error)

	// Publish records the bound addresses. Called once, after both listeners
	// bind and before serving begins, so a recorded address is always
	// reachable. The caller composes whatever record it keeps; the runtime
	// supplies only the facts it owns. Nil disables publication.
	Publish func(proxyAddr, dashAddr string) error
	// Unpublish removes that record. Called when Serve returns, whatever the
	// reason. Nil disables it.
	Unpublish func()
}

// Runtime is a constructed, bound, not-yet-serving proxy process.
type Runtime struct {
	cfg       Config
	logger    *slog.Logger
	store     *store.Store
	providers []proxy.Provider
	pxy       *proxy.Server
	dash      *dashboard.Server
	pxyLn     net.Listener
	dashLn    net.Listener
}

// Start acquires every resource the process needs, in dependency order, and
// leaves both listeners bound and the addresses published.
//
// Each acquisition registers its own undo step, so a failure at any point
// unwinds exactly what was acquired and nothing else. That is the whole reason
// this lives in one function: partial-startup cleanup is a single invariant,
// not four hand-written branches.
func Start(ctx context.Context, cfg Config) (*Runtime, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	var undo []func()
	rollback := func() {
		for _, i := range slices.Backward(undo) {
			i()
		}
	}

	ca, err := proxy.LoadCA(cfg.Home)
	if err != nil {
		return nil, fmt.Errorf("load CA — run 'osm init' first: %w", err)
	}

	// Store construction and unlock. This repeats cmd/osm's openUnlocked by
	// design: that helper prompts for the passphrase itself, which a runtime
	// must never do, and package main cannot be imported. The interactive
	// commands (add, preload, status) keep using theirs.
	st, err := store.Open(ctx, storePath(cfg.Home))
	if err != nil {
		return nil, err
	}
	undo = append(undo, func() { _ = st.Close() })

	ok, err := st.Initialized(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !ok {
		rollback()
		return nil, errors.New("not initialized — run 'osm init' first")
	}
	if cfg.Passphrase == nil {
		rollback()
		return nil, errors.New("proxyproc: Config.Passphrase is required")
	}
	pass, err := cfg.Passphrase()
	if err != nil {
		rollback()
		return nil, err
	}
	if err := st.Unlock(ctx, pass); err != nil {
		rollback()
		return nil, err
	}

	det, err := detect.New(detect.Config{Entropy: cfg.Entropy})
	if err != nil {
		rollback()
		return nil, err
	}
	m := mask.NewMasker(st, det)

	providers := slices.Clone(proxy.DefaultProviders)
	for _, p := range cfg.ExtraProviders {
		host, dialect, found := strings.Cut(p, "=")
		if !found {
			dialect = "custom"
		}
		providers = append(providers, proxy.Provider{Host: host, Dialect: dialect})
	}

	// Both listeners bind before anything is published: with ":0" this process
	// is the only party that can learn the real addresses, and a published
	// address must always be reachable.
	pxyLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("proxy listen on %s: %w", cfg.Listen, err)
	}
	undo = append(undo, func() { _ = pxyLn.Close() })

	dashLn, err := net.Listen("tcp", cfg.Dash)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("dashboard listen on %s: %w", cfg.Dash, err)
	}
	undo = append(undo, func() { _ = dashLn.Close() })

	dashSrv, err := dashboard.NewServer(st, logger)
	if err != nil {
		rollback()
		return nil, err
	}
	pxy := proxy.NewServer(proxy.Config{
		Providers: providers,
		CA:        ca,
		Masker:    m,
		Store:     st,
		Logger:    logger,
	})

	if cfg.Publish != nil {
		if err := cfg.Publish(pxyLn.Addr().String(), dashLn.Addr().String()); err != nil {
			rollback()
			return nil, fmt.Errorf("publish daemon state: %w", err)
		}
	}

	return &Runtime{
		cfg: cfg, logger: logger, store: st, providers: providers,
		pxy: pxy, dash: dashSrv, pxyLn: pxyLn, dashLn: dashLn,
	}, nil
}

func storePath(home string) string { return filepath.Join(home, "osm.db") }

// ProxyAddr is the bound proxy address — concrete even when Listen was ":0".
func (r *Runtime) ProxyAddr() string { return r.pxyLn.Addr().String() }

// DashAddr is the bound dashboard address.
func (r *Runtime) DashAddr() string { return r.dashLn.Addr().String() }

// Providers is the effective interception policy: the defaults plus the
// configured extras. Exposed for startup logging and tests.
func (r *Runtime) Providers() []proxy.Provider { return slices.Clone(r.providers) }
