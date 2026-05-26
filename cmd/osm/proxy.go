package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/proxy"
)

// shutdownTimeout bounds how long in-flight requests get to drain on Ctrl-C.
const shutdownTimeout = 10 * time.Second

func proxyCmd() *cobra.Command {
	var (
		listen   string
		dash     string
		extra    []string
		entropy  bool
		logLevel string
	)
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the masking proxy and dashboard",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger, err := newLogger(os.Stderr, logLevel)
			if err != nil {
				return err
			}
			home, err := homeDir()
			if err != nil {
				return err
			}
			ca, err := proxy.LoadCA(home)
			if err != nil {
				return fmt.Errorf("load CA — run 'osm init' first: %w", err)
			}
			st, err := openUnlocked(cmd.Context(), home)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			m, err := newMasker(st, entropy)
			if err != nil {
				return err
			}

			providers := slices.Clone(proxy.DefaultProviders)
			for _, p := range extra {
				host, dialect, ok := strings.Cut(p, "=")
				if !ok {
					dialect = "custom"
				}
				providers = append(providers, proxy.Provider{Host: host, Dialect: dialect})
			}

			// Bind both listeners up front so the actual addresses can be
			// recorded in the pidfile — 'osm run' reads that file to discover
			// where to send traffic. Supports :0 ephemeral ports.
			pxyLn, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("proxy listen on %s: %w", listen, err)
			}
			dashLn, err := net.Listen("tcp", dash)
			if err != nil {
				_ = pxyLn.Close()
				return fmt.Errorf("dashboard listen on %s: %w", dash, err)
			}
			proxyAddr := pxyLn.Addr().String()
			dashAddr := dashLn.Addr().String()

			dashSrv, err := dashboard.NewServer(st, logger)
			if err != nil {
				_ = pxyLn.Close()
				_ = dashLn.Close()
				return err
			}
			pxy := proxy.NewServer(proxy.Config{
				Providers: providers,
				CA:        ca,
				Masker:    m,
				Store:     st,
				Logger:    logger,
			})

			// Pidfile is the single source of truth that 'osm run' polls for
			// daemon discovery. Written after listeners bind, removed on
			// shutdown so a clean exit leaves no stale record.
			if err := writePidFile(home, pidInfo{
				PID:       os.Getpid(),
				ProxyAddr: proxyAddr,
				DashAddr:  dashAddr,
				StartedAt: time.Now(),
				Extra:     extra,
				Entropy:   entropy,
				LogLevel:  logLevel,
			}); err != nil {
				_ = pxyLn.Close()
				_ = dashLn.Close()
				return fmt.Errorf("write pidfile: %w", err)
			}
			defer func() { _ = removePidFile(home) }()

			logger.Info("proxy listening", "addr", proxyAddr, "dashboard", "http://"+dashAddr)
			for _, p := range providers {
				paths := "all"
				if len(p.Paths) > 0 {
					paths = strings.Join(p.Paths, ",")
				}
				logger.Info("intercepting", "host", p.Host, "dialect", p.Dialect, "paths", paths)
			}

			// Drain in-flight requests on Ctrl-C / SIGTERM instead of dropping
			// them: cancel ctx on signal, then Shutdown both servers.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			g, gctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				if err := pxy.Serve(pxyLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			})
			g.Go(func() error {
				if err := dashSrv.Serve(dashLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			})
			g.Go(func() error {
				<-gctx.Done()
				sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()
				logger.Info("shutting down, draining requests")
				if err := pxy.Shutdown(sctx); err != nil {
					logger.Error("proxy shutdown", "err", err)
				}
				if err := dashSrv.Shutdown(sctx); err != nil {
					logger.Error("dashboard shutdown", "err", err)
				}
				return nil
			})
			return g.Wait()
		},
	}
	cmd.Flags().StringVar(&listen, "listen", proxyListen, "proxy listen address")
	cmd.Flags().StringVar(&dash, "dashboard", dashListen, "dashboard listen address")
	cmd.Flags().StringArrayVar(&extra, "provider", nil, "extra host to intercept (host or host=dialect)")
	cmd.Flags().BoolVar(&entropy, "detect-entropy", false, "also mask high-entropy tokens (may over-mask)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log verbosity: debug, info, warn, error")
	return cmd
}

// newLogger builds a slog text logger writing to w at the given level.
// Each line is tagged with the source file and line that emitted it.
func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "info":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q (want debug, info, warn, error)", level)
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     lv,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Shorten source from an absolute path to file:line.
			if a.Key == slog.SourceKey {
				if src, ok := a.Value.Any().(*slog.Source); ok {
					a.Value = slog.StringValue(filepath.Base(src.File) + ":" + strconv.Itoa(src.Line))
				}
			}
			return a
		},
	})
	return slog.New(h), nil
}
