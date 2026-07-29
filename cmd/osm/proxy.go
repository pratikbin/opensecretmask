package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/daemon"
	"github.com/pratikbin/opensecretmask/internal/history"
	"github.com/pratikbin/opensecretmask/internal/proxyproc"
)

func proxyCmd() *cobra.Command {
	var (
		listen           string
		dash             string
		extra            []string
		entropy          bool
		logLevel         string
		allowExternal    bool
		historyRetention string
	)
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the masking proxy and dashboard",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateListenAddr(listen, allowExternal); err != nil {
				return err
			}
			if err := validateListenAddr(dash, allowExternal); err != nil {
				return err
			}
			logger, err := newLogger(os.Stderr, logLevel)
			if err != nil {
				return err
			}
			retention, err := time.ParseDuration(historyRetention)
			if err != nil {
				return fmt.Errorf("invalid --history-retention %q: %w", historyRetention, err)
			}
			home, err := homeDir()
			if err != nil {
				return err
			}

			rt, err := proxyproc.Start(cmd.Context(), proxyproc.Config{
				Home:             home,
				Listen:           listen,
				Dash:             dash,
				ExtraProviders:   extra,
				Entropy:          entropy,
				HistoryRetention: retention,
				Logger:           logger,
				Passphrase:       passphrase,
				// The runtime knows the bound addresses; this adapter knows
				// the flags the daemon record must preserve for a respawn.
				Publish: func(proxyAddr, dashAddr string) error {
					return daemon.Publish(home, daemon.Info{
						PID:              os.Getpid(),
						ProxyAddr:        proxyAddr,
						DashAddr:         dashAddr,
						StartedAt:        time.Now(),
						Extra:            extra,
						Entropy:          entropy,
						LogLevel:         logLevel,
						AllowExternal:    allowExternal,
						HistoryRetention: historyRetention,
					})
				},
				Unpublish: func() { _ = daemon.Unpublish(home) },
			})
			if err != nil {
				return err
			}

			logger.Info("proxy listening", "addr", rt.ProxyAddr(), "dashboard", "http://"+rt.DashAddr())
			for _, p := range rt.Providers() {
				paths := "all"
				if len(p.Paths) > 0 {
					paths = strings.Join(p.Paths, ",")
				}
				logger.Info("intercepting", "host", p.Host, "dialect", p.Dialect, "paths", paths)
			}

			// Signal conversion belongs here, at the process edge: the runtime
			// takes cancellation, not signals.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return rt.Serve(ctx)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", proxyListen, "proxy listen address")
	cmd.Flags().StringVar(&dash, "dashboard", dashListen, "dashboard listen address")
	cmd.Flags().StringArrayVar(&extra, "provider", nil, "extra host to intercept (host or host=dialect)")
	cmd.Flags().BoolVar(&entropy, "detect-entropy", false, "also mask high-entropy tokens (may over-mask)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log verbosity: debug, info, warn, error")
	cmd.Flags().BoolVar(&allowExternal, "allow-external-bind", false,
		"allow --listen/--dashboard to bind non-loopback addresses (dangerous: unauthenticated proxy and reveal routes)")
	cmd.Flags().StringVar(&historyRetention, "history-retention", history.DefaultRetention.String(),
		"how long to keep captured request history; 0 disables purging")
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
