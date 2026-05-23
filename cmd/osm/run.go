package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pratikbin/opensecretmask/internal/dashboard"
	"github.com/pratikbin/opensecretmask/internal/proxy"
)

// proxyDialTimeout bounds the probe that decides whether a standalone
// 'osm proxy' daemon is already running and can be reused.
const proxyDialTimeout = 2 * time.Second

func runCmd() *cobra.Command {
	var (
		listen   string
		extra    []string
		entropy  bool
		logLevel string
	)
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "Run a command with its TLS traffic masked through an osm proxy",
		Long: "run executes a command — an LLM agent, a shell, a script — with its\n" +
			"HTTP-proxy and CA-trust environment variables set so all of its TLS\n" +
			"traffic is routed through the osm masking proxy.\n\n" +
			"If a standalone 'osm proxy' is already listening it is reused.\n" +
			"Otherwise run starts its own proxy and dashboard on ephemeral\n" +
			"loopback ports for the lifetime of the command and shuts them down\n" +
			"when it exits — nothing outside this one process is affected.\n\n" +
			"Trust is per-process: the env vars make Node, Python and curl trust\n" +
			"the osm CA without touching the system trust store.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			certPath, err := filepath.Abs(proxy.CertPath(home))
			if err != nil {
				return err
			}
			if _, err := os.Stat(certPath); err != nil {
				return fmt.Errorf("CA cert not found at %s — run 'osm init' first", certPath)
			}
			bin, err := exec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("command not found: %s", args[0])
			}

			// Reuse a running 'osm proxy' if one answers; otherwise spawn an
			// ephemeral proxy that lives only as long as the child command.
			proxyURL := "http://" + listen
			var cleanup func()
			if conn, derr := net.DialTimeout("tcp", listen, proxyDialTimeout); derr == nil {
				_ = conn.Close()
				fmt.Fprintf(os.Stderr, "osm: reusing proxy at %s\n", listen)
			} else {
				addr, cl, serr := startEphemeralProxy(cmd.Context(), home, extra, entropy, logLevel)
				if serr != nil {
					return serr
				}
				cleanup = cl
				proxyURL = "http://" + addr
			}

			env := withEnv(os.Environ(), map[string]string{
				"HTTP_PROXY":          proxyURL,
				"HTTPS_PROXY":         proxyURL,
				"http_proxy":          proxyURL,
				"https_proxy":         proxyURL,
				"NODE_EXTRA_CA_CERTS": certPath, // Claude Code and other Node tools
				"SSL_CERT_FILE":       certPath, // OpenSSL, Go, many Python tools
				"REQUESTS_CA_BUNDLE":  certPath, // Python requests
				"CURL_CA_BUNDLE":      certPath, // curl
			})

			fmt.Fprintf(os.Stderr, "osm: routing %s through %s\n", args[0], proxyURL)
			code, rerr := runChild(bin, args, env)
			// cleanup drains the ephemeral proxy; run it before os.Exit, which
			// would otherwise skip it.
			if cleanup != nil {
				cleanup()
			}
			if rerr != nil {
				return rerr
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", proxyListen, "address of an existing osm proxy to reuse")
	cmd.Flags().StringArrayVar(&extra, "provider", nil, "extra host to intercept when spawning own proxy (host or host=dialect)")
	cmd.Flags().BoolVar(&entropy, "detect-entropy", false, "also mask high-entropy tokens when spawning own proxy")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "proxy log verbosity when spawning own proxy: debug, info, warn, error")
	// Stop flag parsing at the first positional so flags meant for the child
	// command (e.g. 'osm run claude --resume') are passed through untouched.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// startEphemeralProxy brings up a masking proxy and dashboard on loopback
// ephemeral ports for a single 'osm run'. It returns the proxy address to point
// the child at and a cleanup func that drains both servers and closes the store.
func startEphemeralProxy(ctx context.Context, home string, extra []string, entropy bool, logLevel string) (string, func(), error) {
	// Proxy and dashboard logs go to a file, never stderr: stderr is shared
	// with the child, and a TUI agent's screen corrupts on interleaved logs.
	logPath := filepath.Join(home, "run.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return "", nil, fmt.Errorf("open run log: %w", err)
	}
	started := false
	defer func() {
		if !started {
			_ = logFile.Close()
		}
	}()
	logger, err := newLogger(logFile, logLevel)
	if err != nil {
		return "", nil, err
	}
	ca, err := proxy.LoadCA(home)
	if err != nil {
		return "", nil, fmt.Errorf("load CA — run 'osm init' first: %w", err)
	}
	st, err := openUnlocked(ctx, home)
	if err != nil {
		return "", nil, err
	}
	m, err := newMasker(st, entropy)
	if err != nil {
		_ = st.Close()
		return "", nil, err
	}

	providers := slices.Clone(proxy.DefaultProviders)
	for _, p := range extra {
		host, dialect, ok := strings.Cut(p, "=")
		if !ok {
			dialect = "custom"
		}
		providers = append(providers, proxy.Provider{Host: host, Dialect: dialect})
	}

	pxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = st.Close()
		return "", nil, fmt.Errorf("proxy listen: %w", err)
	}
	dashLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = pxyLn.Close()
		_ = st.Close()
		return "", nil, fmt.Errorf("dashboard listen: %w", err)
	}

	dashSrv, err := dashboard.NewServer(st, logger)
	if err != nil {
		_ = pxyLn.Close()
		_ = dashLn.Close()
		_ = st.Close()
		return "", nil, err
	}
	pxy := proxy.NewServer(proxy.Config{
		Providers: providers,
		CA:        ca,
		Masker:    m,
		Store:     st,
		Logger:    logger,
	})

	g := new(errgroup.Group)
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

	dashURL := "http://" + dashLn.Addr().String()
	logger.Info("ephemeral proxy started", "proxy", pxyLn.Addr().String(), "dashboard", dashURL)
	fmt.Fprintf(os.Stderr, "osm: dashboard %s · logs %s\n", dashURL, logPath)

	started = true
	cleanup := func() {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := pxy.Shutdown(sctx); err != nil {
			logger.Error("proxy shutdown", "err", err)
		}
		if err := dashSrv.Shutdown(sctx); err != nil {
			logger.Error("dashboard shutdown", "err", err)
		}
		if err := g.Wait(); err != nil {
			logger.Error("server group", "err", err)
		}
		_ = st.Close()
		_ = logFile.Close()
	}
	return pxyLn.Addr().String(), cleanup, nil
}

// runChild runs the wrapped command with the prepared environment, inheriting
// stdio and forwarding termination signals, and returns its exit code. osm
// stays alive as the parent so an in-process proxy survives until the child
// exits — unlike syscall.Exec, which would replace osm entirely.
func runChild(bin string, args, env []string) (int, error) {
	child := exec.Command(bin) // #nosec G204 -- running a user-specified command is the purpose of run
	child.Args = args
	child.Env = env
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return 0, fmt.Errorf("start %s: %w", args[0], err)
	}

	// Trap termination signals so osm is not killed before the child: forward
	// them on and let the child's own exit drive shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for sig := range sigs {
			_ = child.Process.Signal(sig)
		}
	}()

	err := child.Wait()
	signal.Stop(sigs)
	close(sigs)

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// withEnv returns base with the given keys overridden — any existing entries
// for those keys are dropped so the new values are unambiguous.
func withEnv(base []string, over map[string]string) []string {
	out := make([]string, 0, len(base)+len(over))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := over[k]; !ok {
			out = append(out, kv)
		}
	}
	for k, v := range over {
		out = append(out, k+"="+v)
	}
	return out
}

