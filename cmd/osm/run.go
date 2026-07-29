package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/proxy"
)

// watchdogInterval is how often 'osm run' probes the daemon's TCP listener
// while the child is alive. Set short enough that a silent daemon SIGKILL
// causes only ~1 retry's worth of failed requests in the child before the
// listener is back up on the same address.
const watchdogInterval = 2 * time.Second

func runCmd() *cobra.Command {
	var (
		listen        string
		dash          string
		extra         []string
		entropy       bool
		logLevel      string
		allowExternal bool
	)
	cmd := &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "Run a command with its TLS traffic masked through an osm proxy",
		Long: "run executes a command — an LLM agent, a shell, a script — with its\n" +
			"HTTP-proxy and CA-trust environment variables set so all of its TLS\n" +
			"traffic is routed through the osm masking proxy.\n\n" +
			"The first 'osm run' on a machine spawns a background 'osm proxy'\n" +
			"daemon and records its PID/address in $OPENSECRETMASK_HOME/proxy.pid.\n" +
			"Subsequent invocations reuse that daemon. If the daemon has died,\n" +
			"the next 'osm run' respawns it. The daemon outlives the child;\n" +
			"stop it manually with 'kill $(jq .pid < ~/.opensecretmask/proxy.pid)'.\n\n" +
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

			// Fast path: a healthy daemon is recorded — skip the passphrase
			// prompt entirely and reuse it. The daemon already has the store
			// unlocked from its own startup.
			p, _ := readPidFile(home)
			var osmKey string
			opts := daemonOpts{extra: extra, entropy: entropy, logLevel: logLevel, allowExternal: allowExternal}
			if !daemonHealthy(p) {
				if err := validateListenAddr(listen, allowExternal); err != nil {
					return err
				}
				if err := validateListenAddr(dash, allowExternal); err != nil {
					return err
				}
				key, kerr := passphrase()
				if kerr != nil {
					return kerr
				}
				osmKey = key
				np, _, derr := ensureDaemon(home, listen, dash, key, opts)
				if derr != nil {
					return derr
				}
				p = np
				fmt.Fprintf(os.Stderr, "osm: started daemon pid=%d proxy=http://%s dashboard=http://%s\n",
					p.PID, p.ProxyAddr, p.DashAddr)
			} else {
				// Reuse path: prefer $OSM_KEY for silent watchdog respawn. If
				// unset, the daemon is still usable now but a mid-session
				// death will require a manual restart with $OSM_KEY exported.
				osmKey = os.Getenv(keyEnv)
				fmt.Fprintf(os.Stderr, "osm: reusing daemon pid=%d proxy=http://%s\n", p.PID, p.ProxyAddr)
				if osmKey == "" {
					fmt.Fprintf(os.Stderr, "osm: warning — $OSM_KEY unset; daemon auto-respawn disabled. Export OSM_KEY to enable.\n")
				}
				// Inherit prior spawn config so a respawn produces the same
				// listener addresses, providers, entropy and log level.
				opts.extra = p.Extra
				opts.entropy = p.Entropy
				if p.LogLevel != "" {
					opts.logLevel = p.LogLevel
				}
				opts.allowExternal = p.AllowExternal
			}

			proxyURL := "http://" + p.ProxyAddr
			fmt.Fprintf(os.Stderr, "osm: routing %s through %s\n", args[0], proxyURL)

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

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			var wg sync.WaitGroup
			wg.Go(func() {
				watchDaemon(ctx, home, p, osmKey, opts)
			})

			code, rerr := runChild(bin, args, env)
			cancel()
			wg.Wait()
			if rerr != nil {
				return rerr
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", proxyListen, "proxy listen address (only used when spawning daemon)")
	cmd.Flags().StringVar(&dash, "dashboard", dashListen, "dashboard listen address (only used when spawning daemon)")
	cmd.Flags().StringArrayVar(&extra, "provider", nil, "extra host to intercept when spawning daemon (host or host=dialect)")
	cmd.Flags().BoolVar(&entropy, "detect-entropy", false, "also mask high-entropy tokens when spawning daemon")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "proxy log verbosity when spawning daemon: debug, info, warn, error")
	cmd.Flags().BoolVar(&allowExternal, "allow-external-bind", false,
		"allow non-loopback listener binds when spawning the daemon (dangerous)")
	// Stop flag parsing at the first positional so flags meant for the child
	// command (e.g. 'osm run claude --resume') are passed through untouched.
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runChild runs the wrapped command with the prepared environment, inheriting
// stdio and forwarding termination signals, and returns its exit code. osm
// stays alive as the parent so signals reach the child cleanly — unlike
// syscall.Exec, which would replace osm entirely.
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

// watchDaemon polls the daemon's TCP listener while the child is alive and
// respawns it on the same address if it disappears (silent SIGKILL, macOS
// sudden_termination on sleep, manual kill). Because the child inherits a
// fixed HTTPS_PROXY URL pointing at p.ProxyAddr, the respawn must rebind
// that exact address — passing it explicitly to ensureDaemon forces this.
//
// If osmKey is empty (reuse path with no $OSM_KEY in env), respawn is
// disabled: the new daemon would fail to unlock the store and exit, which
// would loop. The warning is logged once at startup in runCmd.
func watchDaemon(ctx context.Context, home string, p *pidInfo, osmKey string, opts daemonOpts) {
	if osmKey == "" {
		return
	}
	addr := p.ProxyAddr
	dash := p.DashAddr
	var inflight atomic.Bool
	// spawnWg drains any in-flight respawn goroutine before watchDaemon
	// returns, so the caller's wg.Wait() in runCmd doesn't race a child
	// goroutine still holding the daemon flock.
	var spawnWg sync.WaitGroup
	defer spawnWg.Wait()
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur, _ := readPidFile(home)
		if daemonHealthy(cur) {
			continue
		}
		// CompareAndSwap so a long respawn does not stack a second attempt.
		if !inflight.CompareAndSwap(false, true) {
			continue
		}
		// Re-check ctx after winning the CAS — cancellation may have
		// arrived while we were in readPidFile/daemonHealthy. Skipping the
		// spawn here avoids fork-exec during shutdown.
		select {
		case <-ctx.Done():
			inflight.Store(false)
			return
		default:
		}
		spawnWg.Go(func() {
			defer inflight.Store(false)
			fmt.Fprintf(os.Stderr, "osm: daemon died — respawning on %s\n", addr)
			np, _, err := ensureDaemon(home, addr, dash, osmKey, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "osm: respawn failed: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "osm: daemon respawned pid=%d\n", np.PID)
		})
	}
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
