package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// stopTimeout bounds how long 'osm restart' waits for the old daemon to exit
// after SIGTERM before giving up. Old daemon must drain in-flight requests
// (proxy.shutdownTimeout = 10s) plus its own teardown.
const stopTimeout = 15 * time.Second

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Stop the running daemon and respawn it with the current binary",
		Long: "Sends SIGTERM to the running daemon, waits for clean exit, then\n" +
			"respawns with the same listen / dashboard / provider / entropy /\n" +
			"log-level config preserved in proxy.pid. Use after rebuilding the\n" +
			"binary to pick up changes (dashboard tweaks, new detection rules)\n" +
			"without losing the daemon's spawn configuration.\n\n" +
			"Requires $OSM_KEY in the environment (or a TTY for the prompt) —\n" +
			"the fresh daemon must re-unlock the store.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			p, err := readPidFile(home)
			if err != nil {
				return fmt.Errorf("no running daemon to restart (start with 'osm run'): %w", err)
			}
			if !processAlive(p.PID) {
				_ = removePidFile(home)
				return fmt.Errorf("daemon pid=%d not running — stale pidfile cleared; start with 'osm run'", p.PID)
			}

			key, kerr := passphrase()
			if kerr != nil {
				return kerr
			}

			fmt.Fprintf(os.Stderr, "osm: stopping daemon pid=%d\n", p.PID)
			if err := syscall.Kill(p.PID, syscall.SIGTERM); err != nil {
				return fmt.Errorf("signal daemon: %w", err)
			}
			if err := waitForExit(home, p.PID, stopTimeout); err != nil {
				return err
			}

			opts := daemonOpts{extra: p.Extra, entropy: p.Entropy, logLevel: p.LogLevel, allowExternal: p.AllowExternal}
			if opts.logLevel == "" {
				opts.logLevel = "info"
			}
			np, _, derr := ensureDaemon(home, p.ProxyAddr, p.DashAddr, key, opts)
			if derr != nil {
				return derr
			}
			fmt.Fprintf(os.Stderr, "osm: restarted daemon pid=%d proxy=http://%s dashboard=http://%s\n",
				np.PID, np.ProxyAddr, np.DashAddr)
			return nil
		},
	}
}

// waitForExit polls until the old daemon is gone — both the process is dead
// and the pidfile is removed (clean SIGTERM does this via deferred cleanup
// in proxyCmd). Without the pidfile-gone check, ensureDaemon would see the
// stale entry and skip respawning.
func waitForExit(home string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive := processAlive(pid)
		_, perr := readPidFile(home)
		if !alive && perr != nil {
			return nil
		}
		time.Sleep(daemonPollInterval)
	}
	return fmt.Errorf("daemon pid=%d did not exit within %s", pid, timeout)
}
