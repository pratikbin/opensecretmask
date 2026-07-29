package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/daemon"
)

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Stop the running daemon and respawn it with the current binary",
		Long: "Sends SIGTERM to the running daemon, waits for clean exit, then\n" +
			"respawns with the same listen / dashboard / provider / entropy /\n" +
			"log-level config preserved in proxy.pid. Use after rebuilding the\n" +
			"binary to pick up changes (dashboard tweaks, new detection rules)\n" +
			"without losing the daemon's spawn configuration.\n\n" +
			"A record left behind by a daemon that died uncleanly is not an\n" +
			"error: restart clears it and brings a fresh daemon up on the same\n" +
			"addresses.\n\n" +
			"Requires $OSM_KEY in the environment (or a TTY for the prompt) —\n" +
			"the fresh daemon must re-unlock the store.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			// Cheap existence check before the prompt: never ask for a
			// passphrase when there is nothing to restart.
			if p, _ := daemon.Status(home); p == nil {
				return errors.New("no running daemon to restart (start with 'osm run')")
			}
			key, kerr := passphrase()
			if kerr != nil {
				return kerr
			}
			np, rerr := daemon.Restart(home, key)
			if rerr != nil {
				if errors.Is(rerr, daemon.ErrNoDaemon) {
					return errors.New("no running daemon to restart (start with 'osm run')")
				}
				return rerr
			}
			fmt.Fprintf(os.Stderr, "osm: restarted daemon pid=%d proxy=http://%s dashboard=http://%s\n",
				np.PID, np.ProxyAddr, np.DashAddr)
			return nil
		},
	}
}
