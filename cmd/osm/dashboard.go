package main

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/daemon"
)

func dashboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dashboard",
		Short: "Open the running daemon's dashboard in a browser",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			p, ok := daemon.Status(home)
			if p == nil {
				return errors.New("no running daemon (start with 'osm run')")
			}
			if !ok {
				return fmt.Errorf("daemon pid=%d is not healthy (start with 'osm run')", p.PID)
			}
			url := "http://" + p.DashAddr
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "opening dashboard at %s\n", url)
			return openBrowser(url)
		},
	}
}

func openBrowser(url string) error {
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"open", url}
	case "windows":
		args = []string{"cmd", "/c", "start", url}
	default:
		args = []string{"xdg-open", url}
	}
	return exec.Command(args[0], args[1:]...).Start() // #nosec G204 -- url is internal daemon address
}
