package main

import (
	"fmt"
	"os"
	"time"

	"github.com/smallstep/truststore"
	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/proxy"
)

func uninstallCmd() *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the opensecretmask CA from the system trust store",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			certPath := proxy.CertPath(home)
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				return fmt.Errorf("CA certificate not found at %s — run 'osm init' first", certPath)
			}

			fmt.Printf(`Removing the opensecretmask CA from the system trust store:

  macOS:  sudo security remove-trusted-cert -d %s
  Linux:  remove from /usr/local/share/ca-certificates/ + sudo update-ca-certificates

You will see an administrator password prompt. To cancel: press Ctrl-C now.

`, certPath)
			for i := 5; i > 0; i-- {
				fmt.Printf("\r  continuing in %d ... ", i)
				time.Sleep(time.Second)
			}
			fmt.Print("\r                          \r")

			if err := truststore.UninstallFile(certPath); err != nil {
				fmt.Printf("warning: could not remove CA from trust store: %v\n", err)
				fmt.Printf("remove %s from your trust store manually\n", certPath)
			} else {
				fmt.Println("CA removed from system trust store")
			}

			if purge {
				if err := os.RemoveAll(home); err != nil {
					return fmt.Errorf("purge failed: %w", err)
				}
				fmt.Printf("state directory removed: %s\n", home)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete the state directory and all secrets")
	return cmd
}
