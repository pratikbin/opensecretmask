package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func initCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the state directory, CA, and encrypted secret store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}

			if check {
				_, dbErr := os.Stat(dbPath(home))
				_, caErr := os.Stat(proxy.CertPath(home))
				dbOK := dbErr == nil
				caOK := caErr == nil
				fmt.Printf("state dir:  %s\n", statusMark(dbOK || caOK))
				fmt.Printf("secret store: %s\n", statusMark(dbOK))
				fmt.Printf("CA cert:    %s\n", statusMark(caOK))
				if dbOK && caOK {
					fmt.Println("\ninitialized")
					return nil
				}
				return fmt.Errorf("not initialized — run 'osm init'")
			}

			if err := os.MkdirAll(home, 0o700); err != nil {
				return err
			}

			st, err := store.Open(cmd.Context(), dbPath(home))
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			already, err := st.Initialized(cmd.Context())
			if err != nil {
				return err
			}
			if already {
				return fmt.Errorf("already initialized at %s", home)
			}
			pass, err := newPassphrase()
			if err != nil {
				return err
			}
			if err := st.InitCrypto(cmd.Context(), pass); err != nil {
				return err
			}

			ca, err := proxy.GenerateCA()
			if err != nil {
				return err
			}
			if err := ca.Save(home); err != nil {
				return err
			}
			certPath := proxy.CertPath(home)
			fmt.Printf("CA written to %s\n", certPath)

			printSetup(home, certPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report init status and exit (no side effects)")
	return cmd
}

func statusMark(ok bool) string {
	if ok {
		return "ok"
	}
	return "missing"
}

func printSetup(home, certPath string) {
	fmt.Printf(`
opensecretmask initialized at %s

Recommended: run agents through osm (per-process trust, no system changes):
  osm run -- claude
  osm run -- curl https://api.anthropic.com/...

Or start the proxy and dashboard, then point tools at it manually:
  osm proxy
  export HTTPS_PROXY=http://%s
  export NODE_EXTRA_CA_CERTS=%s   # Claude Code and other Node tools
  export SSL_CERT_FILE=%s          # some Python / Go tools

Register secrets to mask:
  osm add NAME=value
  osm preload                      # scan .env files in the current directory
`, home, proxyListen, certPath, certPath)
}
