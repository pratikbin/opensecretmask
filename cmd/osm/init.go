package main

import (
	"fmt"
	"os"
	"time"

	"github.com/smallstep/truststore"
	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func initCmd() *cobra.Command {
	var noTrust, check bool
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

			if noTrust {
				fmt.Printf("CA written to %s (not installed — --no-trust)\n", certPath)
			} else {
				installCAWithCountdown(certPath)
			}

			printSetup(home, certPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&noTrust, "no-trust", false, "do not install the CA into the system trust store")
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

Start the proxy and dashboard:
  osm proxy

Point your LLM tools at the proxy (proxy %s, dashboard http://%s):
  export HTTPS_PROXY=http://%s
  export NODE_EXTRA_CA_CERTS=%s   # Claude Code and other Node tools
  export SSL_CERT_FILE=%s          # some Python / Go tools

Register secrets to mask:
  osm add NAME=value
  osm preload                      # scan .env files in the current directory
`, home, proxyListen, dashListen, proxyListen, certPath, certPath)
}

// installCAWithCountdown prints exactly what the trust-store install will do,
// counts down 5 seconds so the user can cancel, then installs the CA.
// Installing into the system trust store is the only osm-init step that needs
// administrator access — it writes to a root-owned location.
func installCAWithCountdown(certPath string) {
	fmt.Print(`
The next step needs ADMINISTRATOR access. It installs the opensecretmask CA
into your system trust store, so your tools trust the proxy's intercepted TLS:

  macOS:  sudo security add-trusted-cert -d \
            -k /Library/Keychains/System.keychain \
            ` + certPath + `
  Linux:  copy the cert into /usr/local/share/ca-certificates/
            then  sudo update-ca-certificates

You will see a password / keychain prompt. To skip: press Ctrl-C now, or
re-run as 'osm init --no-trust' (the CA file is written either way).

`)
	for i := 5; i > 0; i-- {
		fmt.Printf("\r  continuing in %d ... ", i)
		time.Sleep(time.Second)
	}
	fmt.Print("\r                          \r")

	if err := truststore.InstallFile(certPath); err != nil {
		fmt.Printf("warning: could not install the CA: %v\n", err)
		fmt.Printf("install %s into your trust store manually, or re-run with privileges\n", certPath)
		return
	}
	fmt.Println("CA installed into the system trust store")
}

