package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/store"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the opensecretmask installation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			healthy := true
			check := func(label string, pass bool, detail string) {
				mark := "ok  "
				if !pass {
					mark = "FAIL"
					healthy = false
				}
				if detail != "" {
					fmt.Printf("[%s] %s — %s\n", mark, label, detail)
				} else {
					fmt.Printf("[%s] %s\n", mark, label)
				}
			}

			_, statErr := os.Stat(home)
			check("state directory", statErr == nil, home)

			certPath := proxy.CertPath(home)
			_, caErr := os.Stat(certPath)
			check("CA certificate", caErr == nil, certPath)

			st, openErr := store.Open(cmd.Context(), dbPath(home))
			if openErr != nil {
				check("secret store", false, openErr.Error())
			} else {
				defer func() { _ = st.Close() }()
				inited, _ := st.Initialized(cmd.Context())
				check("secret store", inited, dbPath(home))
			}

			fmt.Println()
			if !healthy {
				return fmt.Errorf("doctor found problems — run 'osm init' if not set up yet")
			}
			fmt.Println("all checks passed")
			return nil
		},
	}
}

