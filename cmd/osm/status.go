package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show installation status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			root, err := store.Root()
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "root: %s\n", root)
			s, _ := store.LoadSecrets(filepath.Join(root, store.SecretsName))
			m, _ := store.LoadMappings(filepath.Join(root, store.MappingsName))
			fmt.Fprintf(out, "secrets: %d\n", len(s.Secrets))
			fmt.Fprintf(out, "mappings: %d\n", len(m.ByMask))
			audit := filepath.Join(root, store.AuditName)
			if st, err := os.Stat(audit); err == nil {
				fmt.Fprintf(out, "audit.log: %d bytes (mtime %s)\n", st.Size(), st.ModTime().Format("2006-01-02T15:04:05Z07:00"))
			} else {
				fmt.Fprintln(out, "audit.log: (none)")
			}
			return nil
		},
	}
}
