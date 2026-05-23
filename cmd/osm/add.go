package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add NAME=VALUE",
		Short: "Register a secret to mask",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, value, ok := strings.Cut(args[0], "=")
			if !ok || name == "" || value == "" {
				return fmt.Errorf("expected NAME=VALUE, got %q", args[0])
			}
			home, err := homeDir()
			if err != nil {
				return err
			}
			st, err := openUnlocked(cmd.Context(), home)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			m, err := newMasker(st, false)
			if err != nil {
				return err
			}
			sec, err := m.Register(cmd.Context(), name, value)
			if err != nil {
				return err
			}
			fmt.Printf("registered %q\n  mask sent to LLMs: %s\n", sec.Name, sec.Mask)
			return nil
		},
	}
}
