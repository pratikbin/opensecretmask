package main

import "github.com/spf13/cobra"

func newAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add NAME=value",
		Short: "Register a secret (NAME=value)",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
}
