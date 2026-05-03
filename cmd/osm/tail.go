package main

import "github.com/spf13/cobra"

func newTailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tail",
		Short: "Tail audit log",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
}
