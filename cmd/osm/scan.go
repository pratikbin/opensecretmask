package main

import "github.com/spf13/cobra"

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan FILE",
		Short: "Scan a file for secrets",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
}
