package main

import "github.com/spf13/cobra"

func newAllowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "allow VALUE",
		Short: "Add a value to the allowlist",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
}
