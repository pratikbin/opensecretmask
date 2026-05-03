package main

import "github.com/spf13/cobra"

func newInstallCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "install <harness>",
		Short: "Install hooks into a target harness (claude-code)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	// add uninstall as a sibling later in Task 20
	return c
}
