package main

import "github.com/spf13/cobra"

func newHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "hook EVENT",
		Short: "Run hook event handler (called by AI agent harnesses)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	c.Flags().String("harness", "", "harness name (e.g. claude-code)")
	return c
}
