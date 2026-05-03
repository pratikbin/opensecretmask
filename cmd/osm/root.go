package main

import (
	"errors"

	"github.com/spf13/cobra"
)

var Version = "dev"

var errNotImplemented = errors.New("not implemented")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "osm",
		Short:         "opensecretmask — credential masker for AI coding agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newDoctorCmd(),
		newScanCmd(),
		newHookCmd(),
		newInstallCmd(),
		newUninstallCmd(),
		newAddCmd(),
		newAllowCmd(),
		newStatusCmd(),
		newTailCmd(),
		newVersionCmd(),
	)
	return root
}
