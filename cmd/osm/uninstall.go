package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/shell"
)

// uninstallCmd is kept as a deprecated stub. osm no longer touches the system
// trust store (per-process trust via 'osm run' is the only path), so there is
// nothing system-wide to uninstall. State lives entirely under $OPENSECRETMASK_HOME
// (default ~/.opensecretmask) and can be removed with 'rm -rf'.
func uninstallCmd() *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:        "uninstall",
		Short:      "Deprecated: osm no longer installs anything system-wide",
		Deprecated: "osm does not modify the system trust store. Delete $OPENSECRETMASK_HOME manually, or pass --purge to wipe it.",
		Args:       cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			if !purge {
				fmt.Printf(`osm uninstall is a no-op — nothing is installed system-wide.

To wipe state, either:
  rm -rf %s
  osm uninstall --purge
`, home)
				return nil
			}
			// Strip shell rc source lines first so they do not point at the
			// about-to-be-deleted script and break future shell startup.
			cleared, sherr := shell.Uninstall()
			if sherr != nil {
				fmt.Fprintf(os.Stderr, "warn: shell uninstall: %v\n", sherr)
			}
			for _, rc := range cleared {
				fmt.Printf("removed shell source line from %s\n", rc.Path)
			}
			if err := os.RemoveAll(home); err != nil {
				return fmt.Errorf("purge failed: %w", err)
			}
			fmt.Printf("state directory removed: %s\n", home)
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "delete the state directory and all secrets")
	return cmd
}
