package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pratikbin/opensecretmask/internal/shell"
)

func shellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Manage shell integration that wraps LLM agent CLIs with `osm run`",
		Long: "shell installs a posix-shell init script that defines functions\n" +
			"for " + strings.Join(shell.WrappedTools, ", ") + " — typing the bare command then runs\n" +
			"`osm run -- <cmd>` so traffic flows through the osm masking proxy.\n\n" +
			"Source line is appended to ~/.zshrc and ~/.bashrc (whichever exist);\n" +
			"a one-shot pre-osm backup is written to <rc>.osm.bak.\n\n" +
			"Note: codex and pi currently bypass the proxy (websocket / non-https-proxy\n" +
			"transport). The wrapper installs functions ready for when that's fixed.",
	}
	cmd.AddCommand(shellInstallCmd(), shellUninstallCmd(), shellStatusCmd())
	return cmd
}

func shellInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install shell functions wrapping " + strings.Join(shell.WrappedTools, ", "),
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			updated, err := shell.Install(home)
			if err != nil {
				return err
			}
			for _, rc := range updated {
				fmt.Fprintf(os.Stderr, "osm: wired %s (%s)\n", rc.Path, rc.Shell)
			}
			fmt.Fprintf(os.Stderr, "osm: restart your shell or `source` the rc file to activate.\n")
			fmt.Fprintf(os.Stderr, "osm: wrapped tools — %s\n", strings.Join(shell.WrappedTools, ", "))
			return nil
		},
	}
}

func shellUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the osm source line from shell rc files",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cleared, err := shell.Uninstall()
			if err != nil {
				return err
			}
			if len(cleared) == 0 {
				fmt.Fprintln(os.Stderr, "osm: nothing to remove.")
				return nil
			}
			for _, rc := range cleared {
				fmt.Fprintf(os.Stderr, "osm: removed source line from %s\n", rc.Path)
			}
			fmt.Fprintln(os.Stderr, "osm: restart your shell to drop the wrapped functions.")
			return nil
		},
	}
}

func shellStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show shell integration state per rc file",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			files, scriptPresent, err := shell.Status(home)
			if err != nil {
				return err
			}
			if scriptPresent {
				fmt.Printf("script: present\n")
			} else {
				fmt.Printf("script: missing\n")
			}
			for _, f := range files {
				switch {
				case !f.Exists:
					fmt.Printf("%-5s %s — rc file absent\n", f.Shell, f.Path)
				case f.Installed:
					fmt.Printf("%-5s %s — installed\n", f.Shell, f.Path)
				default:
					fmt.Printf("%-5s %s — not installed\n", f.Shell, f.Path)
				}
			}
			return nil
		},
	}
}
