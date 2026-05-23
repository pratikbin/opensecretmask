package main

import "github.com/spf13/cobra"

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "osm",
		Short: "opensecretmask — local masking proxy for LLM API traffic",
		Long: "opensecretmask (osm) runs a local CA-MITM proxy that swaps secrets in\n" +
			"requests to LLM APIs for format-preserving fakes, then restores them in\n" +
			"the responses. Real secrets never reach the provider.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		initCmd(),
		uninstallCmd(),
		proxyCmd(),
		runCmd(),
		addCmd(),
		preloadCmd(),
		statusCmd(),
		doctorCmd(),
	)
	return root
}
