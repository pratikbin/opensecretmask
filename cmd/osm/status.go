package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show stored secrets and recent proxy activity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := homeDir()
			if err != nil {
				return err
			}
			st, err := openUnlocked(cmd.Context(), home)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			stats, err := st.Stats(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Printf("secrets:  %d  (%d registered, %d detected)\n",
				stats.Secrets, stats.Registered, stats.Detected)
			fmt.Printf("requests: %d  (%d carried secrets, %d masking events)\n",
				stats.Requests, stats.MaskedRequests, stats.TotalMasked)

			secrets, err := st.ListSecrets(cmd.Context())
			if err != nil {
				return err
			}
			if len(secrets) == 0 {
				return nil
			}
			fmt.Println()
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSOURCE\tMASK\tHITS")
			for _, s := range secrets {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", s.Name, s.Source, s.Mask, s.Hits)
			}
			return tw.Flush()
		},
	}
}

