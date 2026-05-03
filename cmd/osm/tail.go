package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

func newTailCmd() *cobra.Command {
	var rawJSON bool
	var follow bool
	c := &cobra.Command{
		Use:   "tail",
		Short: "Tail audit log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := store.Root()
			if err != nil {
				return err
			}
			path := filepath.Join(root, store.AuditName)
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			out := cmd.OutOrStdout()
			r := bufio.NewReader(f)
			emit := func(line string) {
				if rawJSON {
					fmt.Fprintln(out, line)
					return
				}
				var ev store.AuditEvent
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					fmt.Fprintln(out, line)
					return
				}
				fmt.Fprintf(out, "%s %s tool=%s rule=%s count=%d\n",
					ev.TS.Format("2006-01-02T15:04:05Z07:00"),
					ev.Action, ev.Tool, ev.Rule, ev.Count)
			}
			for {
				line, err := r.ReadString('\n')
				if len(line) > 0 {
					emit(strings.TrimRight(line, "\n"))
				}
				if err == io.EOF {
					if !follow {
						return nil
					}
					time.Sleep(250 * time.Millisecond)
					continue
				}
				if err != nil {
					return err
				}
			}
		},
	}
	c.Flags().BoolVar(&rawJSON, "json", false, "raw NDJSON passthrough")
	c.Flags().BoolVar(&follow, "follow", false, "follow file (tail -f style)")
	return c
}
