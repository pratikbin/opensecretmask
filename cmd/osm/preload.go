package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func preloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preload [dir]",
		Short: "Scan .env files in a directory and register every value",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			files, err := envFiles(dir)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Printf("no .env files found in %s\n", dir)
				return nil
			}
			home, err := homeDir()
			if err != nil {
				return err
			}
			st, err := openUnlocked(cmd.Context(), home)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			m, err := newMasker(st, false)
			if err != nil {
				return err
			}

			total := 0
			for _, f := range files {
				pairs, err := parseEnvFile(f)
				if err != nil {
					fmt.Printf("warning: %s: %v\n", f, err)
					continue
				}
				for name, value := range pairs {
					if _, err := m.Register(cmd.Context(), name, value); err != nil {
						return err
					}
				}
				total += len(pairs)
				fmt.Printf("%s: %d values\n", f, len(pairs))
			}
			fmt.Printf("registered %d secrets\n", total)
			return nil
		},
	}
}

// envFiles lists files named .env or .env.* in dir (non-recursive).
func envFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); n == ".env" || strings.HasPrefix(n, ".env.") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out, nil
}

// parseEnvFile reads KEY=VALUE pairs from a .env file.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- user-named .env file to scan
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out, sc.Err()
}

