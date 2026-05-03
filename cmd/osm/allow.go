package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

func newAllowCmd() *cobra.Command {
	var pattern, rule string
	var force bool
	c := &cobra.Command{
		Use:   "allow [VALUE]",
		Short: "Add a value to the allowlist",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := store.Root()
			if err != nil {
				return err
			}
			cfg, err := store.LoadConfig(filepath.Join(root, store.ConfigName))
			if err != nil {
				return err
			}
			lock, err := store.OpenLock(root)
			if err != nil {
				return err
			}
			allowPath := filepath.Join(root, store.AllowlistName)
			if err := lock.WithExclusive(time.Duration(cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
				a, err := store.LoadAllowlist(allowPath)
				if err != nil {
					return err
				}
				if pattern != "" {
					a.Patterns = append(a.Patterns, pattern)
					return store.SaveAllowlist(allowPath, a)
				}
				if rule != "" {
					a.RulesDisabled = append(a.RulesDisabled, rule)
					return store.SaveAllowlist(allowPath, a)
				}
				if len(args) == 0 {
					return fmt.Errorf("usage: osm allow VALUE | --pattern RE | --rule ID")
				}
				v := args[0]
				// refuse if already a registered secret
				if !force {
					s, err := store.LoadSecrets(filepath.Join(root, store.SecretsName))
					if err == nil {
						for _, e := range s.Secrets {
							if e.Value == v {
								return fmt.Errorf("value already registered as secret %q; use --force", e.Label)
							}
						}
					}
				}
				a.Values = append(a.Values, v)
				return store.SaveAllowlist(allowPath, a)
			}); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	c.Flags().StringVar(&pattern, "pattern", "", "regex pattern to allow")
	c.Flags().StringVar(&rule, "rule", "", "rule id to disable")
	c.Flags().BoolVar(&force, "force", false, "allow value even if already registered")
	return c
}
