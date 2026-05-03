package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Create ~/.opensecretmask/ + install.key + default config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := store.Root()
			if err != nil {
				return err
			}
			if !force {
				if _, err := os.Stat(filepath.Join(root, keymgr.InstallKeyName)); err == nil {
					return fmt.Errorf("already initialized at %s; use --force to overwrite", root)
				}
			}
			if err := os.MkdirAll(root, 0o700); err != nil {
				return err
			}
			if err := os.Chmod(root, 0o700); err != nil {
				return err
			}
			if _, err := keymgr.Generate(root); err != nil {
				return err
			}
			cfg := store.DefaultConfig()
			cfgBytes, err := tomlMarshal(cfg)
			if err != nil {
				return fmt.Errorf("marshal config: %w", err)
			}
			if err := store.WriteAtomic(filepath.Join(root, store.ConfigName), cfgBytes, 0o644); err != nil {
				return err
			}
			if err := store.SaveSecrets(filepath.Join(root, store.SecretsName), &store.Secrets{Version: 1}); err != nil {
				return err
			}
			if err := store.SaveMappings(filepath.Join(root, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}); err != nil {
				return err
			}
			al := &store.Allowlist{Values: cfg.Detector.Allowlist.Values}
			if err := store.SaveAllowlist(filepath.Join(root, store.AllowlistName), al); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Initialized %s\n", root)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite existing init")
	return c
}

// tomlMarshal serializes cfg via BurntSushi/toml.NewEncoder.
func tomlMarshal(cfg *store.Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
