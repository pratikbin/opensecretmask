package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
	"github.com/spf13/cobra"
)

func newAddCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "add NAME=value",
		Short: "Register a secret (NAME=value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eq := strings.IndexByte(args[0], '=')
			if eq <= 0 {
				return fmt.Errorf("usage: osm add NAME=value")
			}
			name := args[0][:eq]
			value := args[0][eq+1:]
			if value == "" {
				return fmt.Errorf("empty value")
			}
			root, err := store.Root()
			if err != nil {
				return err
			}
			cfg, err := store.LoadConfig(filepath.Join(root, store.ConfigName))
			if err != nil {
				return err
			}
			keyBytes, err := keymgr.LoadOrError(root)
			if err != nil {
				return err
			}
			hasher := keymgr.NewHasher(keyBytes)
			lock, err := store.OpenLock(root)
			if err != nil {
				return err
			}
			rule := transformer.Rule{
				ID:      "env-import",
				MinLen:  1,
				MaxLen:  4096,
				Charset: transformer.CharsetBase64URL,
			}
			var masked string
			if err := lock.WithExclusive(time.Duration(cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
				m, err := store.LoadMappings(filepath.Join(root, store.MappingsName))
				if err != nil {
					return err
				}
				s, err := store.LoadSecrets(filepath.Join(root, store.SecretsName))
				if err != nil {
					return err
				}
				if m.ByMask == nil {
					m.ByMask = map[string]string{}
				}
				// reuse if already present
				for mk, v := range m.ByMask {
					if v == value {
						masked = mk
						return nil
					}
				}
				mk, err := transformer.Mask(value, rule, hasher, m.ByMask)
				if err != nil {
					return err
				}
				m.ByMask[mk] = value
				s.Upsert(store.SecretEntry{
					ID:           mk,
					Label:        name,
					Source:       "manual",
					Rule:         "manual",
					Value:        value,
					Masked:       mk,
					RegisteredAt: time.Now().UTC(),
					LastSeenAt:   time.Now().UTC(),
				})
				if err := store.SaveMappings(filepath.Join(root, store.MappingsName), m); err != nil {
					return err
				}
				if err := store.SaveSecrets(filepath.Join(root, store.SecretsName), s); err != nil {
					return err
				}
				masked = mk
				return nil
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "registered %s -> %s\n", name, masked)
			return nil
		},
	}
	return c
}
