package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var noPersist bool
	c := &cobra.Command{
		Use:   "scan FILE",
		Short: "Scan a file for secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := store.Root()
			if err != nil {
				return err
			}
			cfgPath := filepath.Join(root, store.ConfigName)
			cfg, err := store.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			keyBytes, err := keymgr.LoadOrError(root)
			if err != nil {
				return fmt.Errorf("load install.key: %w", err)
			}
			hasher := keymgr.NewHasher(keyBytes)

			lock, err := store.OpenLock(root)
			if err != nil {
				return fmt.Errorf("lock: %w", err)
			}

			mappingsPath := filepath.Join(root, store.MappingsName)
			secretsPath := filepath.Join(root, store.SecretsName)
			allowPath := filepath.Join(root, store.AllowlistName)

			var maps *store.Mappings
			var secs *store.Secrets
			var allow *store.Allowlist
			if err := lock.WithShared(time.Duration(cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
				m, err := store.LoadMappings(mappingsPath)
				if err != nil {
					return err
				}
				s, err := store.LoadSecrets(secretsPath)
				if err != nil {
					return err
				}
				a, err := store.LoadAllowlist(allowPath)
				if err != nil {
					return err
				}
				maps = m
				secs = s
				allow = a
				return nil
			}); err != nil {
				return fmt.Errorf("rlock: %w", err)
			}

			rules := detector.BuiltinRules()
			al, err := detector.NewAllowlistSet(allow.Values, allow.Patterns, allow.RulesDisabled)
			if err != nil {
				return fmt.Errorf("allowlist: %w", err)
			}
			ent := detector.NewEntropyScannerEnabled(cfg.Detector.Entropy.Enabled, cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
			regValues := make([]string, 0, len(secs.Secrets))
			for _, e := range secs.Secrets {
				regValues = append(regValues, e.Value)
			}
			det := detector.NewDetector(detector.NewRegisteredSet(regValues), rules, ent, al)

			ruleByID := map[string]transformer.Rule{}
			for _, r := range rules {
				ruleByID[r.ID] = r
			}

			// pending accumulates new mask->real pairs found this run
			pending := map[string]string{}

			mask := func(value, ruleID string) (string, error) {
				for m, v := range maps.ByMask {
					if v == value {
						return m, nil
					}
				}
				if p, ok := pending[value]; ok {
					return p, nil
				}
				rule, ok := ruleByID[ruleID]
				if !ok {
					return value, nil
				}
				masked, err := transformer.Mask(value, rule, hasher, maps.ByMask)
				if err != nil {
					return "", err
				}
				pending[masked] = value
				return masked, nil
			}

			scanner := detector.NewScanner(det, rules, cfg.Hooks.MaxScanBytes, cfg.Hooks.MaxContainerBytes, mask)
			scanner.SetOnScanCap(cfg.Hooks.OnScanCap)

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
			defer f.Close()

			if err := scanner.Stream(f, cmd.OutOrStdout()); err != nil {
				return err
			}

			if !noPersist && len(pending) > 0 {
				if err := lock.WithExclusive(time.Duration(cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
					m, err := store.LoadMappings(mappingsPath)
					if err != nil {
						return err
					}
					s, err := store.LoadSecrets(secretsPath)
					if err != nil {
						return err
					}
					if m.ByMask == nil {
						m.ByMask = map[string]string{}
					}
					for masked, value := range pending {
						m.ByMask[masked] = value
						s.Upsert(store.SecretEntry{
							ID:           masked,
							Source:       "scan",
							SourcePath:   args[0],
							Value:        value,
							Masked:       masked,
							RegisteredAt: time.Now().UTC(),
							LastSeenAt:   time.Now().UTC(),
						})
					}
					if err := store.SaveMappings(mappingsPath, m); err != nil {
						return err
					}
					return store.SaveSecrets(secretsPath, s)
				}); err != nil {
					return fmt.Errorf("persist: %w", err)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&noPersist, "no-persist", false, "do not register new findings")
	return c
}
