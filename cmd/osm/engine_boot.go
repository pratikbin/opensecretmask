package main

import (
	"fmt"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/engine"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

func bootstrapEngine() (*engine.Engine, error) {
	root, err := store.Root()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(root, store.ConfigName)
	cfg, err := store.LoadConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	keyBytes, err := keymgr.LoadOrError(root)
	if err != nil {
		return nil, fmt.Errorf("install.key: %w", err)
	}
	hasher := keymgr.NewHasher(keyBytes)

	lock, err := store.OpenLock(root)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}

	allow, err := store.LoadAllowlist(filepath.Join(root, store.AllowlistName))
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	secs, err := store.LoadSecrets(filepath.Join(root, store.SecretsName))
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}

	rules := detector.BuiltinRules()
	al, err := detector.NewAllowlistSet(allow.Values, allow.Patterns, allow.RulesDisabled)
	if err != nil {
		return nil, fmt.Errorf("allowlist set: %w", err)
	}
	ent := detector.NewEntropyScannerEnabled(cfg.Detector.Entropy.Enabled, cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	regValues := make([]string, 0, len(secs.Secrets))
	for _, e := range secs.Secrets {
		regValues = append(regValues, e.Value)
	}
	det := detector.NewDetector(detector.NewRegisteredSet(regValues), rules, ent, al)
	au := store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo)
	return &engine.Engine{
		Cfg: cfg, Hasher: hasher, Lock: lock, Detector: det,
		Audit: au, Root: root, Allowlist: allow, Rules: rules,
	}, nil
}
