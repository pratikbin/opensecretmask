// Package api exposes the harness-agnostic engine for library consumers.
// Stable surface; no harness types exposed.
package api

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/engine"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
)

// Options configures Masker construction.
// Home: override OPENSECRETMASK_HOME (empty → use env var or ~/.opensecretmask).
type Options struct {
	Home string
}

// Finding mirrors detector.Finding to keep the public surface stable.
type Finding struct {
	Start, End int
	Value      string
	Rule       string
	Confidence float64
}

// Masker is a thread-safe credential masker.
type Masker struct {
	eng *engine.Engine
}

// New constructs a Masker. Requires a previously-initialized opensecretmask home
// (see `osm init`). Returns an error if install.key or config is missing.
func New(opts Options) (*Masker, error) {
	root := opts.Home
	if root == "" {
		r, err := store.Root()
		if err != nil {
			return nil, err
		}
		root = r
	}
	cfg, err := store.LoadConfig(filepath.Join(root, store.ConfigName))
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	keyBytes, err := keymgr.LoadOrError(root)
	if err != nil {
		return nil, err
	}
	hasher := keymgr.NewHasher(keyBytes)
	lock, err := store.OpenLock(root)
	if err != nil {
		return nil, err
	}
	allow, err := store.LoadAllowlist(filepath.Join(root, store.AllowlistName))
	if err != nil {
		return nil, err
	}
	secs, err := store.LoadSecrets(filepath.Join(root, store.SecretsName))
	if err != nil {
		return nil, err
	}
	rules := detector.BuiltinRules()
	al, err := detector.NewAllowlistSet(allow.Values, allow.Patterns, allow.RulesDisabled)
	if err != nil {
		return nil, err
	}
	ent := detector.NewEntropyScanner(cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	regValues := make([]string, 0, len(secs.Secrets))
	for _, e := range secs.Secrets {
		regValues = append(regValues, e.Value)
	}
	det := detector.NewDetector(detector.NewRegisteredSet(regValues), rules, ent, al)
	au := store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo)
	return &Masker{
		eng: &engine.Engine{
			Cfg: cfg, Hasher: hasher, Lock: lock, Detector: det,
			Audit: au, Root: root, Allowlist: allow, Rules: rules,
		},
	}, nil
}

// Mask runs the detector and replaces secrets with format-preserving masks.
// New mappings are persisted under exclusive lock.
func (m *Masker) Mask(ctx context.Context, text string) (string, error) {
	out, _, err := m.eng.MaskText(ctx, "", "api", text)
	return out, err
}

// Unmask replaces all known masks with their original values.
// Unknown masks are left as-is.
func (m *Masker) Unmask(text string) (string, error) {
	out, _, err := m.eng.UnmaskText(text)
	return out, err
}

// Detect returns findings without modifying state.
func (m *Masker) Detect(text string) []Finding {
	hits := m.eng.Detector.Detect(text)
	out := make([]Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, Finding{
			Start: h.Start, End: h.End,
			Value: h.Value, Rule: h.Rule, Confidence: h.Confidence,
		})
	}
	return out
}
