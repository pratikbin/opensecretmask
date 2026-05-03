// Package engine wires detector + transformer + store + keymgr into the
// MaskText / UnmaskText / PreloadEnv pipeline used by cmd/osm/hook.
package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

// Engine wires the masking pipeline. Hook dispatcher constructs one per call.
type Engine struct {
	Cfg       *store.Config
	Hasher    *keymgr.Hasher
	Lock      *store.Lock
	Detector  *detector.Detector
	Audit     *store.AuditWriter
	Root      string
	Allowlist *store.Allowlist
	Rules     []transformer.Rule
}

// LoadMappings reads mappings.json under shared lock.
func (e *Engine) LoadMappings() (*store.Mappings, error) {
	mappingsPath := filepath.Join(e.Root, store.MappingsName)
	var m *store.Mappings
	err := e.Lock.WithShared(time.Duration(e.Cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
		mm, lerr := store.LoadMappings(mappingsPath)
		if lerr != nil {
			return lerr
		}
		m = mm
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// MaskText runs detector + transformer.Mask, persists new mappings, returns masked text.
func (e *Engine) MaskText(_ context.Context, sessionID, source, text string) (string, []detector.Finding, error) {
	maps, err := e.LoadMappings()
	if err != nil {
		return text, nil, fmt.Errorf("load mappings: %w", err)
	}
	hits := e.Detector.Detect(text)
	if len(hits) == 0 {
		return text, nil, nil
	}

	ruleByID := map[string]transformer.Rule{}
	for _, r := range e.Rules {
		ruleByID[r.ID] = r
	}

	// Reverse lookup helper: real value -> existing mask.
	findExistingMask := func(val string, byMask map[string]string) string {
		for m, v := range byMask {
			if v == val {
				return m
			}
		}
		return ""
	}

	type pendingItem struct {
		value, mask, ruleID string
	}
	var pending []pendingItem
	resolved := map[string]string{} // real value -> mask

	for _, h := range hits {
		if _, done := resolved[h.Value]; done {
			continue
		}
		if existing := findExistingMask(h.Value, maps.ByMask); existing != "" {
			resolved[h.Value] = existing
			continue
		}
		if h.Rule == "registered" {
			// registered hits should already be in mappings; skip if not.
			continue
		}
		rule, ok := ruleByID[h.Rule]
		if !ok {
			continue
		}
		mask, merr := transformer.Mask(h.Value, rule, e.Hasher, maps.ByMask)
		if merr != nil {
			return text, hits, fmt.Errorf("mask %s: %w", h.Rule, merr)
		}
		resolved[h.Value] = mask
		pending = append(pending, pendingItem{value: h.Value, mask: mask, ruleID: h.Rule})
	}

	if len(pending) > 0 {
		mappingsPath := filepath.Join(e.Root, store.MappingsName)
		secretsPath := filepath.Join(e.Root, store.SecretsName)
		err := e.Lock.WithExclusive(time.Duration(e.Cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
			m2, lerr := store.LoadMappings(mappingsPath)
			if lerr != nil {
				return lerr
			}
			s2, lerr := store.LoadSecrets(secretsPath)
			if lerr != nil {
				return lerr
			}
			if m2.ByMask == nil {
				m2.ByMask = map[string]string{}
			}
			now := time.Now().UTC()
			for _, p := range pending {
				// Re-check inside lock — another process may have persisted same value.
				if existing := findExistingMask(p.value, m2.ByMask); existing != "" {
					resolved[p.value] = existing
					continue
				}
				m2.ByMask[p.mask] = p.value
				s2.Upsert(store.SecretEntry{
					ID:           p.mask,
					Source:       source,
					Rule:         p.ruleID,
					Value:        p.value,
					Masked:       p.mask,
					RegisteredAt: now,
					LastSeenAt:   now,
				})
			}
			if serr := store.SaveMappings(mappingsPath, m2); serr != nil {
				return serr
			}
			return store.SaveSecrets(secretsPath, s2)
		})
		if err != nil {
			return text, hits, fmt.Errorf("persist: %w", err)
		}
	}

	// Apply replacements in descending start order so byte indices stay valid.
	type rep struct {
		start, end int
		mask       string
	}
	reps := make([]rep, 0, len(hits))
	for _, h := range hits {
		mask, ok := resolved[h.Value]
		if !ok {
			continue
		}
		reps = append(reps, rep{h.Start, h.End, mask})
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].start > reps[j].start })
	out := []byte(text)
	for _, r := range reps {
		buf := make([]byte, 0, len(out)-(r.end-r.start)+len(r.mask))
		buf = append(buf, out[:r.start]...)
		buf = append(buf, []byte(r.mask)...)
		buf = append(buf, out[r.end:]...)
		out = buf
	}
	return string(out), hits, nil
}

// UnmaskText loads mappings and runs ReverseIndex.Replace.
// Returns (output, replacementCount, error).
func (e *Engine) UnmaskText(text string) (string, int, error) {
	maps, err := e.LoadMappings()
	if err != nil {
		return text, 0, err
	}
	rev := transformer.BuildReverseIndex(maps.ByMask)
	out := rev.Replace(text)
	count := 0
	if out != text {
		for k := range maps.ByMask {
			if k == "" {
				continue
			}
			count += strings.Count(text, k)
		}
	}
	return out, count, nil
}

// PreloadEnv parses .env files in cwd hierarchy and registers them as secrets.
// Returns the count of newly imported entries.
func (e *Engine) PreloadEnv(_ context.Context, cwd string) (int, error) {
	if !e.Cfg.Detector.Env.Enabled {
		return 0, nil
	}
	files, err := detector.FindEnvFiles(cwd, e.Cfg.Detector.Env.Patterns, e.Cfg.Detector.Env.WalkUpToGitRoot)
	if err != nil {
		return 0, err
	}
	ignore := map[string]struct{}{}
	for _, k := range e.Cfg.Detector.Env.IgnoreKeys {
		ignore[k] = struct{}{}
	}
	type item struct {
		key, value, src string
	}
	var entries []item
	for _, p := range files {
		ee, perr := detector.ParseEnvFile(p)
		if perr != nil {
			continue
		}
		for _, x := range ee {
			if _, skip := ignore[x.Key]; skip {
				continue
			}
			if len(x.Value) < e.Cfg.Detector.MinSecretLength {
				continue
			}
			entries = append(entries, item{x.Key, x.Value, p})
		}
	}
	if len(entries) == 0 {
		return 0, nil
	}

	mappingsPath := filepath.Join(e.Root, store.MappingsName)
	secretsPath := filepath.Join(e.Root, store.SecretsName)
	envRule := transformer.Rule{
		ID:      "env-import",
		MinLen:  1,
		MaxLen:  4096,
		Charset: transformer.CharsetBase64URL,
	}

	imported := 0
	err = e.Lock.WithExclusive(time.Duration(e.Cfg.Hooks.LockTimeoutMs)*time.Millisecond, func() error {
		m, lerr := store.LoadMappings(mappingsPath)
		if lerr != nil {
			return lerr
		}
		s, lerr := store.LoadSecrets(secretsPath)
		if lerr != nil {
			return lerr
		}
		if m.ByMask == nil {
			m.ByMask = map[string]string{}
		}
		now := time.Now().UTC()
		for _, it := range entries {
			already := false
			for _, v := range m.ByMask {
				if v == it.value {
					already = true
					break
				}
			}
			if already {
				continue
			}
			mask, merr := transformer.Mask(it.value, envRule, e.Hasher, m.ByMask)
			if merr != nil {
				continue
			}
			m.ByMask[mask] = it.value
			s.Upsert(store.SecretEntry{
				ID:           mask,
				Label:        it.key,
				Source:       "env",
				SourcePath:   it.src,
				Rule:         "env-import",
				Value:        it.value,
				Masked:       mask,
				RegisteredAt: now,
				LastSeenAt:   now,
			})
			imported++
		}
		if serr := store.SaveMappings(mappingsPath, m); serr != nil {
			return serr
		}
		return store.SaveSecrets(secretsPath, s)
	})
	if err != nil {
		return 0, err
	}
	return imported, nil
}
