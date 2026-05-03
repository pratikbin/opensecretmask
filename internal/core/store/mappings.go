package store

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"
)

type Mappings struct {
	Version   int               `json:"version"`
	ByMask    map[string]string `json:"by_mask"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func LoadMappings(path string) (*Mappings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Mappings{Version: 1, ByMask: map[string]string{}}, nil
		}
		return nil, err
	}
	m := &Mappings{}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, err
	}
	if m.ByMask == nil {
		m.ByMask = map[string]string{}
	}
	return m, nil
}

func SaveMappings(path string, m *Mappings) error {
	m.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o600)
}

func (m *Mappings) Set(mask, real string) {
	if m.ByMask == nil {
		m.ByMask = map[string]string{}
	}
	m.ByMask[mask] = real
}

func (m *Mappings) Lookup(mask string) (string, bool) {
	v, ok := m.ByMask[mask]
	return v, ok
}

// AhoCorasickReplace replaces every mask in text with its real value.
//
// Note: cloudflare/ahocorasick.Match only returns dictionary indices of hits,
// not byte positions, so we cannot use it directly to drive replacement. For
// v1 (mappings expected to stay <100 entries) we use a longest-first
// strings.Index scan, which gives correct non-overlapping longest-match-wins
// semantics. The function name is preserved so a true AC-driven impl can be
// swapped in later.
func (m *Mappings) AhoCorasickReplace(text string) string {
	if len(m.ByMask) == 0 {
		return text
	}
	masks := make([]string, 0, len(m.ByMask))
	for k := range m.ByMask {
		masks = append(masks, k)
	}
	// longest first → non-overlapping longest-match-wins
	sort.Slice(masks, func(i, j int) bool {
		return len(masks[i]) > len(masks[j])
	})

	var b strings.Builder
	b.Grow(len(text))
	i := 0
	for i < len(text) {
		matched := false
		for _, mask := range masks {
			if mask == "" {
				continue
			}
			if strings.HasPrefix(text[i:], mask) {
				b.WriteString(m.ByMask[mask])
				i += len(mask)
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte(text[i])
			i++
		}
	}
	return b.String()
}
