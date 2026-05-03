// Package transformer: unmask is the reverse of Mask. Given text containing
// masks (e.g., LLM tool input), replace each mask with the real secret using
// Aho-Corasick for O(N+M) multi-pattern search across many keys.
//
// Uses iohub/ahocorasick (package cedar) — exposes match offsets via
// MatchToken.At (end position) and KLen, unlike cloudflare/ahocorasick.
package transformer

import (
	"sort"
	"strings"

	cedar "github.com/iohub/ahocorasick"
)

// ReverseIndex maps mask -> real secret using an Aho-Corasick automaton.
type ReverseIndex struct {
	m *cedar.Matcher
}

// BuildReverseIndex constructs an Aho-Corasick matcher from mask -> secret pairs.
// Returns an empty index for an empty map; Replace then becomes a passthrough.
func BuildReverseIndex(byMask map[string]string) *ReverseIndex {
	if len(byMask) == 0 {
		return &ReverseIndex{}
	}
	m := cedar.NewMatcher()
	for k, v := range byMask {
		m.Insert([]byte(k), v)
	}
	m.Compile()
	return &ReverseIndex{m: m}
}

// Replace scans text for any inserted mask and replaces with its secret.
// Overlap policy: prefer earlier start; on tie, prefer longer match (greedy
// non-overlapping after sort).
func (r *ReverseIndex) Replace(text string) string {
	if r == nil || r.m == nil {
		return text
	}
	buf := []byte(text)
	resp := r.m.Match(buf)
	type hit struct {
		start, end int
		v          string
	}
	hits := make([]hit, 0, 16)
	for resp.HasNext() {
		for _, t := range resp.NextMatchItem(buf) {
			// MatchToken.At is the end index of the match (inclusive).
			// Key spans buf[At-KLen+1 : At+1].
			start := t.At - t.KLen + 1
			end := t.At + 1
			v, _ := t.Value.(string)
			hits = append(hits, hit{start, end, v})
		}
	}
	resp.Release()
	if len(hits) == 0 {
		return text
	}
	// Sort by start asc, end desc → longer-at-same-start wins.
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})
	// Greedy non-overlapping: skip hits that start before previous end.
	keep := hits[:0]
	prevEnd := -1
	for _, h := range hits {
		if h.start < prevEnd {
			continue
		}
		keep = append(keep, h)
		prevEnd = h.end
	}
	var sb strings.Builder
	last := 0
	for _, h := range keep {
		sb.WriteString(text[last:h.start])
		sb.WriteString(h.v)
		last = h.end
	}
	sb.WriteString(text[last:])
	return sb.String()
}
