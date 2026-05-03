package detector

import (
	"sort"

	cedar "github.com/iohub/ahocorasick"
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

type Finding struct {
	Start, End int
	Value      string
	Rule       string
	Confidence float64
}

type registeredMatcher struct {
	m *cedar.Matcher
}

type RegisteredSet struct {
	values  map[string]struct{}
	matcher *registeredMatcher
}

// NewRegisteredSet builds an Aho-Corasick matcher over the given exact values.
func NewRegisteredSet(values []string) *RegisteredSet {
	rs := &RegisteredSet{values: make(map[string]struct{}, len(values))}
	if len(values) == 0 {
		return rs
	}
	m := cedar.NewMatcher()
	any := false
	for _, v := range values {
		if v == "" {
			continue
		}
		rs.values[v] = struct{}{}
		m.Insert([]byte(v), []byte(v))
		any = true
	}
	if !any {
		return rs
	}
	m.Compile()
	rs.matcher = &registeredMatcher{m: m}
	return rs
}

func (r *RegisteredSet) scan(text string) []Finding {
	if r == nil || r.matcher == nil || r.matcher.m == nil {
		return nil
	}
	resp := r.matcher.m.Match([]byte(text))
	var hits []Finding
	for resp.HasNext() {
		for _, t := range resp.NextMatchItem([]byte(text)) {
			key := string(t.Value.([]byte))
			end := int(t.At) + 1
			start := end - int(t.KLen)
			hits = append(hits, Finding{
				Start: start, End: end, Value: key,
				Rule: "registered", Confidence: 1.0,
			})
		}
	}
	resp.Release()
	return hits
}

type Detector struct {
	registered *RegisteredSet
	rules      []transformer.Rule
	entropy    *EntropyScanner
	allowlist  *AllowlistSet
}

func NewDetector(reg *RegisteredSet, rules []transformer.Rule, entropy *EntropyScanner, allow *AllowlistSet) *Detector {
	return &Detector{registered: reg, rules: rules, entropy: entropy, allowlist: allow}
}

// Detect runs all 3 layers and resolves overlaps.
func (d *Detector) Detect(text string) []Finding {
	var hits []Finding
	if d.registered != nil {
		hits = append(hits, d.registered.scan(text)...)
	}
	for ri, r := range d.rules {
		if d.allowlist.RuleDisabled(r.ID) {
			continue
		}
		idxs := r.Pattern.FindAllStringIndex(text, -1)
		for _, ix := range idxs {
			val := text[ix[0]:ix[1]]
			if d.allowlist.AllowsValue(val) {
				continue
			}
			if r.MinLen > 0 && len(val) < r.MinLen {
				continue
			}
			if r.MaxLen > 0 && len(val) > r.MaxLen {
				continue
			}
			hits = append(hits, Finding{
				Start: ix[0], End: ix[1], Value: val,
				Rule: r.ID, Confidence: 0.95 - 0.001*float64(ri),
			})
		}
	}
	if d.entropy != nil {
		hits = append(hits, d.entropyScan(text, hits)...)
	}
	return resolveOverlaps(hits)
}

// entropyScan finds entropy-high tokens not already covered by hits.
// Tokens are scanned as runs of [A-Za-z0-9_+/=-]; each is checked against the
// entropy threshold + minLen. Allowlist values + already-covered ranges are skipped.
func (d *Detector) entropyScan(text string, existing []Finding) []Finding {
	covered := func(s, e int) bool {
		for _, h := range existing {
			if s < h.End && h.Start < e {
				return true
			}
		}
		return false
	}
	var hits []Finding
	i := 0
	for i < len(text) {
		c := text[i]
		isTokenChar := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '+' || c == '/' || c == '=' || c == '-'
		if !isTokenChar {
			i++
			continue
		}
		j := i
		for j < len(text) {
			cj := text[j]
			ok := (cj >= 'A' && cj <= 'Z') || (cj >= 'a' && cj <= 'z') ||
				(cj >= '0' && cj <= '9') || cj == '_' || cj == '+' || cj == '/' || cj == '=' || cj == '-'
			if !ok {
				break
			}
			j++
		}
		tok := text[i:j]
		if !covered(i, j) && !d.allowlist.AllowsValue(tok) && d.entropy.IsSecret(tok) {
			hits = append(hits, Finding{Start: i, End: j, Value: tok, Rule: "entropy-high", Confidence: 0.5})
		}
		i = j
	}
	return hits
}

// resolveOverlaps drops findings that overlap a higher-priority finding.
// Sort by Confidence desc, then by length desc, then by Start asc.
// Greedy: keep finding if it doesn't overlap any kept finding.
func resolveOverlaps(hits []Finding) []Finding {
	if len(hits) <= 1 {
		return hits
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Confidence != hits[j].Confidence {
			return hits[i].Confidence > hits[j].Confidence
		}
		li := hits[i].End - hits[i].Start
		lj := hits[j].End - hits[j].Start
		if li != lj {
			return li > lj
		}
		return hits[i].Start < hits[j].Start
	})
	keep := make([]Finding, 0, len(hits))
	for _, h := range hits {
		overlap := false
		for _, k := range keep {
			if h.Start < k.End && k.Start < h.End {
				overlap = true
				break
			}
		}
		if !overlap {
			keep = append(keep, h)
		}
	}
	// return sorted by Start asc for caller convenience
	sort.SliceStable(keep, func(i, j int) bool { return keep[i].Start < keep[j].Start })
	return keep
}
