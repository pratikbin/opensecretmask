// Package detect finds secrets in request bodies. Detection rules are
// supplied by Providers (see provider.go); a Shannon-entropy heuristic
// catches unknown high-entropy tokens when enabled in Config.
package detect

import (
	"bytes"
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sourcegraph/conc/pool"
)

// parallelScanMinBody is the body size (bytes) at or above which Scan
// fans the rule set out across goroutines. Below it the goroutine
// scheduling cost outweighs the regex work, so Scan stays on the
// sequential path.
const parallelScanMinBody = 4096

// Finding is one detected secret.
type Finding struct {
	Value    string
	Rule     string
	Severity string
}

// Config controls the optional entropy layer.
type Config struct {
	Entropy          bool
	EntropyThreshold float64 // bits per character; 0 applies the default
	EntropyMinLen    int     // 0 applies the default
}

// Detector scans bytes for secrets.
type Detector struct {
	rules []compiledRule
	cfg   Config
}

type compiledRule struct {
	name        string
	severity    string
	group       int
	re          *regexp.Regexp
	prefix      string
	prefixBytes []byte // prefix as []byte, for the Scan literal-prefix gate
}

// New builds a Detector. When called with no providers, it falls back
// to DefaultProviders(). Providers are flattened in declaration order;
// when two rules match the same byte span, the first one wins.
func New(cfg Config, providers ...Provider) (*Detector, error) {
	if cfg.EntropyThreshold == 0 {
		cfg.EntropyThreshold = 4.0
	}
	if cfg.EntropyMinLen == 0 {
		cfg.EntropyMinLen = 24
	}
	if len(providers) == 0 {
		providers = DefaultProviders()
	}

	var total int
	for _, p := range providers {
		total += len(p.Rules())
	}
	compiled := make([]compiledRule, 0, total)
	for _, p := range providers {
		for _, r := range p.Rules() {
			if r.Regex == nil {
				return nil, fmt.Errorf("detect: provider %q: rule %q has nil regex", p.Name(), r.Name)
			}
			prefix, _ := r.Regex.LiteralPrefix()
			compiled = append(compiled, compiledRule{
				name:        r.Name,
				severity:    r.Severity,
				group:       r.Group,
				re:          r.Regex,
				prefix:      prefix,
				prefixBytes: []byte(prefix),
			})
		}
	}
	return &Detector{rules: compiled, cfg: cfg}, nil
}

// RuleCount returns the number of compiled detection rules across all
// providers.
func (d *Detector) RuleCount() int { return len(d.rules) }

// Scan returns every distinct secret found in body, sorted by value.
// Regex rules always run; the entropy heuristic runs only when enabled
// in Config.
func (d *Detector) Scan(body []byte) []Finding {
	seen := make(map[string]Finding, len(d.rules))

	applyRule := func(r compiledRule) []Finding {
		if len(r.prefixBytes) > 0 && !bytes.Contains(body, r.prefixBytes) {
			return nil
		}
		var local []Finding
		for _, m := range r.re.FindAllSubmatch(body, -1) {
			if r.group >= len(m) {
				continue
			}
			v := string(m[r.group])
			if v == "" {
				continue
			}
			local = append(local, Finding{Value: v, Rule: r.name, Severity: r.severity})
		}
		return local
	}

	merge := func(findings []Finding) {
		for _, f := range findings {
			if _, ok := seen[f.Value]; !ok {
				seen[f.Value] = f
			}
		}
	}

	if len(body) >= parallelScanMinBody {
		p := pool.NewWithResults[[]Finding]()
		for _, r := range d.rules {
			p.Go(func() []Finding { return applyRule(r) })
		}
		for _, findings := range p.Wait() {
			merge(findings)
		}
	} else {
		for _, r := range d.rules {
			merge(applyRule(r))
		}
	}

	if d.cfg.Entropy {
		for _, tok := range entropyTokens(body, d.cfg.EntropyThreshold, d.cfg.EntropyMinLen) {
			if _, ok := seen[tok]; !ok {
				seen[tok] = Finding{Value: tok, Rule: "entropy", Severity: "medium"}
			}
		}
	}
	out := make([]Finding, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.Value, b.Value) })
	return out
}

// LiteralPrefixLen returns the byte length of the longest rule literal
// prefix that value begins with — used to keep a credential's
// recognizable prefix intact when garbling. Returns 0 when no rule
// prefix matches.
func (d *Detector) LiteralPrefixLen(value string) int {
	best := 0
	for _, r := range d.rules {
		if len(r.prefix) > best && strings.HasPrefix(value, r.prefix) {
			best = len(r.prefix)
		}
	}
	return best
}
