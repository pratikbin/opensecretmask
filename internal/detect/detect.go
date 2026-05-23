// Package detect finds secrets in request bodies using vendored credential
// regexes plus a Shannon-entropy heuristic for unknown high-entropy tokens.
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

// parallelScanMinBody is the body size (bytes) at or above which Scan fans the
// 48 regex rules out across goroutines. Below it the goroutine scheduling cost
// outweighs the regex work, so Scan stays on the sequential path.
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

// New compiles the vendored rule set into a Detector.
func New(cfg Config) (*Detector, error) {
	if cfg.EntropyThreshold == 0 {
		cfg.EntropyThreshold = 4.0
	}
	if cfg.EntropyMinLen == 0 {
		cfg.EntropyMinLen = 24
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.regex)
		if err != nil {
			return nil, fmt.Errorf("detect: rule %q: %w", r.name, err)
		}
		prefix, _ := re.LiteralPrefix()
		compiled = append(compiled, compiledRule{
			name: r.name, severity: r.severity, group: r.group, re: re,
			prefix: prefix, prefixBytes: []byte(prefix),
		})
	}
	return &Detector{rules: compiled, cfg: cfg}, nil
}

// RuleCount returns the number of compiled detection rules.
func (d *Detector) RuleCount() int { return len(d.rules) }

// Scan returns every distinct secret found in body, sorted by value. Regex
// rules always run; the entropy heuristic runs only when enabled in Config.
func (d *Detector) Scan(body []byte) []Finding {
	seen := make(map[string]Finding, len(d.rules))

	// applyRule runs one rule against body and returns its findings in match
	// order. body is read-only; FindAllSubmatch does not mutate it, so this is
	// safe to call concurrently.
	applyRule := func(r compiledRule) []Finding {
		// A rule whose regex starts with a literal prefix cannot match unless
		// that prefix is present; bytes.Contains is far cheaper than a regex
		// scan, so skip the scan when the prefix is absent.
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

	// merge folds a rule's findings into seen with first-rule-wins dedup; it
	// must be called in rule (slice) order to keep attribution deterministic.
	merge := func(findings []Finding) {
		for _, f := range findings {
			if _, ok := seen[f.Value]; !ok {
				seen[f.Value] = f
			}
		}
	}

	if len(body) >= parallelScanMinBody {
		// pool.NewWithResults preserves submission order in the returned slice,
		// so iterating it merges rules in slice order — identical dedup to the
		// sequential path.
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

// LiteralPrefixLen returns the byte length of the longest rule literal prefix
// that value begins with — used to keep a credential's recognizable prefix
// intact when garbling. Returns 0 when no rule prefix matches.
func (d *Detector) LiteralPrefixLen(value string) int {
	best := 0
	for _, r := range d.rules {
		if len(r.prefix) > best && strings.HasPrefix(value, r.prefix) {
			best = len(r.prefix)
		}
	}
	return best
}

