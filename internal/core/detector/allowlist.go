package detector

import "regexp"

type AllowlistSet struct {
	values        map[string]struct{}
	patterns      []*regexp.Regexp
	rulesDisabled map[string]struct{}
}

func NewAllowlistSet(values []string, patterns []string, disabled []string) (*AllowlistSet, error) {
	a := &AllowlistSet{
		values:        make(map[string]struct{}),
		rulesDisabled: make(map[string]struct{}),
	}
	for _, v := range values {
		a.values[v] = struct{}{}
	}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		a.patterns = append(a.patterns, re)
	}
	for _, r := range disabled {
		a.rulesDisabled[r] = struct{}{}
	}
	return a, nil
}

func (a *AllowlistSet) AllowsValue(v string) bool {
	if a == nil {
		return false
	}
	if _, ok := a.values[v]; ok {
		return true
	}
	for _, re := range a.patterns {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

func (a *AllowlistSet) RuleDisabled(id string) bool {
	if a == nil {
		return false
	}
	_, ok := a.rulesDisabled[id]
	return ok
}
