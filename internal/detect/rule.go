package detect

import "regexp"

// Rule is one compiled detection pattern contributed by a Provider.
// Group is the regex submatch index holding the credential itself
// (0 = whole match). Severity is one of "low", "medium", "high", "critical".
type Rule struct {
	Name     string
	Severity string
	Regex    *regexp.Regexp
	Group    int
}
