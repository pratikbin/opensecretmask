package detector

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

// Known issues regression tests gated by t.Skip. See CLAUDE.md "Known issues".

// Bug #3: rules.go:110 sets EndMarker: "-----END " for the pem-private-key
// rule (loose substring match). The SSH rule at line 140 uses the exact
// terminator "-----END OPENSSH PRIVATE KEY-----". The PEM rule's pattern
// regex still gates final acceptance, but the loose container marker can
// admit unintended boundaries during streaming/container scanning. Fix:
// tighten EndMarker to "-----END [A-Z ]*PRIVATE KEY-----" or rely on the
// regex anchor exclusively.
func TestPEMEndMarker_LooseMatch_KnownBug(t *testing.T) {
	t.Skip("known: see CLAUDE.md known issues — rules.go:110 EndMarker '-----END ' " +
		"is loose; SSH variant at rules.go:140 is exact. Tighten on next pass.")

	rules := BuiltinRules()
	var pem *transformer.Rule
	for i := range rules {
		if rules[i].ID == "pem-private-key" {
			pem = &rules[i]
			break
		}
	}
	require.NotNil(t, pem, "pem-private-key rule missing from BuiltinRules")
	require.NotEqual(t, "-----END ", pem.EndMarker,
		"post-fix: EndMarker must be tightened to a specific terminator, not '-----END '")
	require.True(t, strings.Contains(pem.EndMarker, "PRIVATE KEY"),
		"post-fix: EndMarker should reference PRIVATE KEY token explicitly")
}
