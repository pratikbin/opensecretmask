package detect

import "regexp"

// devtoolsRules cover developer/engineering tool credentials cherry-picked
// from the gitleaks catalog (round-2 expansion). Same anchor-strip policy
// as the other rules_<domain>.go files: only distinctive-prefix patterns
// are included; vendors whose tokens require keyword context (Snyk's bare
// UUID, Sonar's plain alphanum, Twitter, Plaid) are deliberately omitted —
// without an allowlist engine they would FP on routine prompt text.
var devtoolsRules = []Rule{
	{"PlanetScale API Token", "critical", regexp.MustCompile(`pscale_tkn_[\w=\.\-]{32,64}`), 0},
	{"PlanetScale OAuth Token", "critical", regexp.MustCompile(`pscale_oauth_[\w=\.\-]{32,64}`), 0},
	{"PlanetScale Password", "critical", regexp.MustCompile(`pscale_pw_[\w=\.\-]{32,64}`), 0},
	{"Postman API Token", "critical", regexp.MustCompile(`PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}`), 0},
	{"Prefect API Token", "critical", regexp.MustCompile(`pnu_[a-zA-Z0-9]{36}`), 0},
	{"Sourcegraph Access Token", "critical", regexp.MustCompile(`sgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}`), 0},
	{"Typeform API Token", "critical", regexp.MustCompile(`tfp_[a-zA-Z0-9\-_\.=]{59}`), 0},
	{"Infracost API Token", "critical", regexp.MustCompile(`ico-[a-zA-Z0-9]{32}`), 0},
	{"1Password Service Account", "critical", regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`), 0},
	{"1Password Secret Key", "critical", regexp.MustCompile(`A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`), 0},
}

type devtoolsProvider struct{}

func (devtoolsProvider) Name() string  { return "devtools" }
func (devtoolsProvider) Rules() []Rule { return devtoolsRules }
