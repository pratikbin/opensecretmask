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
	// Round-3 (gitleaks): developer-tool, SaaS and package-registry
	// credentials. Adobe's p8e- client secret is distinct from the bare
	// 32-hex client secret the cloud rules deliberately omit; the Sentry
	// user token (sntryu_) is distinct from the sntrys_ auth token in
	// builtinRules.
	{"Adobe Client Secret", "critical", regexp.MustCompile(`p8e-[a-zA-Z0-9]{32}`), 0},
	{"Clojars API Token", "critical", regexp.MustCompile(`CLOJARS_[a-zA-Z0-9]{60}`), 0},
	{"Duffel API Token", "critical", regexp.MustCompile(`duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}`), 0},
	{"Frame.io API Token", "critical", regexp.MustCompile(`fio-u-[a-zA-Z0-9\-_=]{64}`), 0},
	{"Intra42 Client Secret", "critical", regexp.MustCompile(`s-s4t2(?:ud|af)-[a-fA-F0-9]{64}`), 0},
	{"Readme API Token", "critical", regexp.MustCompile(`rdme_[a-z0-9]{70}`), 0},
	{"RubyGems API Token", "critical", regexp.MustCompile(`rubygems_[a-f0-9]{48}`), 0},
	{"Sentry User Token", "critical", regexp.MustCompile(`sntryu_[a-f0-9]{64}`), 0},
	{"Shippo API Token", "critical", regexp.MustCompile(`shippo_(?:live|test)_[a-fA-F0-9]{40}`), 0},
	{"SettleMint Application Access Token", "critical", regexp.MustCompile(`sm_aat_[a-zA-Z0-9]{16}`), 0},
	{"SettleMint Personal Access Token", "critical", regexp.MustCompile(`sm_pat_[a-zA-Z0-9]{16}`), 0},
	{"SettleMint Service Access Token", "critical", regexp.MustCompile(`sm_sat_[a-zA-Z0-9]{16}`), 0},
	// Round-4 (trufflehog catalog + ~/workspace scan): developer-tool, SaaS
	// and fintech credentials. Copperx (pav1_) and FC (skp_) were observed
	// live in the local workspace; the rest are prefix-distinctive secrets
	// cherry-picked from trufflehog's detector set.
	{"CircleCI Personal Access Token", "critical", regexp.MustCompile(`CCIPAT_[0-9A-Za-z]{22}_[0-9A-Fa-f]{40}`), 0},
	{"Contentful Personal Access Token", "critical", regexp.MustCompile(`CFPAT-[A-Za-z0-9_\-]{43}`), 0},
	{"Buildkite User Access Token", "critical", regexp.MustCompile(`bkua_[0-9a-z]{40}`), 0},
	{"Endor Labs API Key", "critical", regexp.MustCompile(`endr\+[A-Za-z0-9\-]{16}`), 0},
	{"Sourcegraph Cody Access Token", "critical", regexp.MustCompile(`slk_[0-9a-f]{64}`), 0},
	{"Flexport API Token", "critical", regexp.MustCompile(`shltm_[A-Za-z0-9_\-]{40}`), 0},
	{"PostHog Personal API Key", "critical", regexp.MustCompile(`phx_[A-Za-z0-9_]{43}`), 0},
	{"Ubidots Token", "critical", regexp.MustCompile(`BBFF-[0-9A-Za-z]{30}`), 0},
	{"Copperx API Key", "critical", regexp.MustCompile(`pav1_[0-9A-Za-z]{64}`), 0},
	{"Robinhood Crypto API Key", "critical", regexp.MustCompile(`rh-api-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`), 0},
	{"Ramp API Secret", "critical", regexp.MustCompile(`ramp_sec_[0-9A-Za-z]{48}`), 0},
	{"Salesforce OAuth Token", "critical", regexp.MustCompile(`3MVG9[A-Za-z0-9._\-+=]{80,251}`), 0},
	{"Salesforce Refresh Token", "critical", regexp.MustCompile(`5AEP861[A-Za-z0-9._=]{80,}`), 0},
	{"Fleetbase API Key", "critical", regexp.MustCompile(`flb_live_[0-9A-Za-z]{20}`), 0},
	{"Intra42 User Token", "critical", regexp.MustCompile(`u-s4t2(?:ud|af)-[0-9a-f]{64}`), 0},
	{"HubSpot Private App Token", "critical", regexp.MustCompile(`pat-(?:eu|na)1-[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}`), 0},
	{"FC API Key", "critical", regexp.MustCompile(`skp_[a-zA-Z0-9]{32}`), 0},
}

type devtoolsProvider struct{}

func (devtoolsProvider) Name() string  { return "devtools" }
func (devtoolsProvider) Rules() []Rule { return devtoolsRules }
