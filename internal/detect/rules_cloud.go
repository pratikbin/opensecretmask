package detect

import "regexp"

// cloudRules are cloud-provider and infra-tool credential patterns
// cherry-picked from the gitleaks catalog. Same anchor-strip policy as
// llmRules: vendors whose keys lack a distinctive prefix (Adobe 32-hex,
// Azure-AD bare GUID, Coinbase 64-char alphanumeric) are omitted to
// avoid FP storms without an allowlist engine.
var cloudRules = []Rule{
	{"Age Secret Key", "critical", regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`), 0},
	{"Alibaba Access Key ID", "critical", regexp.MustCompile(`LTAI[a-zA-Z0-9]{20}`), 0},
	{"Artifactory API Key", "critical", regexp.MustCompile(`AKCp[A-Za-z0-9]{69}`), 0},
	{"Cloudflare Origin CA Key", "critical", regexp.MustCompile(`v1\.0-[a-f0-9]{24}-[a-f0-9]{146}`), 0},
	{"Doppler Token", "critical", regexp.MustCompile(`dp\.(?:pt|st|sa|ct|scim|audit)\.[a-zA-Z0-9]{40,}`), 0},
	{"Dynatrace API Token", "critical", regexp.MustCompile(`dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}`), 0},
	{"Flutterwave Secret Key", "critical", regexp.MustCompile(`FLWSECK_TEST-[a-h0-9]{32}-X`), 0},
	{"Grafana Cloud API Token", "critical", regexp.MustCompile(`glc_[A-Za-z0-9+/]{32,}={0,2}`), 0},
	{"Grafana Service Account Token", "critical", regexp.MustCompile(`glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}`), 0},
	{"Heroku API Key v2", "critical", regexp.MustCompile(`HRKU-AA[A-Za-z0-9_\-]{20,}`), 0},
	{"Docker PAT", "critical", regexp.MustCompile(`dckr_pat_[A-Za-z0-9_\-]{27,}`), 0},
	{"Netlify Access Token", "critical", regexp.MustCompile(`nfp_[A-Za-z0-9]{40,}`), 0},
	{"Sendinblue API Token", "critical", regexp.MustCompile(`xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}`), 0},
	{"Shopify Access Token", "critical", regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`), 0},
	{"Shopify Custom Access Token", "critical", regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`), 0},
	{"Shopify Private App Access Token", "critical", regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`), 0},
	{"Square Access Token", "critical", regexp.MustCompile(`(?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60}`), 0},
	// Round-3 (gitleaks): additional cloud/hosting, IaC, infra and
	// observability credentials. DigitalOcean OAuth access/refresh tokens
	// are distinct from the dop_v1_ personal token in builtinRules; the
	// New Relic insert key is distinct from the NRAK- user key there.
	{"DigitalOcean OAuth Access Token", "critical", regexp.MustCompile(`doo_v1_[a-f0-9]{64}`), 0},
	{"DigitalOcean OAuth Refresh Token", "critical", regexp.MustCompile(`dor_v1_[a-f0-9]{64}`), 0},
	{"HashiCorp Vault Batch Token", "critical", regexp.MustCompile(`hvb\.[\w-]{138,300}`), 0},
	{"New Relic Insights Insert Key", "critical", regexp.MustCompile(`NRII-[a-zA-Z0-9\-]{32}`), 0},
	{"Pulumi API Token", "critical", regexp.MustCompile(`pul-[a-f0-9]{40}`), 0},
	{"OpenShift User Token", "critical", regexp.MustCompile(`sha256~[\w-]{43}`), 0},
	{"Shopify Shared Secret", "critical", regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`), 0},
	{"Scalingo API Token", "critical", regexp.MustCompile(`tk-us-[\w-]{48}`), 0},
	{"Defined Networking API Token", "critical", regexp.MustCompile(`dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}`), 0},
	// Round-4 (trufflehog catalog): cloud/hosting, observability and
	// platform credentials. FLWSECK- is the live secret-key variant of the
	// FLWSECK_TEST- test key above; sq0idp- is the Square OAuth secret,
	// distinct from the EAAA/sq0atp- access token.
	{"Rootly API Token", "critical", regexp.MustCompile(`rootly_[0-9a-f]{64}`), 0},
	{"SaladCloud API Key", "critical", regexp.MustCompile(`salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235}`), 0},
	{"Supabase Personal Access Token", "critical", regexp.MustCompile(`sbp_[0-9a-z]{40}`), 0},
	{"Square OAuth Secret", "critical", regexp.MustCompile(`sq0idp-[0-9A-Za-z]{22}`), 0},
	{"Flutterwave Live Secret Key", "critical", regexp.MustCompile(`FLWSECK-[0-9a-z]{32}-X`), 0},
	{"Artifactory Reference Token", "critical", regexp.MustCompile(`cmVmdGtu[0-9A-Za-z]{56}`), 0},
}

type cloudProvider struct{}

func (cloudProvider) Name() string  { return "cloud" }
func (cloudProvider) Rules() []Rule { return cloudRules }
