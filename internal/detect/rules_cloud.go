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
}

type cloudProvider struct{}

func (cloudProvider) Name() string  { return "cloud" }
func (cloudProvider) Rules() []Rule { return cloudRules }
