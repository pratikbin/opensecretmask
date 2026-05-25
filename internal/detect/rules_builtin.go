package detect

import "regexp"

// builtinRules are the vendored credential and PII detection patterns
// originally drawn from pipelock (github.com/luckyPipewrench/pipelock,
// Apache-2.0). Validators (luhn/mod97/wif) are not applied; the regex
// alone drives detection. Three context-bearing rules wrap the
// credential in a capture group so only the secret is masked, not the
// surrounding text.
var builtinRules = []Rule{
	{"Anthropic API Key", "critical", regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{10,}`), 0},
	{"OpenAI API Key", "critical", regexp.MustCompile(`sk-proj-[a-zA-Z0-9\-_]{10,}`), 0},
	{"OpenAI Service Key", "critical", regexp.MustCompile(`sk-svcacct-[a-zA-Z0-9\-]{10,}`), 0},
	{"Fireworks API Key", "critical", regexp.MustCompile(`fw_[a-zA-Z0-9]{24,}`), 0},
	{"Google API Key", "high", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), 0},
	{"Google OAuth Client Secret", "critical", regexp.MustCompile(`GOCSPX-[A-Za-z0-9_\-]{28,}`), 0},
	{"Stripe Key", "critical", regexp.MustCompile(`[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}`), 0},
	{"Stripe Webhook Secret", "critical", regexp.MustCompile(`whsec_[a-zA-Z0-9_\-]{20,}`), 0},
	{"GitHub Token", "critical", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), 0},
	{"GitHub Fine-Grained PAT", "critical", regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{36,}`), 0},
	{"GitLab PAT", "critical", regexp.MustCompile(`glpat-[a-zA-Z0-9\-_]{20,}`), 0},
	{"AWS Access ID", "critical", regexp.MustCompile(`(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`), 0},
	{"AWS Secret Key", "critical", regexp.MustCompile(`(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*([A-Za-z0-9/+=]{40})`), 1},
	{"Google OAuth Token", "critical", regexp.MustCompile(`ya29\.[a-zA-Z0-9_-]{20,}`), 0},
	{"Slack Token", "critical", regexp.MustCompile(`xox[bpras]-[0-9a-zA-Z-]{15,}`), 0},
	{"Slack App Token", "critical", regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+`), 0},
	{"Discord Bot Token", "critical", regexp.MustCompile(`[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`), 0},
	{"Twilio API Key", "high", regexp.MustCompile(`SK[a-f0-9]{32}`), 0},
	{"SendGrid API Key", "critical", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), 0},
	{"Mailgun API Key", "high", regexp.MustCompile(`key-[a-zA-Z0-9]{32}`), 0},
	{"New Relic API Key", "critical", regexp.MustCompile(`NRAK-[A-Z0-9]{27,}`), 0},
	{"Hugging Face Token", "critical", regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`), 0},
	{"Databricks Token", "critical", regexp.MustCompile(`dapi[a-z0-9]{30,}`), 0},
	{"Replicate API Token", "critical", regexp.MustCompile(`r8_[A-Za-z0-9]{20,}`), 0},
	{"Together AI Key", "critical", regexp.MustCompile(`tok_[a-z0-9]{40,}`), 0},
	{"Pinecone API Key", "critical", regexp.MustCompile(`pcsk_[a-zA-Z0-9]{36,}`), 0},
	{"Groq API Key", "critical", regexp.MustCompile(`gsk_[a-zA-Z0-9]{48,}`), 0},
	{"xAI API Key", "critical", regexp.MustCompile(`xai-[a-zA-Z0-9\-_]{80,}`), 0},
	{"DigitalOcean Token", "critical", regexp.MustCompile(`dop_v1_[a-f0-9]{64}`), 0},
	{"HashiCorp Vault Token", "critical", regexp.MustCompile(`hvs\.[a-zA-Z0-9]{23,}`), 0},
	{"Vercel Token", "critical", regexp.MustCompile(`(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}`), 0},
	{"Supabase Service Key", "critical", regexp.MustCompile(`sb_secret_[a-zA-Z0-9_-]{20,}`), 0},
	{"npm Token", "critical", regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`), 0},
	{"PyPI Token", "critical", regexp.MustCompile(`pypi-[A-Za-z0-9_-]{16,}`), 0},
	{"Linear API Key", "high", regexp.MustCompile(`lin_api_[a-zA-Z0-9]{40,}`), 0},
	{"Notion API Key", "high", regexp.MustCompile(`ntn_[a-zA-Z0-9]{40,}`), 0},
	{"Sentry Auth Token", "high", regexp.MustCompile(`sntrys_[a-zA-Z0-9]{40,}`), 0},
	{"Private Key Header", "critical", regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`), 0},
	{"JWT Token", "high", regexp.MustCompile(`(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}`), 0},
	{"Extended Private Key", "critical", regexp.MustCompile(`[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}`), 0},
	{"Ethereum Private Key", "critical", regexp.MustCompile(`0x[0-9a-f]{64}`), 0},
	{"Social Security Number", "low", regexp.MustCompile(`\d{3}-\d{2}-\d{4}`), 0},
	{"Google OAuth Client ID", "medium", regexp.MustCompile(`[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), 0},
	{"Credential in URL", "high", regexp.MustCompile(`(?m)(?:^|[?&;])\s*(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*([^\s&]{4,})`), 1},
	{"Environment Variable Secret", "high", regexp.MustCompile(`(?-i:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\s*=\s*(\S{8,})`), 1},
}

type builtinProvider struct{}

func (builtinProvider) Name() string  { return "builtin" }
func (builtinProvider) Rules() []Rule { return builtinRules }
