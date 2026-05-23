package detect

// rawRule is a vendored detection pattern. group is the regex submatch index
// holding the credential itself (0 = whole match).
type rawRule struct {
	name     string
	severity string
	regex    string
	group    int
}

// rules are credential and PII detection patterns vendored from pipelock
// (github.com/luckyPipewrench/pipelock, Apache-2.0) — its DLP "balanced"
// preset. Validators (luhn/mod97/wif) are not applied; the regex alone drives
// detection. Three context-bearing rules wrap the credential in a capture
// group so only the secret is masked, not the surrounding text.
var rules = []rawRule{
	{"Anthropic API Key", "critical", `sk-ant-[a-zA-Z0-9\-_]{10,}`, 0},
	{"OpenAI API Key", "critical", `sk-proj-[a-zA-Z0-9\-_]{10,}`, 0},
	{"OpenAI Service Key", "critical", `sk-svcacct-[a-zA-Z0-9\-]{10,}`, 0},
	{"Fireworks API Key", "critical", `fw_[a-zA-Z0-9]{24,}`, 0},
	{"Google API Key", "high", `AIza[0-9A-Za-z\-_]{35}`, 0},
	{"Google OAuth Client Secret", "critical", `GOCSPX-[A-Za-z0-9_\-]{28,}`, 0},
	{"Stripe Key", "critical", `[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}`, 0},
	{"Stripe Webhook Secret", "critical", `whsec_[a-zA-Z0-9_\-]{20,}`, 0},
	{"GitHub Token", "critical", `gh[pousr]_[A-Za-z0-9_]{36,}`, 0},
	{"GitHub Fine-Grained PAT", "critical", `github_pat_[a-zA-Z0-9_]{36,}`, 0},
	{"GitLab PAT", "critical", `glpat-[a-zA-Z0-9\-_]{20,}`, 0},
	{"AWS Access ID", "critical", `(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`, 0},
	{"AWS Secret Key", "critical", `(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*([A-Za-z0-9/+=]{40})`, 1},
	{"Google OAuth Token", "critical", `ya29\.[a-zA-Z0-9_-]{20,}`, 0},
	{"Slack Token", "critical", `xox[bpras]-[0-9a-zA-Z-]{15,}`, 0},
	{"Slack App Token", "critical", `xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+`, 0},
	{"Discord Bot Token", "critical", `[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}`, 0},
	{"Twilio API Key", "high", `SK[a-f0-9]{32}`, 0},
	{"SendGrid API Key", "critical", `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, 0},
	{"Mailgun API Key", "high", `key-[a-zA-Z0-9]{32}`, 0},
	{"New Relic API Key", "critical", `NRAK-[A-Z0-9]{27,}`, 0},
	{"Hugging Face Token", "critical", `hf_[A-Za-z0-9]{20,}`, 0},
	{"Databricks Token", "critical", `dapi[a-z0-9]{30,}`, 0},
	{"Replicate API Token", "critical", `r8_[A-Za-z0-9]{20,}`, 0},
	{"Together AI Key", "critical", `tok_[a-z0-9]{40,}`, 0},
	{"Pinecone API Key", "critical", `pcsk_[a-zA-Z0-9]{36,}`, 0},
	{"Groq API Key", "critical", `gsk_[a-zA-Z0-9]{48,}`, 0},
	{"xAI API Key", "critical", `xai-[a-zA-Z0-9\-_]{80,}`, 0},
	{"DigitalOcean Token", "critical", `dop_v1_[a-f0-9]{64}`, 0},
	{"HashiCorp Vault Token", "critical", `hvs\.[a-zA-Z0-9]{23,}`, 0},
	{"Vercel Token", "critical", `(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}`, 0},
	{"Supabase Service Key", "critical", `sb_secret_[a-zA-Z0-9_-]{20,}`, 0},
	{"npm Token", "critical", `npm_[A-Za-z0-9]{36,}`, 0},
	{"PyPI Token", "critical", `pypi-[A-Za-z0-9_-]{16,}`, 0},
	{"Linear API Key", "high", `lin_api_[a-zA-Z0-9]{40,}`, 0},
	{"Notion API Key", "high", `ntn_[a-zA-Z0-9]{40,}`, 0},
	{"Sentry Auth Token", "high", `sntrys_[a-zA-Z0-9]{40,}`, 0},
	{"Private Key Header", "critical", `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`, 0},
	{"JWT Token", "high", `(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}`, 0},
	{"Extended Private Key", "critical", `[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}`, 0},
	{"Ethereum Private Key", "critical", `0x[0-9a-f]{64}`, 0},
	{"Social Security Number", "low", `\d{3}-\d{2}-\d{4}`, 0},
	{"Google OAuth Client ID", "medium", `[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, 0},
	{"Credential in URL", "high", `(?m)(?:^|[?&;])\s*(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*([^\s&]{4,})`, 1},
	{"Environment Variable Secret", "high", `(?-i:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\s*=\s*(\S{8,})`, 1},
}
