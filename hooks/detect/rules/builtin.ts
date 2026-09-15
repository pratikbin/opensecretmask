import { rule, type Rule } from '../rule'

/**
 * Vendor credentials with a distinctive prefix, plus the two context-bearing
 * shapes (`KEY=value`, `?token=value`) that need a capture group.
 *
 * The private-key rule matches the WHOLE PEM block, not just the header: the
 * header alone is reconstructible, so masking it protects nothing while the
 * base64 body passes through.
 */
export const builtinRules: Rule[] = [
  rule('Anthropic API Key', 'critical', /sk-ant-[a-zA-Z0-9\-_]{10,}/g),
  rule('OpenAI API Key', 'critical', /sk-proj-[a-zA-Z0-9\-_]{10,}/g),
  rule('OpenAI Service Key', 'critical', /sk-svcacct-[a-zA-Z0-9\-]{10,}/g),
  rule('Fireworks API Key', 'critical', /fw_[a-zA-Z0-9]{24,}/g),
  rule('Google API Key', 'high', /AIza[0-9A-Za-z\-_]{35}/g),
  rule('Google OAuth Client Secret', 'critical', /GOCSPX-[A-Za-z0-9_\-]{28,}/g),
  rule('Stripe Key', 'critical', /[sr]k[-_](live|test)[-_][a-zA-Z0-9]{20,}/g),
  rule('Stripe Webhook Secret', 'critical', /whsec_[a-zA-Z0-9_\-]{20,}/g),
  rule('GitHub Token', 'critical', /gh[pousr]_[A-Za-z0-9_]{36,}/g),
  rule('GitHub Fine-Grained PAT', 'critical', /github_pat_[a-zA-Z0-9_]{36,}/g),
  rule('GitLab PAT', 'critical', /glpat-[a-zA-Z0-9\-_]{20,}/g),
  rule(
    'AWS Access ID',
    'critical',
    /(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}/g,
  ),
  rule(
    'AWS Secret Key',
    'critical',
    /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*([A-Za-z0-9/+=]{40})/g,
    1,
  ),
  rule('Google OAuth Token', 'critical', /ya29\.[a-zA-Z0-9_-]{20,}/g),
  rule('Slack Token', 'critical', /xox[bpras]-[0-9a-zA-Z-]{15,}/g),
  rule('Slack App Token', 'critical', /xapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+/g),
  rule(
    'Discord Bot Token',
    'critical',
    /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}/g,
  ),
  rule('Twilio API Key', 'high', /SK[a-f0-9]{32}/g),
  rule('SendGrid API Key', 'critical', /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g),
  rule('Mailgun API Key', 'high', /key-[a-zA-Z0-9]{32}/g),
  rule('New Relic API Key', 'critical', /NRAK-[A-Z0-9]{27,}/g),
  rule('Hugging Face Token', 'critical', /hf_[A-Za-z0-9]{20,}/g),
  rule('Databricks Token', 'critical', /dapi[a-z0-9]{30,}/g),
  rule('Replicate API Token', 'critical', /r8_[A-Za-z0-9]{20,}/g),
  rule('Together AI Key', 'critical', /tok_[a-z0-9]{40,}/g),
  rule('Pinecone API Key', 'critical', /pcsk_[a-zA-Z0-9]{36,}/g),
  rule('Groq API Key', 'critical', /gsk_[a-zA-Z0-9]{48,}/g),
  rule('xAI API Key', 'critical', /xai-[a-zA-Z0-9\-_]{80,}/g),
  rule('DigitalOcean Token', 'critical', /dop_v1_[a-f0-9]{64}/g),
  rule('HashiCorp Vault Token', 'critical', /hvs\.[a-zA-Z0-9]{23,}/g),
  rule('Vercel Token', 'critical', /(?:vercel|vc[piark])_[a-zA-Z0-9]{24,}/g),
  rule('Supabase Service Key', 'critical', /sb_secret_[a-zA-Z0-9_-]{20,}/g),
  rule('npm Token', 'critical', /npm_[A-Za-z0-9]{36,}/g),
  rule('PyPI Token', 'critical', /pypi-[A-Za-z0-9_-]{16,}/g),
  rule('Linear API Key', 'high', /lin_api_[a-zA-Z0-9]{40,}/g),
  rule('Notion API Key', 'high', /ntn_[a-zA-Z0-9]{40,}/g),
  rule('Sentry Auth Token', 'high', /sntrys_[a-zA-Z0-9]{40,}/g),
  // The whole block, BEGIN through END. A header-only match leaves the key
  // material intact and the header is trivially reconstructible.
  rule(
    'Private Key Block',
    'critical',
    /-----BEGIN[^\n-]{0,40}PRIVATE KEY-----[\s\S]{0,20000}?-----END[^\n-]{0,40}PRIVATE KEY-----/g,
  ),
  rule('JWT Token', 'high', /(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}/g),
  rule('Extended Private Key', 'critical', /[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}/g),
  rule('Ethereum Private Key', 'critical', /0x[0-9a-f]{64}/g),
  rule('Social Security Number', 'low', /\d{3}-\d{2}-\d{4}/g),
  rule(
    'Google OAuth Client ID',
    'medium',
    /[0-9]{6,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
  ),
  rule(
    'Credential in URL',
    'high',
    /(?:^|[?&;])\s*(?:password|passwd|secret|token|apikey|api_key|api-key)\s*=\s*([^\s&]{4,})/gm,
    1,
  ),
  // The password inside a connection string: postgres://user:PASSWORD@host.
  // Group 2 alone is masked, so the DSN stays a valid DSN.
  rule(
    'Connection String Password',
    'critical',
    /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/@:]{1,80}:([^\s/@]{3,200})@/gi,
    1,
  ),
  rule(
    'Environment Variable Secret',
    'high',
    /(?:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\s*=\s*(\S{8,})/g,
    1,
  ),
]
