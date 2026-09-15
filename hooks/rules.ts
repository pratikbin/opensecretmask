// The detection rules: 138 patterns in six groups.
//
// Policy: prefix-distinctive regexes only, no allowlists, no gitleaks-style
// anchors, so detection stays stateless across JSON bodies, file contents and
// bare tokens. `group` is the submatch index holding the credential itself
// (0 = whole match), so a context-bearing rule masks the secret and not the
// surrounding text.

export type Rule = {
  name: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  re: RegExp
  group: number
}

const rule = (
  name: string,
  severity: Rule['severity'],
  re: RegExp,
  group = 0,
): Rule => ({ name, severity, re, group })

// ------------------------------------------------------------------ builtin

const builtin: Rule[] = [
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
  rule(
    'Private Key Header',
    'critical',
    /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
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
  rule(
    'Environment Variable Secret',
    'high',
    /(?:[A-Z][A-Z0-9]*[_-](?:SECRET(?:[_-]ACCESS)?[_-]?KEY|SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY))\s*=\s*(\S{8,})/g,
    1,
  ),
]

// ---------------------------------------------------------------------- llm

const llm: Rule[] = [
  rule('Perplexity API Key', 'critical', /pplx-[a-zA-Z0-9]{40,}/g),
  rule('AWS Bedrock Long-Lived Key', 'critical', /ABSK[A-Za-z0-9+/]{100,}={0,2}/g),
  rule('AWS Bedrock Short-Lived Key', 'critical', /bedrock-api-key-[A-Za-z0-9+/=]{20,}/g),
  rule('Hugging Face Organization API Token', 'critical', /api_org_[A-Za-z]{34}/g),
  rule('LangSmith API Key', 'critical', /lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/g),
  rule('NVIDIA API Key', 'critical', /nvapi-[A-Za-z0-9_\-]{64}/g),
  rule('OpenAI API Key (legacy)', 'critical', /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g),
]

// -------------------------------------------------------------------- cloud

const cloud: Rule[] = [
  rule(
    'Age Secret Key',
    'critical',
    /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g,
  ),
  rule('Alibaba Access Key ID', 'critical', /LTAI[a-zA-Z0-9]{20}/g),
  rule('Artifactory API Key', 'critical', /AKCp[A-Za-z0-9]{69}/g),
  rule('Cloudflare Origin CA Key', 'critical', /v1\.0-[a-f0-9]{24}-[a-f0-9]{146}/g),
  rule('Doppler Token', 'critical', /dp\.(?:pt|st|sa|ct|scim|audit)\.[a-zA-Z0-9]{40,}/g),
  rule('Dynatrace API Token', 'critical', /dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}/g),
  rule('Flutterwave Secret Key', 'critical', /FLWSECK_TEST-[a-h0-9]{32}-X/g),
  rule('Grafana Cloud API Token', 'critical', /glc_[A-Za-z0-9+/]{32,}={0,2}/g),
  rule('Grafana Service Account Token', 'critical', /glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}/g),
  rule('Heroku API Key v2', 'critical', /HRKU-AA[A-Za-z0-9_\-]{20,}/g),
  rule('Docker PAT', 'critical', /dckr_pat_[A-Za-z0-9_\-]{27,}/g),
  rule('Netlify Access Token', 'critical', /nfp_[A-Za-z0-9]{40,}/g),
  rule('Sendinblue API Token', 'critical', /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}/g),
  rule('Shopify Access Token', 'critical', /shpat_[a-fA-F0-9]{32}/g),
  rule('Shopify Custom Access Token', 'critical', /shpca_[a-fA-F0-9]{32}/g),
  rule('Shopify Private App Access Token', 'critical', /shppa_[a-fA-F0-9]{32}/g),
  rule('Square Access Token', 'critical', /(?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60}/g),
  rule('DigitalOcean OAuth Access Token', 'critical', /doo_v1_[a-f0-9]{64}/g),
  rule('DigitalOcean OAuth Refresh Token', 'critical', /dor_v1_[a-f0-9]{64}/g),
  rule('HashiCorp Vault Batch Token', 'critical', /hvb\.[\w-]{138,300}/g),
  rule('New Relic Insights Insert Key', 'critical', /NRII-[a-zA-Z0-9\-]{32}/g),
  rule('Pulumi API Token', 'critical', /pul-[a-f0-9]{40}/g),
  rule('OpenShift User Token', 'critical', /sha256~[\w-]{43}/g),
  rule('Shopify Shared Secret', 'critical', /shpss_[a-fA-F0-9]{32}/g),
  rule('Scalingo API Token', 'critical', /tk-us-[\w-]{48}/g),
  rule('Defined Networking API Token', 'critical', /dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}/g),
  rule('Rootly API Token', 'critical', /rootly_[0-9a-f]{64}/g),
  rule('SaladCloud API Key', 'critical', /salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235}/g),
  rule('Supabase Personal Access Token', 'critical', /sbp_[0-9a-z]{40}/g),
  rule('Square OAuth Secret', 'critical', /sq0idp-[0-9A-Za-z]{22}/g),
  rule('Flutterwave Live Secret Key', 'critical', /FLWSECK-[0-9a-z]{32}-X/g),
  rule('Artifactory Reference Token', 'critical', /cmVmdGtu[0-9A-Za-z]{56}/g),
]

// --------------------------------------------------------------------- chat

const chat: Rule[] = [
  rule('Slack Config Access Token', 'critical', /xoxe\.xoxp-\d-[A-Za-z0-9-]{40,}/g),
  rule('Slack Config Refresh Token', 'critical', /xoxe-\d-[A-Za-z0-9-]{40,}/g),
  rule(
    'Slack Webhook URL',
    'critical',
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
  ),
  rule(
    'Microsoft Teams Webhook',
    'critical',
    /https:\/\/[a-z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]{36}@[a-f0-9-]{36}\/IncomingWebhook\/[a-f0-9]{32}\/[a-f0-9-]{36}/g,
  ),
]

// ---------------------------------------------------------------------- git

const git: Rule[] = [
  rule('GitLab Pipeline Trigger Token', 'critical', /glptt-[0-9a-f]{40}/g),
  rule('GitLab Runner Registration Token', 'critical', /GR1348941[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab Feed Token', 'high', /glft-[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab Incoming Mail Token', 'high', /glimt-[0-9a-zA-Z_\-]{25}/g),
  rule('GitLab Kubernetes Agent Token', 'critical', /glagent-[0-9a-zA-Z_\-]{50}/g),
  rule('GitLab CI/CD Job Token', 'critical', /glcbt-[0-9a-zA-Z_\-]{20,}/g),
  rule('GitLab Deploy Token', 'critical', /gldt-[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab SCIM Token', 'critical', /glsoat-[0-9a-zA-Z_\-]{20,}/g),
  rule('GitLab OIDC Application Secret', 'critical', /gloas-[0-9a-zA-Z_\-]{64}/g),
  rule('GitLab Runner Authentication Token', 'critical', /glrt-[0-9a-zA-Z_\-]{20}/g),
  rule('GitLab Session Cookie', 'high', /_gitlab_session=([0-9a-z]{32})/g, 1),
]

// ----------------------------------------------------------------- devtools

const devtools: Rule[] = [
  rule('PlanetScale API Token', 'critical', /pscale_tkn_[\w=\.\-]{32,64}/g),
  rule('PlanetScale OAuth Token', 'critical', /pscale_oauth_[\w=\.\-]{32,64}/g),
  rule('PlanetScale Password', 'critical', /pscale_pw_[\w=\.\-]{32,64}/g),
  rule('Postman API Token', 'critical', /PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}/g),
  rule('Prefect API Token', 'critical', /pnu_[a-zA-Z0-9]{36}/g),
  rule('Sourcegraph Access Token', 'critical', /sgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}/g),
  rule('Typeform API Token', 'critical', /tfp_[a-zA-Z0-9\-_\.=]{59}/g),
  rule('Infracost API Token', 'critical', /ico-[a-zA-Z0-9]{32}/g),
  rule('1Password Service Account', 'critical', /ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}/g),
  rule(
    '1Password Secret Key',
    'critical',
    /A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}/g,
  ),
  rule('Adobe Client Secret', 'critical', /p8e-[a-zA-Z0-9]{32}/g),
  rule('Clojars API Token', 'critical', /CLOJARS_[a-zA-Z0-9]{60}/g),
  rule('Duffel API Token', 'critical', /duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}/g),
  rule('Frame.io API Token', 'critical', /fio-u-[a-zA-Z0-9\-_=]{64}/g),
  rule('Intra42 Client Secret', 'critical', /s-s4t2(?:ud|af)-[a-fA-F0-9]{64}/g),
  rule('Readme API Token', 'critical', /rdme_[a-z0-9]{70}/g),
  rule('RubyGems API Token', 'critical', /rubygems_[a-f0-9]{48}/g),
  rule('Sentry User Token', 'critical', /sntryu_[a-f0-9]{64}/g),
  rule('Shippo API Token', 'critical', /shippo_(?:live|test)_[a-fA-F0-9]{40}/g),
  rule('SettleMint Application Access Token', 'critical', /sm_aat_[a-zA-Z0-9]{16}/g),
  rule('SettleMint Personal Access Token', 'critical', /sm_pat_[a-zA-Z0-9]{16}/g),
  rule('SettleMint Service Access Token', 'critical', /sm_sat_[a-zA-Z0-9]{16}/g),
  rule('CircleCI Personal Access Token', 'critical', /CCIPAT_[0-9A-Za-z]{22}_[0-9A-Fa-f]{40}/g),
  rule('Contentful Personal Access Token', 'critical', /CFPAT-[A-Za-z0-9_\-]{43}/g),
  rule('Buildkite User Access Token', 'critical', /bkua_[0-9a-z]{40}/g),
  rule('Endor Labs API Key', 'critical', /endr\+[A-Za-z0-9\-]{16}/g),
  rule('Sourcegraph Cody Access Token', 'critical', /slk_[0-9a-f]{64}/g),
  rule('Flexport API Token', 'critical', /shltm_[A-Za-z0-9_\-]{40}/g),
  rule('PostHog Personal API Key', 'critical', /phx_[A-Za-z0-9_]{43}/g),
  rule('Ubidots Token', 'critical', /BBFF-[0-9A-Za-z]{30}/g),
  rule('Copperx API Key', 'critical', /pav1_[0-9A-Za-z]{64}/g),
  rule(
    'Robinhood Crypto API Key',
    'critical',
    /rh-api-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/g,
  ),
  rule('Ramp API Secret', 'critical', /ramp_sec_[0-9A-Za-z]{48}/g),
  rule('Salesforce OAuth Token', 'critical', /3MVG9[A-Za-z0-9._\-+=]{80,251}/g),
  rule('Salesforce Refresh Token', 'critical', /5AEP861[A-Za-z0-9._=]{80,}/g),
  rule('Fleetbase API Key', 'critical', /flb_live_[0-9A-Za-z]{20}/g),
  rule('Intra42 User Token', 'critical', /u-s4t2(?:ud|af)-[0-9a-f]{64}/g),
  rule(
    'HubSpot Private App Token',
    'critical',
    /pat-(?:eu|na)1-[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}/g,
  ),
  rule('FC API Key', 'critical', /skp_[a-zA-Z0-9]{32}/g),
]

/**
 * Every rule, in provider order. When two rules match the same span the
 * first one wins.
 */
export const RULES: readonly Rule[] = [
  ...builtin,
  ...llm,
  ...cloud,
  ...chat,
  ...git,
  ...devtools,
]
