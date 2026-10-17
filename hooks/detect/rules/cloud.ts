import { rule, type Rule } from '../rule'

/** Cloud, hosting, IaC and observability credentials. See PATTERNS.md. */
export const cloudRules: Rule[] = [
  rule('Tailscale API Token', 'critical', /\btskey-api-[A-Za-z0-9]{10,32}-[A-Za-z0-9]{16,128}(?![\w-])/g),
  rule('Tailscale Auth Key', 'critical', /\btskey-auth-[A-Za-z0-9]{10,32}-[A-Za-z0-9]{16,128}(?![\w-])/g),
  rule('Tailscale OAuth Client Secret', 'critical', /\btskey-client-[A-Za-z0-9]{10,32}-[A-Za-z0-9]{16,128}(?![\w-])/g),
  rule('Tailscale SCIM Key', 'critical', /\btskey-scim-[A-Za-z0-9]{10,32}-[A-Za-z0-9]{16,128}(?![\w-])/g),
  rule('Tailscale Webhook Key', 'critical', /\btskey-webhook-[A-Za-z0-9]{10,32}-[A-Za-z0-9]{16,128}(?![\w-])/g),
  rule('Fly.io OAuth Token', 'critical', /\bfo1_[A-Za-z0-9_-]{43}(?![\w-])/g),
  rule('Fly.io Access Token', 'critical', /\bfm1a_[A-Za-z0-9+/]{100,}={0,3}(?![\w+/=-])/g),
  rule('Fly.io Refresh Token', 'critical', /\bfm1r_[A-Za-z0-9+/]{100,}={0,3}(?![\w+/=-])/g),
  rule('Fly.io Macaroon Token', 'critical', /\bfm2_[A-Za-z0-9+/]{100,}={0,3}(?![\w+/=-])/g),
  // Modern PATs have an embedded signature, not a distinctive prefix. The
  // fake keeps `AZDO` through `SIGNATURES` in detect/index.ts.
  rule('Azure DevOps PAT', 'critical', /(?<![\w-])[A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5}(?![\w-])/g),
  rule(
    'Age Secret Key',
    'critical',
    /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g,
  ),
  rule('Alibaba Access Key ID', 'critical', /LTAI[a-zA-Z0-9]{20}/g),
  // A context rule: 86 base64 characters and `==` after `AccountKey=` or a
  // storage-key name. Group 1 alone is masked, so a connection string keeps
  // its shape. From claude-code-redact's azure-storage-key rule (MIT).
  rule(
    'Azure Storage Account Key',
    'critical',
    /(?:AccountKey|azure[_.-]?storage[_.-]?(?:account[_.-]?)?key|storage[_.-]?account[_.-]?key)["'`]?[ \t]{0,5}[=:][ \t]{0,5}["'`]?([A-Za-z0-9+/]{86}==)/gi,
    1,
  ),
  rule('Artifactory API Key', 'critical', /AKCp[A-Za-z0-9]{69}/g),
  rule('Cloudflare Origin CA Key', 'critical', /v1\.0-[a-f0-9]{24}-[a-f0-9]{146}/g),
  rule('Doppler Token', 'critical', /dp\.(?:pt|st|sa|ct|scim|audit)\.[a-zA-Z0-9]{40,}/g),
  rule('Dynatrace API Token', 'critical', /dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}/g),
  rule('Flutterwave Secret Key', 'critical', /FLWSECK_TEST-[a-h0-9]{32}-X/g),
  rule('Flutterwave Live Secret Key', 'critical', /FLWSECK-[0-9a-z]{32}-X/g),
  rule('Grafana Cloud API Token', 'critical', /glc_[A-Za-z0-9+/]{32,}={0,2}/g),
  rule('Grafana Service Account Token', 'critical', /glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}/g),
  rule('Heroku API Key v2', 'critical', /HRKU-AA[A-Za-z0-9_\-]{20,}/g),
  rule('Docker PAT', 'critical', /dckr_pat_[A-Za-z0-9_\-]{27,}/g),
  rule('Netlify Access Token', 'critical', /nfp_[A-Za-z0-9]{40,}/g),
  rule('Sendinblue API Token', 'critical', /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}/g),
  rule('Shopify Access Token', 'critical', /shpat_[a-fA-F0-9]{32}/g),
  rule('Shopify Custom Access Token', 'critical', /shpca_[a-fA-F0-9]{32}/g),
  rule('Shopify Private App Access Token', 'critical', /shppa_[a-fA-F0-9]{32}/g),
  rule('Shopify Shared Secret', 'critical', /shpss_[a-fA-F0-9]{32}/g),
  rule('Square Access Token', 'critical', /(?:EAAA|sq0atp-)[A-Za-z0-9_\-]{22,60}/g),
  rule('Square OAuth Secret', 'critical', /sq0idp-[0-9A-Za-z]{22}/g),
  rule('DigitalOcean OAuth Access Token', 'critical', /doo_v1_[a-f0-9]{64}/g),
  rule('DigitalOcean OAuth Refresh Token', 'critical', /dor_v1_[a-f0-9]{64}/g),
  rule('HashiCorp Vault Batch Token', 'critical', /hvb\.[\w-]{138,300}/g),
  rule('New Relic Insights Insert Key', 'critical', /NRII-[a-zA-Z0-9\-]{32}/g),
  rule('Pulumi API Token', 'critical', /pul-[a-f0-9]{40}/g),
  rule('OpenShift User Token', 'critical', /sha256~[\w-]{43}/g),
  rule('Scalingo API Token', 'critical', /tk-us-[\w-]{48}/g),
  rule('Defined Networking API Token', 'critical', /dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}/g),
  rule('Rootly API Token', 'critical', /rootly_[0-9a-f]{64}/g),
  rule('SaladCloud API Key', 'critical', /salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235}/g),
  rule('Supabase Personal Access Token', 'critical', /sbp_[0-9a-z]{40}/g),
  rule('Artifactory Reference Token', 'critical', /cmVmdGtu[0-9A-Za-z]{56}/g),
  // The organisation id sits before `.atlasv1.`, so only the token half is
  // masked and the value stays recognisable as a Terraform Cloud token.
  rule('Terraform Cloud Token', 'critical', /[A-Za-z0-9]{14}\.atlasv1\.([A-Za-z0-9_-]{60,})/g, 1),
  // A Sentry DSN is a URL whose user part is the key. Group 1 keeps the URL.
  rule('Sentry DSN', 'high', /https:\/\/([a-f0-9]{32})@[\w.-]+\/\d+/g, 1),
]
