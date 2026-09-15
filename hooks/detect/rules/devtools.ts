import { rule, type Rule } from '../rule'

/**
 * Developer-tool, SaaS and fintech credentials.
 *
 * Vendors whose tokens need keyword context are deliberately absent: Snyk's
 * bare UUID, Sonar's plain alphanumeric, Twitter and Plaid. Without an
 * allowlist engine they would fire on routine prompt text.
 */
export const devtoolsRules: Rule[] = [
  rule('PlanetScale API Token', 'critical', /pscale_tkn_[\w=\.\-]{32,64}/g),
  rule('PlanetScale OAuth Token', 'critical', /pscale_oauth_[\w=\.\-]{32,64}/g),
  rule('PlanetScale Password', 'critical', /pscale_pw_[\w=\.\-]{32,64}/g),
  rule('Postman API Token', 'critical', /PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}/g),
  rule('Prefect API Token', 'critical', /pnu_[a-zA-Z0-9]{36}/g),
  rule('Sourcegraph Access Token', 'critical', /sgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}/g),
  rule('Sourcegraph Cody Access Token', 'critical', /slk_[0-9a-f]{64}/g),
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
  rule('Intra42 User Token', 'critical', /u-s4t2(?:ud|af)-[0-9a-f]{64}/g),
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
  rule(
    'HubSpot Private App Token',
    'critical',
    /pat-(?:eu|na)1-[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}/g,
  ),
  rule('FC API Key', 'critical', /skp_[a-zA-Z0-9]{32}/g),
]
