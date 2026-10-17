import { rule, type Rule } from '../rule'

/** Chat-platform tokens and webhook URLs the builtin `xox[bpras]-` rule misses. */
export const chatRules: Rule[] = [
  rule('Slack Config Access Token', 'critical', /xoxe\.xoxp-\d-[A-Za-z0-9-]{40,}/g),
  rule('Slack Config Refresh Token', 'critical', /xoxe-\d-[A-Za-z0-9-]{40,}/g),
  // From the host on, so the scheme may be missing. One rule per path, so the
  // path sits in the literal prefix and the fake keeps it: an alternation
  // there let the fake scramble `services/`. No upper length bound, so a long
  // `workflows/` URL is masked whole. Shape from claude-code-redact's
  // slack-webhook rule (MIT).
  rule('Slack Webhook URL', 'critical', /hooks\.slack\.com\/services\/[A-Za-z0-9+/]{43,}/g),
  rule('Slack Webhook URL', 'critical', /hooks\.slack\.com\/workflows\/[A-Za-z0-9+/]{43,}/g),
  rule('Slack Webhook URL', 'critical', /hooks\.slack\.com\/triggers\/[A-Za-z0-9+/]{43,}/g),
  rule(
    'Discord Webhook URL',
    'critical',
    /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{10,}\/[A-Za-z0-9_\-]{60,}/g,
  ),
  rule(
    'Microsoft Teams Webhook',
    'critical',
    /https:\/\/[a-z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]{36}@[a-f0-9-]{36}\/IncomingWebhook\/[a-f0-9]{32}\/[a-f0-9-]{36}/g,
  ),
]
