import { rule, type Rule } from '../rule'

/** Chat-platform tokens and webhook URLs the builtin `xox[bpras]-` rule misses. */
export const chatRules: Rule[] = [
  rule('Slack Config Access Token', 'critical', /xoxe\.xoxp-\d-[A-Za-z0-9-]{40,}/g),
  rule('Slack Config Refresh Token', 'critical', /xoxe-\d-[A-Za-z0-9-]{40,}/g),
  rule(
    'Slack Webhook URL',
    'critical',
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
  ),
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
