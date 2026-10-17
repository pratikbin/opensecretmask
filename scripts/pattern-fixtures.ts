// Fabricated credentials only. Shared by offline checks and the live runner;
// complete fixture values are generated, never printed by either checker.
export type PatternCase = { name: string; rule: string; value: string; text: string; prefix?: string }

export function patternFixtures(seed = 7): PatternCase[] {
  const rnd = (n: number, alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') => {
    let value = ''
    for (let i = 0; i < n; i++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0
      value += alphabet[seed % alphabet.length]
    }
    return value
  }
  const hex = (n: number) => rnd(n, '0123456789abcdef')
  const uuid = () => `${hex(8)}-${hex(4)}-${hex(4)}-${hex(4)}-${hex(12)}`
  const cases: PatternCase[] = []
  const bare = (rule: string, prefix: string, body: string, name = rule) => {
    const value = prefix + body
    cases.push({ name, rule, value, text: value, prefix })
  }

  bare('OpenRouter API Key', 'sk-or-v1-', hex(64))
  bare('OpenAI Admin Key', 'sk-admin-', rnd(40) + '_-' + rnd(40))
  bare('OpenAI Service Key', 'sk-svcacct-', rnd(20) + '_' + rnd(30), 'OpenAI service underscore')
  bare('Langfuse Secret Key', 'sk-lf-', uuid())
  for (const prefix of ['tvly-', 'tvly-dev-', 'tvly-prod-']) bare('Tavily API Key', 'tvly-', prefix.slice(5) + rnd(32), prefix)
  bare('Firecrawl API Key', 'fc-', hex(32))
  bare('E2B API Key', 'e2b_', hex(40))
  for (const [kind, label] of [
    ['api', 'API Token'], ['auth', 'Auth Key'], ['client', 'OAuth Client Secret'],
    ['scim', 'SCIM Key'], ['webhook', 'Webhook Key'],
  ]) bare(`Tailscale ${label}`, `tskey-${kind}-`, rnd(10) + '-' + rnd(48))
  bare('Fly.io OAuth Token', 'fo1_', rnd(43))
  for (const [prefix, label] of [['fm1a_', 'Access'], ['fm1r_', 'Refresh'], ['fm2_', 'Macaroon']])
    bare(`Fly.io ${label} Token`, prefix!, rnd(100) + '+/==')
  bare('Azure DevOps PAT', '', rnd(75) + 'AZDO' + rnd(5))
  for (const [prefix, kind] of [['squ_', 'User'], ['sqp_', 'Project'], ['sqa_', 'Global']])
    bare(`SonarQube ${kind} Token`, prefix!, hex(40))
  for (const [prefix, kind] of [['pat.', 'Personal'], ['sat.', 'Service']])
    bare(`Harness ${kind} Token`, prefix!, rnd(22) + '.' + rnd(24) + '.' + rnd(20))
  for (const [prefix, kind] of [
    ['bkct_', 'Cluster'], ['bkar_', 'Registration'], ['bkaa_', 'Agent Session'],
    ['bkaj_', 'Agent Job'], ['bkjat_', 'Job Acquisition'],
  ]) bare(`Buildkite ${kind} Token`, prefix!, rnd(73))
  bare('GitLab PAT', 'glpat-', rnd(50) + '.' + hex(9), 'GitLab routable PAT')
  bare('GitLab Runner Authentication Token', 'glrt-', 't1_' + rnd(50) + '.' + hex(9), 'GitLab routable runner')

  return cases
}

export const patternDecoys = [
  // Preserve existing treatment of ambiguous fields; do not widen the scanner.
  '{"apiKey":"' + '0123456789abcdef'.repeat(2) + '"}',
  '{"clientSecret":"configurationValueNotACredential"}',
  '<add key="ClearTextPassword" value="configuration value" />',
  'client_credential: "aB18Q~' + 'x'.repeat(34) + '"',
  'commit ' + '9f2c1e7b3d5a8c04e6f1b2d39c7e5a10aaaa1111',
  'request_id 550e8400-e29b-41d4-a716-446655440000',
  'port: 3000', 'mode: development', 'api_key: ${SERVICE_KEY}',
  'client_secret: <your-client-secret>', 'password: op://vault/item/password',
  'api_key: your_api_key_here', 'password: process.env.DB_PASSWORD',
  'password: import.meta.env.DB_PASSWORD', 'api_key: "pk_live_' + 'a'.repeat(32) + '"',
  'api_key: "pk-lf-550e8400-e29b-41d4-a716-446655440000"',
  'client_id: 550e8400-e29b-41d4-a716-446655440000',
  'public_key: ssh-ed25519 ' + 'A'.repeat(48),
  '_authToken=${NPM_TOKEN}', '--password <password>', 'x-api-key: YOUR_API_KEY',
  'https://example.org/?signature=ordinary-text', 'sk-or-v1-short', 'sk-admin-docs',
  'sk-lf-not-a-uuid', 'tvly-dev-YOUR_API_KEY', 'fc-not-a-key', 'e2b_code_interpreter',
  'squ_docs', 'sqp_short', 'sqa_example', 'pat.docs.example', 'sat.docs.example',
  'bkct_example', 'bkar_example', 'bkaa_example', 'bkaj_example', 'bkjat_example',
  'fo1_short', 'fm1a_example', 'fm1r_example', 'fm2_example',
  'tskey-api-xxxxxxxxxx', 'tskey-auth-xxxxxxxxxx', 'tskey-client-xxxxxxxxxx',
  'tskey-scim-xxxxxxxxxx', 'tskey-webhook-xxxxxxxxxx',
]
