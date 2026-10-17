import { rule, type Rule } from '../rule'

/**
 * LLM-vendor keys.
 *
 * Unprefixed keys (Cohere, Mistral, DeepSeek, Exa, …) need explicit
 * registration or the existing credential-context rules. Do not guess from
 * a bare hash or UUID. Format sources are listed in PATTERNS.md.
 */
export const llmRules: Rule[] = [
  rule('OpenRouter API Key', 'critical', /\bsk-or-v1-[a-f0-9]{64}(?![\w-])/g),
  rule('OpenAI Admin Key', 'critical', /\bsk-admin-[A-Za-z0-9_-]{24,}(?![\w-])/g),
  rule('Langfuse Secret Key', 'critical', /\bsk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?![\w-])/g),
  // One rule per environment so `dev-`/`prod-` is prefix and survives the fake.
  rule('Tavily API Key', 'critical', /\btvly-dev-[A-Za-z0-9]{32}(?![\w-])/g),
  rule('Tavily API Key', 'critical', /\btvly-prod-[A-Za-z0-9]{32}(?![\w-])/g),
  rule('Tavily API Key', 'critical', /\btvly-[A-Za-z0-9]{32}(?![\w-])/g),
  rule('Firecrawl API Key', 'critical', /\bfc-[a-f0-9]{32}(?![\w-])/g),
  rule('E2B API Key', 'critical', /\be2b_[a-f0-9]{40}(?![\w-])/g),
  rule('Perplexity API Key', 'critical', /pplx-[a-zA-Z0-9]{40,}/g),
  rule('AWS Bedrock Long-Lived Key', 'critical', /ABSK[A-Za-z0-9+/]{100,}={0,2}/g),
  rule('AWS Bedrock Short-Lived Key', 'critical', /bedrock-api-key-[A-Za-z0-9+/=]{20,}/g),
  rule('Hugging Face Organization API Token', 'critical', /api_org_[A-Za-z]{34}/g),
  rule('LangSmith API Key', 'critical', /lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/g),
  rule('NVIDIA API Key', 'critical', /nvapi-[A-Za-z0-9_\-]{64}/g),
  // Pinned by the T3BlbkFJ infix, which makes it false-positive proof.
  rule('OpenAI API Key (legacy)', 'critical', /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g),
  // The bare 48-character form, with no infix. The first lookahead refuses
  // one character repeated (`sk-aaaa…`, a filler), the last keeps it from
  // claiming the head of a longer token. `\b` keeps it out of `risk-…` and
  // `task-…` and leaves the `sk-` gate intact. From claude-code-redact (MIT).
  rule('OpenAI API Key (legacy, 48)', 'critical', /\bsk-(?!([A-Za-z0-9])\1{47})[A-Za-z0-9]{48}(?![\w-])/g),
]
