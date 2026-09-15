import { rule, type Rule } from '../rule'

/**
 * LLM-vendor keys.
 *
 * Vendors whose keys lack a distinctive prefix are deliberately absent:
 * Cohere's bare 40-char alphanumeric, Mistral's bare token, and DeepSeek's
 * `sk-` + 32 hex, which false-positives on any sku or slug of that shape.
 */
export const llmRules: Rule[] = [
  rule('Perplexity API Key', 'critical', /pplx-[a-zA-Z0-9]{40,}/g),
  rule('AWS Bedrock Long-Lived Key', 'critical', /ABSK[A-Za-z0-9+/]{100,}={0,2}/g),
  rule('AWS Bedrock Short-Lived Key', 'critical', /bedrock-api-key-[A-Za-z0-9+/=]{20,}/g),
  rule('Hugging Face Organization API Token', 'critical', /api_org_[A-Za-z]{34}/g),
  rule('LangSmith API Key', 'critical', /lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/g),
  rule('NVIDIA API Key', 'critical', /nvapi-[A-Za-z0-9_\-]{64}/g),
  // Pinned by the T3BlbkFJ infix, which makes it false-positive proof.
  rule('OpenAI API Key (legacy)', 'critical', /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g),
]
