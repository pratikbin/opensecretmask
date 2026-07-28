package detect

import "regexp"

// llmRules are LLM-vendor API key patterns cherry-picked from the
// gitleaks catalog. Anchors removed to keep detection stateless across
// JSON bodies, header values, and bare tokens. Each rule has a
// distinctive prefix; vendors whose keys lack one (Cohere's bare 40-
// char alphanumeric, Mistral's bare token) are deliberately omitted —
// without an allowlist they would FP on routine prompt text.
//
// Anthropic admin keys (sk-ant-admin01-) are already caught by the
// builtin "Anthropic API Key" rule's loose prefix; adding a dedicated
// admin rule would only add attribution, not coverage.
var llmRules = []Rule{
	{"Perplexity API Key", "critical", regexp.MustCompile(`pplx-[a-zA-Z0-9]{40,}`), 0},
	{"AWS Bedrock Long-Lived Key", "critical", regexp.MustCompile(`ABSK[A-Za-z0-9+/]{100,}={0,2}`), 0},
	{"AWS Bedrock Short-Lived Key", "critical", regexp.MustCompile(`bedrock-api-key-[A-Za-z0-9+/=]{20,}`), 0},
	// Round-3 (gitleaks): organization-scoped Hugging Face token, distinct
	// from the personal hf_ token already in builtinRules.
	{"Hugging Face Organization API Token", "critical", regexp.MustCompile(`api_org_[A-Za-z]{34}`), 0},
	// Round-4 (trufflehog catalog + ~/workspace scan): additional LLM-vendor
	// keys. The legacy OpenAI key is pinned by its T3BlbkFJ infix (FP-proof).
	// DeepSeek's bare "sk-" + 32-hex format was evaluated and dropped: no
	// distinguishing infix exists, so it false-positives on any sku/slug id
	// of the same shape (e.g. {"sku":"sk-0123...ef"}) even with a \b anchor.
	{"LangSmith API Key", "critical", regexp.MustCompile(`lsv2_(?:pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}`), 0},
	{"NVIDIA API Key", "critical", regexp.MustCompile(`nvapi-[A-Za-z0-9_\-]{64}`), 0},
	{"OpenAI API Key (legacy)", "critical", regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), 0},
}

type llmProvider struct{}

func (llmProvider) Name() string  { return "llm" }
func (llmProvider) Rules() []Rule { return llmRules }
