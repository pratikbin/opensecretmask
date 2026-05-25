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
}

type llmProvider struct{}

func (llmProvider) Name() string  { return "llm" }
func (llmProvider) Rules() []Rule { return llmRules }
