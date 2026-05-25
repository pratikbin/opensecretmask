package detect

import "regexp"

// chatRules add chat-platform credentials the builtin xox[bpras]- rule
// misses: Slack config (xoxe) tokens and webhook URLs, plus the
// Microsoft Teams incoming webhook shape.
var chatRules = []Rule{
	{"Slack Config Access Token", "critical", regexp.MustCompile(`xoxe\.xoxp-\d-[A-Za-z0-9-]{40,}`), 0},
	{"Slack Config Refresh Token", "critical", regexp.MustCompile(`xoxe-\d-[A-Za-z0-9-]{40,}`), 0},
	{"Slack Webhook URL", "critical", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`), 0},
	{"Microsoft Teams Webhook", "critical", regexp.MustCompile(`https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}`), 0},
}

type chatProvider struct{}

func (chatProvider) Name() string  { return "chat" }
func (chatProvider) Rules() []Rule { return chatRules }
