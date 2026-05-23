// Package proxy implements the v2 transparent HTTP reverse proxy harness.
// It sits between an AI agent (e.g. Claude Code) and api.anthropic.com,
// masking outbound credentials in known JSON fields and unmasking inbound
// JSON / SSE responses.
package proxy
