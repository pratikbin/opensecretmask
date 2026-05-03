package claudecode

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/pratikbin/opensecretmask/internal/harness"
)

type Adapter struct{}

func New() Adapter { return Adapter{} }

func (Adapter) Name() string { return "claudecode" }

func (Adapter) EventDirection(event, tool string) (harness.Direction, error) {
	return eventDirection(event, tool)
}

type rawEnvelope struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	SessionID     string          `json:"session_id"`
	Cwd           string          `json:"cwd"`
	Prompt        string          `json:"prompt"`
	Source        string          `json:"source"`
}

func (a Adapter) ParseRequest(r io.Reader) (*harness.Request, json.RawMessage, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	var hdr rawEnvelope
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, raw, fmt.Errorf("claudecode: parse: %w", err)
	}
	req := &harness.Request{
		Harness:   "claudecode",
		SessionID: hdr.SessionID,
		EventName: hdr.HookEventName,
		ToolName:  hdr.ToolName,
		Cwd:       hdr.Cwd,
	}
	dir, err := eventDirection(hdr.HookEventName, hdr.ToolName)
	if err != nil {
		return nil, raw, err
	}
	req.Direction = dir
	switch hdr.HookEventName {
	case EventPostToolUse:
		for _, p := range postToolUseFields(hdr.ToolName) {
			vals, _ := extractByPath(hdr.ToolResponse, p)
			for _, v := range vals {
				req.Targets = append(req.Targets, harness.Target{Path: p, Content: v, Encoding: "utf8"})
			}
		}
	case EventPreToolUse:
		for _, p := range preToolUseFields(hdr.ToolName) {
			vals, _ := extractByPath(hdr.ToolInput, p)
			for _, v := range vals {
				req.Targets = append(req.Targets, harness.Target{Path: p, Content: v, Encoding: "utf8"})
			}
		}
	case EventUserPromptSubmit:
		req.Targets = []harness.Target{{Path: []string{"prompt"}, Content: hdr.Prompt, Encoding: "utf8"}}
	case EventSessionStart:
		// no targets
	}
	return req, raw, nil
}

// EmitResponse writes claudecode hook output. Behavior per event:
// - PostToolUse: hookSpecificOutput.updatedToolOutput = modified tool_response
// - PreToolUse: hookSpecificOutput.permissionDecision + updatedInput = modified tool_input
// - UserPromptSubmit: hookSpecificOutput.additionalContext (when notes set)
// - DenyReason set: { "decision": "block", "reason": "..." }
// - SessionStart or no modifications: empty {}
func (a Adapter) EmitResponse(w io.Writer, original json.RawMessage, resp *harness.Response) error {
	if resp == nil {
		_, err := w.Write([]byte("{}"))
		return err
	}
	if resp.DenyReason != "" {
		out := map[string]any{
			"decision": "block",
			"reason":   resp.DenyReason,
		}
		return json.NewEncoder(w).Encode(out)
	}
	var hdr rawEnvelope
	if len(original) > 0 {
		_ = json.Unmarshal(original, &hdr)
	}
	switch hdr.HookEventName {
	case EventPostToolUse:
		if !resp.Modified {
			_, err := w.Write([]byte("{}"))
			return err
		}
		updated, err := applyTargets(hdr.ToolResponse, resp.Targets)
		if err != nil {
			return err
		}
		out := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":     "PostToolUse",
				"updatedToolOutput": json.RawMessage(updated),
			},
		}
		return json.NewEncoder(w).Encode(out)
	case EventPreToolUse:
		if !resp.Modified {
			_, err := w.Write([]byte("{}"))
			return err
		}
		updated, err := applyTargets(hdr.ToolInput, resp.Targets)
		if err != nil {
			return err
		}
		out := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "allow",
				"permissionDecisionReason": "opensecretmask",
				"updatedInput":             json.RawMessage(updated),
			},
		}
		return json.NewEncoder(w).Encode(out)
	case EventUserPromptSubmit:
		if len(resp.Notes) == 0 {
			_, err := w.Write([]byte("{}"))
			return err
		}
		out := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":     "UserPromptSubmit",
				"additionalContext": joinNotes(resp.Notes),
			},
		}
		return json.NewEncoder(w).Encode(out)
	default:
		_, err := w.Write([]byte("{}"))
		return err
	}
}

func joinNotes(notes []string) string {
	out := ""
	for i, n := range notes {
		if i > 0 {
			out += "\n"
		}
		out += n
	}
	return out
}

// applyTargets groups Targets by Path and replaces leaves in raw using the
// Targets' Content as replacement values.
func applyTargets(raw json.RawMessage, targets []harness.Target) (json.RawMessage, error) {
	if len(targets) == 0 {
		return raw, nil
	}
	// group by path
	byPath := map[string][][]string{} // pathKey → slice of values batches preserving order
	pathOrder := []string{}
	pathLookup := map[string][]string{}
	for _, t := range targets {
		key := joinPath(t.Path)
		if _, ok := byPath[key]; !ok {
			pathOrder = append(pathOrder, key)
			pathLookup[key] = t.Path
		}
		byPath[key] = append(byPath[key], []string{t.Content})
	}
	cur := raw
	for _, key := range pathOrder {
		path := pathLookup[key]
		batches := byPath[key]
		flat := make([]string, 0, len(batches))
		for _, b := range batches {
			flat = append(flat, b...)
		}
		next, err := replaceByPath(cur, path, flat)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

func joinPath(p []string) string {
	out := ""
	for i, c := range p {
		if i > 0 {
			out += "."
		}
		out += c
	}
	return out
}
