package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/harness"
	"github.com/stretchr/testify/require"
)

func TestParseRequest_PostToolUseRead(t *testing.T) {
	in := `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"sk_live_xyz"},"session_id":"s","cwd":"/c"}`
	req, raw, err := New().ParseRequest(strings.NewReader(in))
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Equal(t, "PostToolUse", req.EventName)
	require.Equal(t, "Read", req.ToolName)
	require.Equal(t, harness.DirMask, req.Direction)
	require.Equal(t, "s", req.SessionID)
	require.Equal(t, "/c", req.Cwd)
	require.Len(t, req.Targets, 1)
	require.Equal(t, []string{"content"}, req.Targets[0].Path)
	require.Equal(t, "sk_live_xyz", req.Targets[0].Content)
}

func TestParseRequest_PreToolUseEdit(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"old_string":"O","new_string":"N"}}`
	req, _, err := New().ParseRequest(strings.NewReader(in))
	require.NoError(t, err)
	require.Equal(t, harness.DirUnmask, req.Direction)
	require.Len(t, req.Targets, 2)
	require.Equal(t, "O", req.Targets[0].Content)
	require.Equal(t, "N", req.Targets[1].Content)
}

func TestParseRequest_PreToolUseMultiEdit(t *testing.T) {
	in := `{"hook_event_name":"PreToolUse","tool_name":"MultiEdit","tool_input":{"edits":[{"old_string":"a","new_string":"b"},{"old_string":"c","new_string":"d"}]}}`
	req, _, err := New().ParseRequest(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, req.Targets, 4)
	contents := []string{}
	for _, tg := range req.Targets {
		contents = append(contents, tg.Content)
	}
	require.Equal(t, []string{"a", "c", "b", "d"}, contents)
}

func TestParseRequest_UserPromptSubmit(t *testing.T) {
	in := `{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`
	req, _, err := New().ParseRequest(strings.NewReader(in))
	require.NoError(t, err)
	require.Equal(t, harness.DirObserve, req.Direction)
	require.Len(t, req.Targets, 1)
	require.Equal(t, "hello", req.Targets[0].Content)
	require.Equal(t, []string{"prompt"}, req.Targets[0].Path)
}

func TestParseRequest_UnknownEvent(t *testing.T) {
	in := `{"hook_event_name":"Garbage"}`
	_, _, err := New().ParseRequest(strings.NewReader(in))
	require.Error(t, err)
}

func TestEmitResponse_PostToolUseModified(t *testing.T) {
	original := json.RawMessage(`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"sk_live_xyz"}}`)
	resp := &harness.Response{
		Modified: true,
		Targets: []harness.Target{
			{Path: []string{"content"}, Content: "{{MASK_1}}", Encoding: "utf8"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, New().EmitResponse(&buf, original, resp))

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "PostToolUse", hso["hookEventName"])
	updated, ok := hso["updatedToolOutput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "{{MASK_1}}", updated["content"])
}

func TestEmitResponse_DenyBlock(t *testing.T) {
	resp := &harness.Response{DenyReason: "bad"}
	var buf bytes.Buffer
	require.NoError(t, New().EmitResponse(&buf, nil, resp))

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	require.Equal(t, "block", out["decision"])
	require.Equal(t, "bad", out["reason"])
}

func TestEmitResponse_PostUnmodified(t *testing.T) {
	original := json.RawMessage(`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"x"}}`)
	resp := &harness.Response{Modified: false}
	var buf bytes.Buffer
	require.NoError(t, New().EmitResponse(&buf, original, resp))
	require.Equal(t, "{}", strings.TrimSpace(buf.String()))
}

func TestEmitResponse_PromptAdditionalContext(t *testing.T) {
	original := json.RawMessage(`{"hook_event_name":"UserPromptSubmit","prompt":"hi"}`)
	resp := &harness.Response{Notes: []string{"warn1"}}
	var buf bytes.Buffer
	require.NoError(t, New().EmitResponse(&buf, original, resp))

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "UserPromptSubmit", hso["hookEventName"])
	require.Equal(t, "warn1", hso["additionalContext"])
}

func TestEmitResponse_PreToolUseModified(t *testing.T) {
	original := json.RawMessage(`{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"old_string":"{{MASK_1}}","new_string":"N"}}`)
	resp := &harness.Response{
		Modified: true,
		Targets: []harness.Target{
			{Path: []string{"old_string"}, Content: "sk_live_xyz", Encoding: "utf8"},
			{Path: []string{"new_string"}, Content: "N", Encoding: "utf8"},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, New().EmitResponse(&buf, original, resp))

	var out map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "PreToolUse", hso["hookEventName"])
	require.Equal(t, "allow", hso["permissionDecision"])
	updated, ok := hso["updatedInput"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "sk_live_xyz", updated["old_string"])
	require.Equal(t, "N", updated["new_string"])
}
