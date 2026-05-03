package harness

import (
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/stretchr/testify/require"
)

func TestDirection_String(t *testing.T) {
	require.Equal(t, "mask", DirMask.String())
	require.Equal(t, "unmask", DirUnmask.String())
	require.Equal(t, "observe", DirObserve.String())
	require.Equal(t, "unknown", Direction(99).String())
}

func TestRequestResponse_StructLiteral(t *testing.T) {
	req := Request{
		Harness:   "claude-code",
		SessionID: "sess-1",
		EventName: "PreToolUse",
		Direction: DirMask,
		ToolName:  "Bash",
		Cwd:       "/tmp",
		Targets: []Target{{
			Path:     []string{"params", "command"},
			Content:  "echo hi",
			Encoding: "utf-8",
			Skip:     false,
		}},
	}
	require.Equal(t, "claude-code", req.Harness)
	require.Equal(t, "sess-1", req.SessionID)
	require.Equal(t, "PreToolUse", req.EventName)
	require.Equal(t, DirMask, req.Direction)
	require.Equal(t, "Bash", req.ToolName)
	require.Equal(t, "/tmp", req.Cwd)
	require.Len(t, req.Targets, 1)
	require.Equal(t, []string{"params", "command"}, req.Targets[0].Path)
	require.Equal(t, "echo hi", req.Targets[0].Content)
	require.Equal(t, "utf-8", req.Targets[0].Encoding)
	require.False(t, req.Targets[0].Skip)

	resp := Response{
		Modified: true,
		Targets: []Target{{
			Path:    []string{"params", "command"},
			Content: "echo {{MASK_1}}",
		}},
		Findings: []detector.Finding{{
			Start:      5,
			End:        10,
			Value:      "secret",
			Rule:       "test-rule",
			Confidence: 0.9,
		}},
		Notes:      []string{"masked 1 secret"},
		DenyReason: "",
	}
	require.True(t, resp.Modified)
	require.Len(t, resp.Targets, 1)
	require.Equal(t, "echo {{MASK_1}}", resp.Targets[0].Content)
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "test-rule", resp.Findings[0].Rule)
	require.Equal(t, 0.9, resp.Findings[0].Confidence)
	require.Equal(t, []string{"masked 1 secret"}, resp.Notes)
	require.Empty(t, resp.DenyReason)
}
