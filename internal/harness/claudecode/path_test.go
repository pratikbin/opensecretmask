package claudecode

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtract_Simple(t *testing.T) {
	raw := json.RawMessage(`{"content":"hi"}`)
	got, err := extractByPath(raw, []string{"content"})
	require.NoError(t, err)
	require.Equal(t, []string{"hi"}, got)
}

func TestExtract_Nested(t *testing.T) {
	raw := json.RawMessage(`{"a":{"b":"x"}}`)
	got, err := extractByPath(raw, []string{"a", "b"})
	require.NoError(t, err)
	require.Equal(t, []string{"x"}, got)
}

func TestExtract_Wildcard(t *testing.T) {
	raw := json.RawMessage(`{"edits":[{"old":"a","new":"b"},{"old":"c","new":"d"}]}`)
	got, err := extractByPath(raw, []string{"edits", "*", "old"})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "c"}, got)
}

func TestExtract_Missing(t *testing.T) {
	raw := json.RawMessage(`{"content":"hi"}`)
	got, err := extractByPath(raw, []string{"nope"})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestReplace_Simple(t *testing.T) {
	raw := json.RawMessage(`{"content":"hi"}`)
	got, err := replaceByPath(raw, []string{"content"}, []string{"hello"})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(got, &m))
	require.Equal(t, "hello", m["content"])
}

func TestReplace_Wildcard(t *testing.T) {
	raw := json.RawMessage(`{"edits":[{"old":"a","new":"b"},{"old":"c","new":"d"}]}`)
	got, err := replaceByPath(raw, []string{"edits", "*", "old"}, []string{"A", "C"})
	require.NoError(t, err)

	vals, err := extractByPath(got, []string{"edits", "*", "old"})
	require.NoError(t, err)
	require.Equal(t, []string{"A", "C"}, vals)

	// untouched
	vals, err = extractByPath(got, []string{"edits", "*", "new"})
	require.NoError(t, err)
	require.Equal(t, []string{"b", "d"}, vals)
}

func TestReplace_RoundTrip(t *testing.T) {
	raw := json.RawMessage(`{"content":"original"}`)
	vals, err := extractByPath(raw, []string{"content"})
	require.NoError(t, err)
	got, err := replaceByPath(raw, []string{"content"}, vals)
	require.NoError(t, err)

	var a, b map[string]any
	require.NoError(t, json.Unmarshal(raw, &a))
	require.NoError(t, json.Unmarshal(got, &b))
	require.Equal(t, a, b)
}
