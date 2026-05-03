package claudecode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostToolUseFields(t *testing.T) {
	require.Equal(t, [][]string{{"content"}}, postToolUseFields("Read"))
	require.Equal(t, [][]string{{"stdout"}, {"stderr"}}, postToolUseFields("Bash"))
	require.Equal(t, [][]string{{"matches"}}, postToolUseFields("Grep"))
	require.Equal(t, [][]string{{"files"}}, postToolUseFields("Glob"))
	require.Equal(t, [][]string{{"content"}}, postToolUseFields("WebFetch"))
	require.Equal(t, [][]string{}, postToolUseFields("Unknown"))
}

func TestPreToolUseFields(t *testing.T) {
	require.Equal(t, [][]string{{"old_string"}, {"new_string"}}, preToolUseFields("Edit"))
	require.Equal(t, [][]string{{"content"}}, preToolUseFields("Write"))
	require.Equal(t, [][]string{{"edits", "*", "old_string"}, {"edits", "*", "new_string"}}, preToolUseFields("MultiEdit"))
	require.Equal(t, [][]string{{"old_source"}, {"new_source"}}, preToolUseFields("NotebookEdit"))
	require.Equal(t, [][]string{{"command"}}, preToolUseFields("Bash"))
	require.Nil(t, preToolUseFields("Unknown"))
}
