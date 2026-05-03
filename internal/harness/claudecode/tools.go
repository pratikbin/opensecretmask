package claudecode

func postToolUseFields(toolName string) [][]string {
	switch toolName {
	case "Read":
		// claude-code 2.x wraps Read response as { file: { content: ... } };
		// the legacy { content: ... } shape is kept for harness backward compat.
		return [][]string{{"file", "content"}, {"content"}}
	case "Bash":
		return [][]string{{"stdout"}, {"stderr"}}
	case "Grep":
		return [][]string{{"matches"}}
	case "Glob":
		return [][]string{{"files"}}
	case "WebFetch":
		return [][]string{{"content"}}
	}
	return [][]string{}
}

func preToolUseFields(toolName string) [][]string {
	switch toolName {
	case "Edit":
		return [][]string{{"old_string"}, {"new_string"}}
	case "Write":
		return [][]string{{"content"}}
	case "MultiEdit":
		return [][]string{{"edits", "*", "old_string"}, {"edits", "*", "new_string"}}
	case "NotebookEdit":
		return [][]string{{"old_source"}, {"new_source"}}
	case "Bash":
		return [][]string{{"command"}}
	}
	return nil
}
