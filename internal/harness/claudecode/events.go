package claudecode

import (
	"fmt"

	"github.com/pratikbin/opensecretmask/internal/harness"
)

const (
	EventPostToolUse      = "PostToolUse"
	EventPreToolUse       = "PreToolUse"
	EventUserPromptSubmit = "UserPromptSubmit"
	EventSessionStart     = "SessionStart"
)

func eventDirection(event, tool string) (harness.Direction, error) {
	switch event {
	case EventPostToolUse:
		return harness.DirMask, nil
	case EventPreToolUse:
		return harness.DirUnmask, nil
	case EventUserPromptSubmit:
		return harness.DirObserve, nil
	case EventSessionStart:
		return harness.DirObserve, nil
	}
	return 0, fmt.Errorf("claudecode: unknown event %q", event)
}
