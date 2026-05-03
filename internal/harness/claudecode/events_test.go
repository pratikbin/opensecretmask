package claudecode

import (
	"testing"

	"github.com/pratikbin/opensecretmask/internal/harness"
	"github.com/stretchr/testify/require"
)

func TestEventDirection_All(t *testing.T) {
	cases := []struct {
		event string
		want  harness.Direction
	}{
		{EventPostToolUse, harness.DirMask},
		{EventPreToolUse, harness.DirUnmask},
		{EventUserPromptSubmit, harness.DirObserve},
		{EventSessionStart, harness.DirObserve},
	}
	for _, c := range cases {
		got, err := eventDirection(c.event, "")
		require.NoError(t, err, c.event)
		require.Equal(t, c.want, got, c.event)
	}
}

func TestEventDirection_Unknown(t *testing.T) {
	_, err := eventDirection("Garbage", "")
	require.Error(t, err)
}
