package claudecode

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain installs goleak as a tripwire. The claudecode package spawns no
// goroutines today; this test is a defensive guard so future refactors
// that introduce background goroutines fail fast unless they clean up.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
