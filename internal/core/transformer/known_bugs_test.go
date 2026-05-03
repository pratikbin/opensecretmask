package transformer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Known issues regression tests. Each test reproduces a bug documented in
// CLAUDE.md "Known issues" and is gated by t.Skip until the bug is fixed.
// Removing the t.Skip line MUST make the test pass once the underlying
// production code is corrected.

// Bug #1: maskSegments info-byte truncation — fpe.go:105 casts int span
// offsets to byte, losing high bits at offset >= 256. Two segments whose
// (start, end) pairs differ only in those high bits derive identical HKDF
// streams. Reproducer: rule with two segments at byte offsets (0, 5) and
// (256, 261). byte(256) == byte(0), byte(261) == byte(5) → collision.
func TestMaskSegments_InfoByteTruncationCollision_KnownBug(t *testing.T) {
	t.Skip("known: see CLAUDE.md known issues — fpe.go:105 byte(sp.start), byte(sp.end) " +
		"truncates >255 producing duplicate streams across segments. Spec-locked.")

	hasher := newKeymgrHasher(t)

	rule := Rule{
		ID:      "synthetic-collision",
		Pattern: regexp.MustCompile(`^([A-Za-z]{5}).{251}([A-Za-z]{5})$`),
		MinLen:  261, MaxLen: 261,
		Segments: []Segment{
			{Name: "first", Group: 1, Charset: CharsetAlphanumeric},
			{Name: "second", Group: 2, Charset: CharsetAlphanumeric},
		},
	}
	input := strings.Repeat("a", 5) + strings.Repeat("x", 251) + strings.Repeat("b", 5)
	require.Len(t, input, 261)

	masked, err := Mask(input, rule, hasher, map[string]string{})
	require.NoError(t, err)

	first := masked[0:5]
	second := masked[256:261]
	require.NotEqual(t, first, second,
		"post-fix: segments at colliding byte-truncated offsets must derive distinct streams")
}

// Bug #4: iohub/ahocorasick (cedar) panics on input containing the NUL byte
// (\x00). BuildReverseIndex passes secret keys directly to cedar.Insert
// without sanitization. Reproducer: feed a mask string containing \x00.
// Today this panics; post-fix it should return without panic and either
// skip the entry or sanitize the key.
func TestBuildReverseIndex_NULBytePanic_KnownBug(t *testing.T) {
	t.Skip("known: see CLAUDE.md known issues — iohub/ahocorasick panics on NUL byte. " +
		"BuildReverseIndex must sanitize input or replace the lib.")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("post-fix: BuildReverseIndex must not panic on NUL byte input; recovered: %v", r)
		}
	}()
	rev := BuildReverseIndex(map[string]string{"\x00mask\x00": "secret"})
	require.NotNil(t, rev)
}
