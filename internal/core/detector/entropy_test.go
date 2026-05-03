package detector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntropy_AllSame(t *testing.T) {
	s := NewEntropyScanner(4.0, 1)
	require.Equal(t, 0.0, s.ScoreToken("aaaaaaaa"))
}

func TestEntropy_HighRandom(t *testing.T) {
	s := NewEntropyScanner(4.0, 8)
	// 32 distinct chars → entropy ~5.0 bits/char
	require.Greater(t, s.ScoreToken("abcdefghijklmnopqrstuvwxyz012345"), 4.0)
}

func TestEntropy_BelowMinLen(t *testing.T) {
	s := NewEntropyScanner(1.0, 10)
	require.False(t, s.IsSecret("short"))
}

func TestEntropy_AboveThreshold(t *testing.T) {
	s := NewEntropyScanner(4.0, 8)
	require.True(t, s.IsSecret("abcdefghijklmnopqrstuvwxyz012345"))
}
