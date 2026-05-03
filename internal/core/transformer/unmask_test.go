package transformer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplace_BasicTwoMasks(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{
		"sk_live_AAA":          "sk_live_111",
		"AKIA1234567890123456": "AKIA0000000000000000",
	})
	in := "use sk_live_AAA and AKIA1234567890123456 now"
	out := idx.Replace(in)
	require.Equal(t, "use sk_live_111 and AKIA0000000000000000 now", out)
}

func TestReplace_NoMasks(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{
		"sk_live_AAA": "sk_live_111",
	})
	require.Equal(t, "no secrets here", idx.Replace("no secrets here"))
}

func TestReplace_OverlappingPreferLonger(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{
		"abcdef": "Z",
		"abc":    "Q",
	})
	require.Equal(t, "xxZxx", idx.Replace("xxabcdefxx"))
}

func TestReplace_AdjacentMasks(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{
		"AAA": "111",
		"BBB": "222",
	})
	require.Equal(t, "x 111222 y", idx.Replace("x AAABBB y"))
}

func TestReplace_EmptyIndex(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{})
	require.Equal(t, "hello", idx.Replace("hello"))

	var nilIdx *ReverseIndex
	require.Equal(t, "hello", nilIdx.Replace("hello"))
}

func TestReplace_PartialMaskNotReplaced(t *testing.T) {
	idx := BuildReverseIndex(map[string]string{
		"sk_live_AbCdEfGhIjKlMnOpQrSt": "sk_live_real",
	})
	in := "prefix sk_live_AbCdEfGh suffix"
	require.Equal(t, in, idx.Replace(in))
}
