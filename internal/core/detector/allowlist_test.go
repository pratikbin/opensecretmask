package detector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowlistSet_Values(t *testing.T) {
	a, err := NewAllowlistSet([]string{"true", "localhost"}, nil, nil)
	require.NoError(t, err)
	require.True(t, a.AllowsValue("true"))
	require.True(t, a.AllowsValue("localhost"))
	require.False(t, a.AllowsValue("secret123"))
}

func TestAllowlistSet_Patterns(t *testing.T) {
	a, err := NewAllowlistSet(nil, []string{`^test_.*$`}, nil)
	require.NoError(t, err)
	require.True(t, a.AllowsValue("test_abc"))
	require.False(t, a.AllowsValue("prod_abc"))
}

func TestAllowlistSet_RuleDisabled(t *testing.T) {
	a, err := NewAllowlistSet(nil, nil, []string{"jwt"})
	require.NoError(t, err)
	require.True(t, a.RuleDisabled("jwt"))
	require.False(t, a.RuleDisabled("stripe"))
}

func TestAllowlistSet_BadPattern(t *testing.T) {
	a, err := NewAllowlistSet(nil, []string{`[(`}, nil)
	require.Error(t, err)
	require.Nil(t, a)
}

func TestAllowlistSet_NilReceiver(t *testing.T) {
	var a *AllowlistSet
	require.False(t, a.AllowsValue("x"))
	require.False(t, a.RuleDisabled("y"))
}
