package keymgr

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestHasher(t *testing.T) *Hasher {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return NewHasher(key)
}

func TestMACDeterminism(t *testing.T) {
	h := newTestHasher(t)
	data := []byte("some-data-to-mac")
	a := h.MAC(data)
	b := h.MAC(data)
	require.Equal(t, a, b)
}

func TestStreamDeterminism(t *testing.T) {
	h := newTestHasher(t)
	info := []byte("charset:digits")

	a := make([]byte, 64)
	_, err := io.ReadFull(h.Stream(info), a)
	require.NoError(t, err)

	b := make([]byte, 64)
	_, err = io.ReadFull(h.Stream(info), b)
	require.NoError(t, err)

	require.Equal(t, a, b)
}

func TestStreamInfoDifferentiation(t *testing.T) {
	h := newTestHasher(t)

	a := make([]byte, 16)
	_, err := io.ReadFull(h.Stream([]byte("info-one")), a)
	require.NoError(t, err)

	b := make([]byte, 16)
	_, err = io.ReadFull(h.Stream([]byte("info-two")), b)
	require.NoError(t, err)

	require.NotEqual(t, a, b)
}
