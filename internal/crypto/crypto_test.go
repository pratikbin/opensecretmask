package crypto

import (
	"bytes"
	"testing"
)

func newTestCipher(t *testing.T, pass string) *Cipher {
	t.Helper()
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	c, err := NewCipher(pass, salt)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestEncryptRoundTrip(t *testing.T) {
	c := newTestCipher(t, "correct horse battery staple")
	want := []byte("sk-ant-api03-realsecretvalue")
	blob, err := c.Encrypt(want)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(blob, want) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, want)
	}
}

func TestEncryptNonceUnique(t *testing.T) {
	c := newTestCipher(t, "pass")
	a, _ := c.Encrypt([]byte("same"))
	b, _ := c.Encrypt([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of identical plaintext matched — nonce reuse")
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	salt, _ := NewSalt()
	good, _ := NewCipher("right-pass", salt)
	bad, _ := NewCipher("wrong-pass", salt)
	blob, _ := good.Encrypt([]byte("secret"))
	if _, err := bad.Decrypt(blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt with wrong passphrase, got %v", err)
	}
}

func TestDecryptShortBlob(t *testing.T) {
	c := newTestCipher(t, "pass")
	if _, err := c.Decrypt([]byte("tiny")); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for short blob, got %v", err)
	}
}

func TestIndexDeterministic(t *testing.T) {
	c := newTestCipher(t, "pass")
	a := c.Index([]byte("token"))
	b := c.Index([]byte("token"))
	if !bytes.Equal(a, b) {
		t.Fatal("Index not deterministic for equal input")
	}
	if bytes.Equal(a, c.Index([]byte("other"))) {
		t.Fatal("Index collision for different input")
	}
}

func TestIndexKeySeparation(t *testing.T) {
	salt, _ := NewSalt()
	c1, _ := NewCipher("pass-one", salt)
	c2, _ := NewCipher("pass-two", salt)
	if bytes.Equal(c1.Index([]byte("x")), c2.Index([]byte("x"))) {
		t.Fatal("Index identical across different passphrases")
	}
}
