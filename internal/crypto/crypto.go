// Package crypto provides passphrase-derived authenticated encryption for
// secret values at rest, plus a deterministic index for dedup lookups.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen  = 16
	keyLen   = 32 // AES-256
	nonceLen = 12 // GCM standard nonce
	derived  = 64 // 32-byte AES key + 32-byte HMAC key

	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
)

// ErrDecrypt means the ciphertext failed authentication — a wrong passphrase
// or tampered data.
var ErrDecrypt = errors.New("crypto: decryption failed")

// NewSalt returns a fresh random salt for key derivation.
func NewSalt() ([]byte, error) {
	s := make([]byte, saltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Cipher encrypts/decrypts secret values and computes dedup indexes. Key
// material lives in memory only.
type Cipher struct {
	aead    cipher.AEAD
	hmacKey []byte
}

// NewCipher derives key material from passphrase + salt via Argon2id. The
// first 32 derived bytes key AES-256-GCM; the next 32 key the HMAC index, so
// the two uses never share a key.
func NewCipher(passphrase string, salt []byte) (*Cipher, error) {
	if len(salt) != saltLen {
		return nil, errors.New("crypto: bad salt length")
	}
	dk := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, derived)
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, hmacKey: dk[keyLen:]}, nil
}

// Encrypt returns nonce||ciphertext for plaintext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt, returning ErrDecrypt if authentication fails.
func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < nonceLen {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Index returns a deterministic HMAC-SHA256 tag for plaintext. Equal
// plaintexts yield equal tags under the same Cipher, enabling dedup lookups
// without decrypting stored rows.
func (c *Cipher) Index(plaintext []byte) []byte {
	m := hmac.New(sha256.New, c.hmacKey)
	m.Write(plaintext)
	return m.Sum(nil)
}

