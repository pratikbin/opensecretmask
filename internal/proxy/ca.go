// Package proxy is the CA-based HTTPS MITM proxy: it intercepts LLM API
// traffic, masks secrets outbound and unmasks them inbound.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "ca-cert.pem"
	caKeyFile  = "ca-key.pem"
)

// CA is a locally-generated certificate authority used to mint per-host leaf
// certificates for MITM interception. The private key never leaves the
// machine; it is what makes interception possible, so it is written 0600.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// GenerateCA creates a fresh root CA valid for ten years.
func GenerateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"opensecretmask"},
			CommonName:   "opensecretmask local CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newCA(cert, key)
}

func newCA(cert *x509.Certificate, key *ecdsa.PrivateKey) (*CA, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &CA{
		Cert:    cert,
		Key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// CertPEM returns the PEM-encoded CA certificate — safe to install in trust
// stores and to share.
func (c *CA) CertPEM() []byte { return c.certPEM }

// TLSCertificate returns the CA as a tls.Certificate for use as the MITM
// signing certificate.
func (c *CA) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{c.Cert.Raw},
		PrivateKey:  c.Key,
		Leaf:        c.Cert,
	}
}

// Save writes the CA certificate and private key into dir, both 0600.
func (c *CA) Save(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, caCertFile), c.certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, caKeyFile), c.keyPEM, 0o600)
}

// CertPath returns the path to the CA certificate within dir.
func CertPath(dir string) string { return filepath.Join(dir, caCertFile) }

// LoadCA reads a CA previously written by Save from dir.
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile)) // #nosec G304 -- opensecretmask's own CA in its config dir
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile)) // #nosec G304 -- opensecretmask's own CA in its config dir
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("proxy: malformed CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("proxy: malformed CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, certPEM: certPEM, keyPEM: keyPEM}, nil
}

