package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Fatal("generated certificate is not a CA")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA cannot sign certificates")
	}
	if time.Until(ca.Cert.NotAfter) < 9*365*24*time.Hour {
		t.Fatalf("CA validity too short: expires %s", ca.Cert.NotAfter)
	}
}

func TestCASignsVerifiableLeaf(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "api.anthropic.com"},
		DNSNames:     []string{"api.anthropic.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.anthropic.com", Roots: pool}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}
}

func TestSaveLoadCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := ca.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if loaded.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Fatal("loaded CA serial does not match saved CA")
	}

	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("CA key file perms = %o, want 600", perm)
	}
}
