// Package testcerts makes throwaway certificates and keys for tests. Only
// test code imports it, so it is never linked into the exporter.
package testcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Spec describes one certificate. Zero NotBefore and NotAfter mean an hour
// ago and a year from now. A nil Issuer makes it self-signed.
type Spec struct {
	CommonName  string
	DNSNames    []string
	ExtKeyUsage []x509.ExtKeyUsage
	NotBefore   time.Time
	NotAfter    time.Time
	IsCA        bool
	Issuer      *Pair
}

// Pair is a certificate and its ECDSA P-256 key, parsed and as PEM (the key
// as PKCS #8).
type Pair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
}

// Server is a valid server certificate for name.
func Server(name string) Spec {
	return Spec{CommonName: name, DNSNames: []string{name}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
}

// Client is a valid client certificate.
func Client(name string) Spec {
	return Spec{CommonName: name, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

// New makes the certificate s describes.
func New(t testing.TB, s Spec) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := s.NotBefore, s.NotAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: s.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           s.ExtKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              s.DNSNames,
	}
	if s.IsCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent, signer := tmpl, key
	if s.Issuer != nil {
		parent, signer = s.Issuer.Cert, s.Issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Cert:    cert,
		Key:     key,
	}
}

// TLS returns p as a client or server certificate for crypto/tls.
func (p Pair) TLS(t testing.TB) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// WriteFile replaces path with data at mode, atomically (write then
// rename), so a reader never sees a partial file.
func WriteFile(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile's mode is filtered by the umask.
	if err := os.Chmod(tmp, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// WriteServer writes p as dir/server.crt (0444) and dir/server.key (0400).
func WriteServer(t testing.TB, dir string, p Pair) {
	t.Helper()
	WriteFile(t, filepath.Join(dir, "server.crt"), p.CertPEM, 0o444)
	WriteFile(t, filepath.Join(dir, "server.key"), p.KeyPEM, 0o400)
}
