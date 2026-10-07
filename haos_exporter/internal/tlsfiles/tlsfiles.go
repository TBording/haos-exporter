// Package tlsfiles checks and reads the operator-provided TLS files in the
// app's config folder: server.crt and server.key for tls_mode: provided,
// and client-ca.crt for tls_client_auth. The exporter cannot write there
// (the folder is mounted read-only), and the toolkit re-reads the files on
// every connection, so replacing them rotates without a restart.
package tlsfiles

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// The config folder and the file names in it.
const (
	DefaultDir     = "/config"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
	ClientCAFile   = "client-ca.crt"
)

const maxFileBytes = 1 << 20

// CheckServer returns why dir's server certificate and key cannot be
// served, or nil. Errors name files and properties, never key material.
func CheckServer(dir string, now time.Time) error {
	keyPath := filepath.Join(dir, ServerKeyFile)
	// Stat follows a symlink, so a link to a group- or world-readable file
	// is refused too.
	st, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("server key %s has mode %#o: it must not be readable by group or others (chmod 0400 it)", keyPath, perm)
	}
	keyPEM, err := readFile(keyPath)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	certPEM, err := readFile(filepath.Join(dir, ServerCertFile))
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("server certificate and key: %w", err)
	}
	// X509KeyPair skips non-certificate blocks, so a key appended to
	// server.crt would pass it; refuse that here, as ServerExpiry would.
	if _, err := certificates(filepath.Join(dir, ServerCertFile)); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return fmt.Errorf("server certificate: %w", err)
		}
	}
	switch {
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("server certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return fmt.Errorf("server certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	case !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth):
		return errors.New("server certificate lacks the serverAuth extended key usage")
	case len(leaf.DNSNames)+len(leaf.IPAddresses) == 0:
		return errors.New("server certificate has no subject alternative name (DNS or IP); TLS clients ignore the common name")
	}
	return nil
}

// CheckClientCA returns why dir's client-ca.crt cannot be used to verify
// client certificates, or nil.
func CheckClientCA(dir string) error {
	_, err := ClientCAExpiry(dir)
	return err
}

// ServerExpiry returns the NotAfter of the first (leaf) certificate in
// server.crt.
func ServerExpiry(dir string) (time.Time, error) {
	certs, err := certificates(filepath.Join(dir, ServerCertFile))
	if err != nil {
		return time.Time{}, err
	}
	return certs[0].NotAfter, nil
}

// ClientCAExpiry returns the latest NotAfter in client-ca.crt. During a
// rotation the file holds the old and the new certificate, and the new
// one is what matters.
func ClientCAExpiry(dir string) (time.Time, error) {
	certs, err := certificates(filepath.Join(dir, ClientCAFile))
	if err != nil {
		return time.Time{}, err
	}
	latest := certs[0].NotAfter
	for _, c := range certs[1:] {
		if c.NotAfter.After(latest) {
			latest = c.NotAfter
		}
	}
	return latest, nil
}

// certificates parses the PEM blocks in path. Every block pem.Decode finds
// must be a parseable CERTIFICATE, otherwise the whole file fails, so a key
// pasted into a certificate file is refused rather than ignored. pem.Decode
// itself skips text between blocks and malformed or truncated PEM, so those
// are not detected; the file must still hold at least one certificate.
func certificates(path string) ([]*x509.Certificate, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s holds a %q block: only certificates belong there", path, block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return certs, nil
}

// readFile reads at most maxFileBytes; a larger file is an error.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxFileBytes)
	}
	return b, nil
}
