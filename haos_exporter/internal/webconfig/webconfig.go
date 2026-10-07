// Package webconfig writes the exporter-toolkit web configuration: basic
// auth always; TLS from an in-memory self-signed certificate or from
// provided files; optionally client certificates.
//
// The toolkit only reads its configuration from a file, and re-reads it on
// every request and TLS handshake, so the file must stay in place while the
// exporter runs. It is the only file the exporter writes.
package webconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v2"
)

// FileName is the name of the web configuration file inside the directory
// given to Write.
const FileName = "web-config.yml"

// CertValidity is the lifetime of the self-signed certificate. A new one is
// generated at every start.
const CertValidity = 365 * 24 * time.Hour

// Config is the input to Write.
type Config struct {
	Username     string
	PasswordHash string
	// TLS enables the in-memory self-signed certificate. It excludes
	// CertFile and KeyFile.
	TLS bool
	// DNSNames go into the self-signed certificate's SAN. Invalid names are
	// skipped.
	DNSNames []string
	// CertFile and KeyFile serve a provided certificate (tls_mode:
	// provided). The toolkit reads them on every connection, so they are
	// referenced, never copied.
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, makes every client present a certificate that
	// verifies against it.
	ClientCAFile string
}

// The toolkit's own types hold the secrets as config.Secret, which marshals
// as "<secret>", so the file is rendered from these plain structs.
type fileConfig struct {
	TLSServerConfig *tlsServerConfig  `yaml:"tls_server_config,omitempty"`
	BasicAuthUsers  map[string]string `yaml:"basic_auth_users"`
}

type tlsServerConfig struct {
	Cert           string `yaml:"cert,omitempty"`
	Key            string `yaml:"key,omitempty"`
	CertFile       string `yaml:"cert_file,omitempty"`
	KeyFile        string `yaml:"key_file,omitempty"`
	MinVersion     string `yaml:"min_version"`
	ClientAuthType string `yaml:"client_auth_type,omitempty"`
	ClientCAFile   string `yaml:"client_ca_file,omitempty"`
}

// Render returns the web configuration YAML.
func Render(cfg Config, now time.Time) ([]byte, error) {
	if cfg.Username == "" || cfg.PasswordHash == "" {
		return nil, errors.New("webconfig: basic auth username and hash are required")
	}
	files := cfg.CertFile != "" || cfg.KeyFile != ""
	switch {
	case cfg.TLS && files:
		return nil, errors.New("webconfig: the self-signed certificate and CertFile/KeyFile are exclusive")
	case files && (cfg.CertFile == "" || cfg.KeyFile == ""):
		return nil, errors.New("webconfig: CertFile and KeyFile go together")
	case cfg.ClientCAFile != "" && !cfg.TLS && !files:
		return nil, errors.New("webconfig: client certificates need TLS")
	}
	fc := fileConfig{BasicAuthUsers: map[string]string{cfg.Username: cfg.PasswordHash}}
	switch {
	case cfg.TLS:
		certPEM, keyPEM, err := SelfSigned(cfg.DNSNames, now)
		if err != nil {
			return nil, err
		}
		fc.TLSServerConfig = &tlsServerConfig{Cert: string(certPEM), Key: string(keyPEM)}
	case files:
		fc.TLSServerConfig = &tlsServerConfig{CertFile: cfg.CertFile, KeyFile: cfg.KeyFile}
	}
	if fc.TLSServerConfig != nil {
		fc.TLSServerConfig.MinVersion = "TLS13"
		if cfg.ClientCAFile != "" {
			fc.TLSServerConfig.ClientAuthType = "RequireAndVerifyClientCert"
			fc.TLSServerConfig.ClientCAFile = cfg.ClientCAFile
		}
	}
	return yaml.Marshal(fc)
}

// Write renders the configuration into dir/FileName with mode 0600,
// replacing any previous file, validates it with the toolkit, and returns
// its path.
func Write(dir string, cfg Config, now time.Time) (string, error) {
	data, err := Render(cfg, now)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, FileName)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("removing old web config: %w", err)
	}
	// O_EXCL: never write through a file or symlink someone else created.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("creating web config: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("writing web config: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("writing web config: %w", err)
	}
	if err := web.Validate(path); err != nil {
		return "", fmt.Errorf("web config does not validate: %w", err)
	}
	return path, nil
}

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9]{0,61}[A-Za-z0-9])?$`)

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// SelfSigned returns a PEM certificate and PKCS #8 key for a new ECDSA
// P-256 self-signed server certificate. It authenticates nothing: it only
// keeps the basic-auth credential off the wire in clear text.
func SelfSigned(dnsNames []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial: %w", err)
	}
	var names []string
	for _, n := range dnsNames {
		if validDNSName(n) {
			names = append(names, n)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "haos-exporter"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
