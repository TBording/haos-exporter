# Verified TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship haos-exporter 0.4.0 with `tls_mode: provided`, which serves an operator-provided certificate that the scraper pins, and `tls_client_auth`, which requires a client certificate. The private key stays in the app's read-only config folder and out of backups.

**Architecture:**
- A new `internal/tlsfiles` package validates and reads `/config/server.crt`, `/config/server.key` and `/config/client-ca.crt`.
- `options` gains the new mode and flag.
- `webconfig` renders file-based TLS (TLS 1.3 minimum, optional client auth) for exporter-toolkit, which re-reads the files on every connection.
- A new live `tls` collector reports certificate expiry.
- `main` refuses to start on unusable files and wires everything together.
- The manifest maps `app_config` read-only with `backup_exclude: ["*.key"]`, AppArmor allows exactly three reads, and CI enforces both.

**Tech Stack:** Go 1.27 (`crypto/tls`, `crypto/x509`), `prometheus/exporter-toolkit` v0.20.0, `client_golang`, Python 3 + PyYAML for CI.

**Spec:** `docs/superpowers/specs/2026-10-03-verified-tls-design.md`

## Global Constraints

- `tls_mode` values are `self_signed`, `provided` and `off`, and the default stays `self_signed`. `tls_client_auth` is a bool with default `false`.
- File names: `server.crt`, `server.key`, `client-ca.crt` in the config folder, `/config` by default.
- `server.key` must have no group or other permission bits. The AppArmor rule is `owner /config/server.key r,`.
- AppArmor `/config` rules are exactly `/config/server.crt r,`, `owner /config/server.key r,` and `/config/client-ca.crt r,`.
- Manifest: `map: [{type: app_config, read_only: true}]` and `backup_exclude: ["*.key"]`. `version: "0.4.0"`.
- TLS 1.3 minimum (`min_version: TLS13`) in every TLS mode. With client auth: `client_auth_type: RequireAndVerifyClientCert`.
- Metric names:
  - `haos_exporter_tls_info{mode, client_auth}`;
  - `haos_exporter_tls_certificate_expiry_timestamp_seconds{cert="server"|"client_ca"}`;
  - collector label `tls`.
- No new Go module dependencies.
- No log line, error or metric may contain key material, the bcrypt hash, the token or the password.
- Nothing homelab-specific in this repo: no addresses, hostnames or Secret names. The homelab rollout lives in the monitor repo's plan.
- Commits use the `users.noreply.github.com` address (already set as the repo's `user.email`) and end with the `Co-Authored-By` trailer.

**Running Go:** there is no local Go toolchain. Every `go …` command in this plan runs in the pinned image, from the repository root:

```sh
docker run --rm -v "$PWD/haos_exporter:/src" -v haos-exporter-gomod:/go/pkg/mod -w /src \
  golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 \
  sh -c '<the go command>'
```

Before every test run that follows a code change, run `gofmt -w .` the same way. The code blocks below are written by hand, and gofmt owns the alignment of struct fields and literals.

## Review Focus

1. **`server.crt` holding a chain** (leaf, then intermediate) from an operator's own CA. It must be accepted, and the expiry reported must be the leaf's (Task 1).
2. **`client-ca.crt` with CRLF line endings, or text before the first PEM block,** as editors and copy-paste produce. It must parse (Task 1).
3. **A config-folder file larger than 1 MiB.** It must be refused with a size error, not read into memory (Task 1).
4. **Options saved by 0.3.x, which have no `tls_client_auth` key.** They must load as `false` with the mode unchanged (Task 2).
5. **`server.key` as a symlink to a file with group or other bits.** It must be refused, because `os.Stat` follows the link (Task 1).

---

### Task 1: `tlsfiles` package and test certificates

**Files:**
- Create: `haos_exporter/internal/testcerts/testcerts.go`
- Create: `haos_exporter/internal/tlsfiles/tlsfiles.go`
- Test: `haos_exporter/internal/tlsfiles/tlsfiles_test.go`

**Interfaces:**
- Produces (`testcerts`, imported only by tests):
  - `type Spec struct { CommonName string; DNSNames []string; ExtKeyUsage []x509.ExtKeyUsage; NotBefore, NotAfter time.Time; IsCA bool; Issuer *Pair }`
  - `type Pair struct { CertPEM, KeyPEM []byte; Cert *x509.Certificate; Key *ecdsa.PrivateKey }`
  - `func New(t testing.TB, s Spec) Pair`
  - `func Server(name string) Spec`, `func Client(name string) Spec`
  - `func (p Pair) TLS(t testing.TB) tls.Certificate`
  - `func WriteFile(t testing.TB, path string, data []byte, mode os.FileMode)`
  - `func WriteServer(t testing.TB, dir string, p Pair)`
- Produces (`tlsfiles`):
  - `const DefaultDir = "/config"`, `ServerCertFile = "server.crt"`, `ServerKeyFile = "server.key"`, `ClientCAFile = "client-ca.crt"`
  - `func CheckServer(dir string, now time.Time) error`
  - `func CheckClientCA(dir string) error`
  - `func ServerExpiry(dir string) (time.Time, error)`
  - `func ClientCAExpiry(dir string) (time.Time, error)`

- [ ] **Step 1: Write the test-certificate helper**

`haos_exporter/internal/testcerts/testcerts.go`:

```go
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
```

- [ ] **Step 2: Write the failing tests**

`haos_exporter/internal/tlsfiles/tlsfiles_test.go`:

```go
package tlsfiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"
)

func serverDir(t *testing.T, s testcerts.Spec) (string, testcerts.Pair) {
	t.Helper()
	dir := t.TempDir()
	p := testcerts.New(t, s)
	testcerts.WriteServer(t, dir, p)
	return dir, p
}

func TestCheckServerAcceptsAValidPair(t *testing.T) {
	dir, _ := serverDir(t, testcerts.Server("haos-exporter"))
	if err := CheckServer(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckServerAcceptsMode0600(t *testing.T) {
	dir, p := serverDir(t, testcerts.Server("haos-exporter"))
	testcerts.WriteFile(t, filepath.Join(dir, ServerKeyFile), p.KeyPEM, 0o600)
	if err := CheckServer(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckServerRefuses(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		setup func(t *testing.T) string
		want  string
	}{
		{"no files", func(t *testing.T) string { return t.TempDir() }, "server key"},
		{"no certificate", func(t *testing.T) string {
			dir, _ := serverDir(t, testcerts.Server("haos-exporter"))
			os.Remove(filepath.Join(dir, ServerCertFile))
			return dir
		}, "server certificate"},
		{"key readable by group", func(t *testing.T) string {
			dir, p := serverDir(t, testcerts.Server("haos-exporter"))
			testcerts.WriteFile(t, filepath.Join(dir, ServerKeyFile), p.KeyPEM, 0o440)
			return dir
		}, "must not be readable by group or others"},
		{"key readable by others", func(t *testing.T) string {
			dir, p := serverDir(t, testcerts.Server("haos-exporter"))
			testcerts.WriteFile(t, filepath.Join(dir, ServerKeyFile), p.KeyPEM, 0o404)
			return dir
		}, "must not be readable by group or others"},
		{"key symlinked to a readable file", func(t *testing.T) string {
			dir, p := serverDir(t, testcerts.Server("haos-exporter"))
			target := filepath.Join(t.TempDir(), "elsewhere.key")
			testcerts.WriteFile(t, target, p.KeyPEM, 0o644)
			os.Remove(filepath.Join(dir, ServerKeyFile))
			if err := os.Symlink(target, filepath.Join(dir, ServerKeyFile)); err != nil {
				t.Fatal(err)
			}
			return dir
		}, "must not be readable by group or others"},
		{"key from another pair", func(t *testing.T) string {
			dir, _ := serverDir(t, testcerts.Server("haos-exporter"))
			other := testcerts.New(t, testcerts.Server("haos-exporter"))
			testcerts.WriteFile(t, filepath.Join(dir, ServerKeyFile), other.KeyPEM, 0o400)
			return dir
		}, "server certificate and key"},
		{"expired", func(t *testing.T) string {
			s := testcerts.Server("haos-exporter")
			s.NotBefore, s.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
			dir, _ := serverDir(t, s)
			return dir
		}, "expired"},
		{"not yet valid", func(t *testing.T) string {
			s := testcerts.Server("haos-exporter")
			s.NotBefore, s.NotAfter = now.Add(24*time.Hour), now.Add(48*time.Hour)
			dir, _ := serverDir(t, s)
			return dir
		}, "not valid until"},
		{"client certificate", func(t *testing.T) string {
			s := testcerts.Client("haos-exporter")
			s.DNSNames = []string{"haos-exporter"}
			dir, _ := serverDir(t, s)
			return dir
		}, "serverAuth"},
		{"no subject alternative name", func(t *testing.T) string {
			s := testcerts.Server("haos-exporter")
			s.DNSNames = nil
			dir, _ := serverDir(t, s)
			return dir
		}, "subject alternative name"},
		{"oversized certificate", func(t *testing.T) string {
			dir, p := serverDir(t, testcerts.Server("haos-exporter"))
			big := append(bytes.Repeat([]byte("#"), maxFileBytes), p.CertPEM...)
			testcerts.WriteFile(t, filepath.Join(dir, ServerCertFile), big, 0o444)
			return dir
		}, "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckServer(tt.setup(t), now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatalf("error leaks key material: %v", err)
			}
		})
	}
}

func TestServerChainIsAcceptedAndReportsTheLeaf(t *testing.T) {
	ca := testcerts.New(t, testcerts.Spec{CommonName: "operator CA", IsCA: true, NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)})
	s := testcerts.Server("haos-exporter")
	s.Issuer = &ca
	leaf := testcerts.New(t, s)
	dir := t.TempDir()
	testcerts.WriteFile(t, filepath.Join(dir, ServerCertFile), append(append([]byte{}, leaf.CertPEM...), ca.CertPEM...), 0o444)
	testcerts.WriteFile(t, filepath.Join(dir, ServerKeyFile), leaf.KeyPEM, 0o400)
	if err := CheckServer(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := ServerExpiry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(leaf.Cert.NotAfter) {
		t.Fatalf("expiry %s, want the leaf's %s", got, leaf.Cert.NotAfter)
	}
}

func TestClientCA(t *testing.T) {
	now := time.Now()
	older := testcerts.Client("prometheus")
	older.NotAfter = now.Add(30 * 24 * time.Hour)
	newer := testcerts.Client("prometheus")
	newer.NotAfter = now.Add(400 * 24 * time.Hour)
	a, b := testcerts.New(t, older), testcerts.New(t, newer)

	tests := []struct {
		name    string
		content []byte
		want    time.Time
		errText string
	}{
		{name: "one certificate", content: a.CertPEM, want: a.Cert.NotAfter},
		{name: "bundle reports the latest", content: append(append([]byte{}, b.CertPEM...), a.CertPEM...), want: b.Cert.NotAfter},
		{name: "CRLF and leading text", content: append([]byte("client CA for the scraper\r\n"), bytes.ReplaceAll(a.CertPEM, []byte("\n"), []byte("\r\n"))...), want: a.Cert.NotAfter},
		{name: "empty", content: nil, errText: "no PEM certificate"},
		{name: "garbage", content: []byte("not a certificate\n"), errText: "no PEM certificate"},
		{name: "a private key in the bundle", content: append(append([]byte{}, a.CertPEM...), a.KeyPEM...), errText: "only certificates belong"},
		{name: "oversized", content: bytes.Repeat([]byte("#"), maxFileBytes+1), errText: "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			testcerts.WriteFile(t, filepath.Join(dir, ClientCAFile), tt.content, 0o444)
			got, err := ClientCAExpiry(dir)
			checkErr := CheckClientCA(dir)
			if tt.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.errText)
				}
				if checkErr == nil {
					t.Fatal("CheckClientCA accepted what ClientCAExpiry refused")
				}
				if strings.Contains(err.Error(), "PRIVATE KEY-----") {
					t.Fatalf("error leaks key material: %v", err)
				}
				return
			}
			if err != nil || checkErr != nil {
				t.Fatalf("err = %v, CheckClientCA = %v", err, checkErr)
			}
			if !got.Equal(tt.want) {
				t.Fatalf("expiry %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientCAMissing(t *testing.T) {
	if err := CheckClientCA(t.TempDir()); err == nil || !strings.Contains(err.Error(), ClientCAFile) {
		t.Fatalf("err = %v, want it to name %s", err, ClientCAFile)
	}
}

func TestServerExpiry(t *testing.T) {
	dir, p := serverDir(t, testcerts.Server("haos-exporter"))
	got, err := ServerExpiry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(p.Cert.NotAfter) {
		t.Fatalf("expiry %s, want %s", got, p.Cert.NotAfter)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/tlsfiles/` (in the Go image, as above)
Expected: FAIL, a build error naming the undefined `CheckServer`, `ServerExpiry` and so on.

- [ ] **Step 4: Write the implementation**

`haos_exporter/internal/tlsfiles/tlsfiles.go`:

```go
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

// certificates parses every PEM block in path. Any block that is not a
// parseable certificate fails the whole file, so a key pasted into a
// certificate file is refused rather than ignored.
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
```

The `block.Type` message quotes only the PEM type, such as `"PRIVATE KEY"`, never block content. The test checks that no `-----` armour line leaks.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/tlsfiles/ ./internal/testcerts/`
Expected: PASS.

Run: `gofmt -l . && go vet ./...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add haos_exporter/internal/testcerts haos_exporter/internal/tlsfiles
git commit -m "Add the tlsfiles package for provided TLS files

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: `provided` mode and `tls_client_auth` options

**Files:**
- Modify: `haos_exporter/internal/options/options.go`
- Test: `haos_exporter/internal/options/options_test.go`

**Interfaces:**
- Produces: `const TLSProvided = "provided"`, plus the field `Options.TLSClientAuth bool`, read from JSON `tls_client_auth`.

- [ ] **Step 1: Write the failing tests**

In `options_test.go`, add these cases to the `tests` slice in `TestNormalize`, after `"bad tls mode"`:

```go
		{
			name: "provided",
			in:   Options{BasicAuthPasswordHash: h, TLSMode: "provided"},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "provided", LogLevel: "info"},
		},
		{
			name: "provided with client auth",
			in:   Options{BasicAuthPasswordHash: h, TLSMode: "provided", TLSClientAuth: true},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "provided", TLSClientAuth: true, LogLevel: "info"},
		},
		{
			name: "self_signed with client auth",
			in:   Options{BasicAuthPasswordHash: h, TLSClientAuth: true},
			want: Options{BasicAuthUsername: "prometheus", BasicAuthPasswordHash: h, TLSMode: "self_signed", TLSClientAuth: true, LogLevel: "info"},
		},
		{name: "client auth without TLS", in: Options{BasicAuthPasswordHash: h, TLSMode: "off", TLSClientAuth: true}, errText: "tls_client_auth"},
```

Append these tests to the file:

```go
// Options saved by 0.3.x have no tls_client_auth key.
func TestFromSupervisorWithoutClientAuthKey(t *testing.T) {
	h := testHash(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"result":"ok","data":{"basic_auth_username":"prometheus","basic_auth_password_hash":%q,"tls_mode":"self_signed","log_level":"info"}}`, h)
	}))
	defer srv.Close()
	c, err := supervisor.New(srv.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	o, err := FromSupervisor(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if o.TLSClientAuth || o.TLSMode != TLSSelfSigned {
		t.Fatalf("got %+v, want self_signed without client auth", o)
	}
}

func TestOptionsPrintClientAuth(t *testing.T) {
	o := Options{TLSMode: TLSProvided, TLSClientAuth: true}
	if !strings.Contains(o.String(), "tls_client_auth=true") {
		t.Fatalf("String() = %s", o.String())
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "options", o)
	if !strings.Contains(buf.String(), "tls_client_auth=true") {
		t.Fatalf("LogValue = %s", buf.String())
	}
}
```

All the imports these use are already in the file: `context`, `fmt`, `log/slog`, `net/http`, `net/http/httptest`, `strings` and `supervisor`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/options/`
Expected: FAIL. It doesn't compile, because there is no field `TLSClientAuth`.

- [ ] **Step 3: Write the implementation**

In `options.go`, make these changes.

The TLS-modes constant block becomes:

```go
// TLS modes.
const (
	TLSSelfSigned = "self_signed"
	TLSProvided   = "provided"
	TLSOff        = "off"
)
```

In `Options`, add the field after `TLSMode`:

```go
	TLSClientAuth         bool   `json:"tls_client_auth"`
```

`String` becomes:

```go
// String never includes the password hash.
func (o Options) String() string {
	return fmt.Sprintf("basic_auth_username=%q basic_auth_password_hash_set=%t tls_mode=%q tls_client_auth=%t log_level=%q",
		o.BasicAuthUsername, o.BasicAuthPasswordHash != "", o.TLSMode, o.TLSClientAuth, o.LogLevel)
}
```

In `LogValue`, after the `tls_mode` line, add:

```go
		slog.Bool("tls_client_auth", o.TLSClientAuth),
```

In `normalize`, replace the `switch o.TLSMode` block with:

```go
	switch o.TLSMode {
	case TLSSelfSigned, TLSProvided, TLSOff:
	default:
		return fmt.Errorf("tls_mode must be %q, %q or %q", TLSSelfSigned, TLSProvided, TLSOff)
	}
	if o.TLSClientAuth && o.TLSMode == TLSOff {
		return errors.New("tls_client_auth needs TLS, but tls_mode is off")
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/options/ ./cmd/...`
Expected: PASS. `TestRunRefusesToStart`'s `"bad tls mode"` case still matches `tls_mode`.

- [ ] **Step 5: Commit**

```bash
git add haos_exporter/internal/options
git commit -m "Accept tls_mode provided and tls_client_auth

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Web-config rendering for provided files, TLS 1.3 and client auth

**Files:**
- Modify: `haos_exporter/internal/webconfig/webconfig.go`
- Test: `haos_exporter/internal/webconfig/webconfig_test.go`

**Interfaces:**
- Consumes: `testcerts.New`, `testcerts.Server`, `testcerts.Client`, `testcerts.WriteServer`, `testcerts.WriteFile` and `Pair.TLS` (Task 1).
- Produces: new fields on `webconfig.Config`: `CertFile string`, `KeyFile string` and `ClientCAFile string`.

- [ ] **Step 1: Write the failing tests**

In `webconfig_test.go`, replace the `parsed` type with the full set of fields. `writeAndParse` uses `UnmarshalStrict`, so every rendered key must be declared:

```go
type parsed struct {
	TLSServerConfig *struct {
		Cert           string `yaml:"cert"`
		Key            string `yaml:"key"`
		CertFile       string `yaml:"cert_file"`
		KeyFile        string `yaml:"key_file"`
		MinVersion     string `yaml:"min_version"`
		ClientAuthType string `yaml:"client_auth_type"`
		ClientCAFile   string `yaml:"client_ca_file"`
	} `yaml:"tls_server_config"`
	BasicAuthUsers map[string]string `yaml:"basic_auth_users"`
}
```

In `TestSelfSigned`, after the `if p.TLSServerConfig == nil` check, add:

```go
	if p.TLSServerConfig.MinVersion != "TLS13" {
		t.Fatalf("min_version %q, want TLS13", p.TLSServerConfig.MinVersion)
	}
	if p.TLSServerConfig.ClientAuthType != "" || p.TLSServerConfig.CertFile != "" {
		t.Fatalf("self-signed config has file or client-auth fields: %+v", *p.TLSServerConfig)
	}
```

Add `"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"` to the imports, then append:

```go
// providedDir writes a server pair and a client CA, and returns the
// directory and the pairs.
func providedDir(t *testing.T) (dir string, server, client testcerts.Pair) {
	t.Helper()
	dir = t.TempDir()
	server = testcerts.New(t, testcerts.Server("localhost"))
	client = testcerts.New(t, testcerts.Client("prometheus"))
	testcerts.WriteServer(t, dir, server)
	testcerts.WriteFile(t, filepath.Join(dir, "client-ca.crt"), client.CertPEM, 0o444)
	return dir, server, client
}

func TestProvidedFiles(t *testing.T) {
	dir, _, _ := providedDir(t)
	_, p := writeAndParse(t, Config{
		Username: "prometheus", PasswordHash: testHash(t),
		CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key"),
	})
	tc := p.TLSServerConfig
	if tc == nil {
		t.Fatal("tls_server_config missing")
	}
	if tc.CertFile != filepath.Join(dir, "server.crt") || tc.KeyFile != filepath.Join(dir, "server.key") {
		t.Fatalf("files %q %q", tc.CertFile, tc.KeyFile)
	}
	if tc.Cert != "" || tc.Key != "" {
		t.Fatal("provided mode copied certificate or key into the web config")
	}
	if tc.MinVersion != "TLS13" || tc.ClientAuthType != "" || tc.ClientCAFile != "" {
		t.Fatalf("unexpected TLS settings %+v", *tc)
	}
}

func TestClientAuthRendering(t *testing.T) {
	dir, _, _ := providedDir(t)
	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{"provided", Config{CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}},
		{"self_signed", Config{TLS: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Username, cfg.PasswordHash = "prometheus", testHash(t)
			cfg.ClientCAFile = filepath.Join(dir, "client-ca.crt")
			_, p := writeAndParse(t, cfg)
			if p.TLSServerConfig.ClientAuthType != "RequireAndVerifyClientCert" || p.TLSServerConfig.ClientCAFile != cfg.ClientCAFile {
				t.Fatalf("client auth not rendered: %+v", *p.TLSServerConfig)
			}
		})
	}
}

func TestRenderRefusesInconsistentTLS(t *testing.T) {
	h := testHash(t)
	for name, cfg := range map[string]Config{
		"self-signed and files":    {Username: "u", PasswordHash: h, TLS: true, CertFile: "/c", KeyFile: "/k"},
		"certificate without key":  {Username: "u", PasswordHash: h, CertFile: "/c"},
		"client CA without TLS":    {Username: "u", PasswordHash: h, ClientCAFile: "/ca"},
	} {
		if _, err := Render(cfg, time.Now()); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

func TestServeRequiresClientCertificate(t *testing.T) {
	dir, server, client := providedDir(t)
	path, err := Write(t.TempDir(), Config{
		Username: "prometheus", PasswordHash: testHash(t),
		CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key"),
		ClientCAFile: filepath.Join(dir, "client-ca.crt"),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }), ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- web.Serve(l, srv, &web.FlagConfig{WebConfigFile: &path}, slog.New(slog.DiscardHandler)) }()
	defer func() {
		srv.Close()
		<-done
	}()

	roots := x509.NewCertPool()
	roots.AddCert(server.Cert)
	stranger := testcerts.New(t, testcerts.Client("stranger"))
	get := func(certs []tls.Certificate) (int, error) {
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: certs},
		}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+l.Addr().String()+"/metrics", nil)
		req.SetBasicAuth("prometheus", password)
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get([]tls.Certificate{client.TLS(t)}); err != nil || code != http.StatusOK {
		t.Fatalf("trusted client: %d, %v", code, err)
	}
	if _, err := get(nil); err == nil {
		t.Fatal("a client without a certificate was served")
	}
	if _, err := get([]tls.Certificate{stranger.TLS(t)}); err == nil {
		t.Fatal("a client certificate outside client-ca.crt was served")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/webconfig/`
Expected: FAIL. It doesn't compile, because `Config` has no `CertFile`, `KeyFile` or `ClientCAFile`.

- [ ] **Step 3: Write the implementation**

In `webconfig.go`, change the package comment's first line to:

```go
// Package webconfig writes the exporter-toolkit web configuration: basic
// auth always; TLS from an in-memory self-signed certificate or from
// provided files; optionally client certificates.
```

`Config` and the file types become:

```go
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
```

`Render` becomes:

```go
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
```

`Write` is unchanged. Its `web.Validate` call now also loads the provided files, which is an extra check at start.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/webconfig/ ./cmd/...`
Expected: PASS. `TestServeRequiresBasicAuth` still passes, because Go's client negotiates TLS 1.3.

- [ ] **Step 5: Commit**

```bash
git add haos_exporter/internal/webconfig
git commit -m "Render provided TLS files, TLS 1.3 and client auth

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: `tls` collector

**Files:**
- Create: `haos_exporter/internal/collector/tls.go`
- Modify: `haos_exporter/internal/collector/labels.go` (one constant)
- Modify: `haos_exporter/internal/collector/exporter.go` (the `Config` field, and wiring in `New`)
- Test: `haos_exporter/internal/collector/tls_test.go`

**Interfaces:**
- Consumes: `tlsfiles.ServerExpiry`, `tlsfiles.ClientCAExpiry` and `tlsfiles.ServerCertFile`/`ClientCAFile` (Task 1); `testcerts` (Task 1).
- Produces: `type TLSConfig struct { Dir string; Server bool; ClientCA bool }` and the field `Config.TLS *TLSConfig`.

- [ ] **Step 1: Write the failing tests**

`haos_exporter/internal/collector/tls_test.go`:

```go
package collector

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"
)

const tlsExpiryMetric = "haos_exporter_tls_certificate_expiry_timestamp_seconds"

func tlsExporter(t *testing.T, cfg TLSConfig) *Exporter {
	t.Helper()
	e, err := New(Config{TLS: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestTLSExpiry(t *testing.T) {
	dir := t.TempDir()
	server := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, dir, server)
	old := testcerts.Client("prometheus")
	old.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	a, b := testcerts.New(t, old), testcerts.New(t, testcerts.Client("prometheus"))
	testcerts.WriteFile(t, filepath.Join(dir, "client-ca.crt"), append(append([]byte{}, a.CertPEM...), b.CertPEM...), 0o444)

	mfs := collectOnce(t, tlsExporter(t, TLSConfig{Dir: dir, Server: true, ClientCA: true}))
	if successOf(t, mfs, collectorTLS) != 1 {
		t.Fatal("tls collector failed")
	}
	for cert, want := range map[string]time.Time{"server": server.Cert.NotAfter, "client_ca": b.Cert.NotAfter} {
		if v, ok := value(mfs, tlsExpiryMetric, map[string]string{"cert": cert}); !ok || v != unixSeconds(want) {
			t.Errorf("%s expiry = %v (%t), want %v", cert, v, ok, unixSeconds(want))
		}
	}
}

func TestTLSExpiryFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	first := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, dir, first)
	e := tlsExporter(t, TLSConfig{Dir: dir, Server: true})
	collectOnce(t, e)
	later := testcerts.Server("haos-exporter")
	later.NotAfter = time.Now().Add(700 * 24 * time.Hour)
	second := testcerts.New(t, later)
	testcerts.WriteServer(t, dir, second)
	mfs := collectOnce(t, e)
	if v, _ := value(mfs, tlsExpiryMetric, map[string]string{"cert": "server"}); v != unixSeconds(second.Cert.NotAfter) {
		t.Fatalf("expiry %v after rotation, want %v", v, unixSeconds(second.Cert.NotAfter))
	}
}

func TestTLSCollectorFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	testcerts.WriteServer(t, dir, testcerts.New(t, testcerts.Server("haos-exporter")))
	e := tlsExporter(t, TLSConfig{Dir: dir, Server: true, ClientCA: true}) // no client-ca.crt
	mfs := collectOnce(t, e)
	if successOf(t, mfs, collectorTLS) != 0 {
		t.Fatal("tls collector succeeded without client-ca.crt")
	}
	if n := countSeries(mfs, tlsExpiryMetric); n != 0 {
		t.Fatalf("%d expiry series emitted by a failed collector", n)
	}
}

func TestTLSCollectorAbsentWithoutProvidedFiles(t *testing.T) {
	for _, cfg := range []*TLSConfig{nil, {Dir: t.TempDir()}} {
		e, err := New(Config{TLS: cfg})
		if err != nil {
			t.Fatal(err)
		}
		mfs := collectOnce(t, e)
		if _, ok := value(mfs, "haos_exporter_collector_success", map[string]string{"collector": collectorTLS}); ok {
			t.Fatalf("tls collector present for %+v", cfg)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/collector/ -run TLS`
Expected: FAIL. It doesn't compile, because `TLSConfig` and `collectorTLS` are undefined.

- [ ] **Step 3: Write the implementation**

In `labels.go`, add to the collector-name constants after `collectorCoreProbe`:

```go
	collectorTLS            = "tls"
```

`haos_exporter/internal/collector/tls.go`:

```go
package collector

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/TBording/haos-exporter/haos_exporter/internal/tlsfiles"
)

// TLSConfig enables the tls collector, which reports when the
// operator-provided certificates expire. It re-reads the files on every
// scrape, so a rotation shows up without a restart.
type TLSConfig struct {
	// Dir is the config folder holding the files.
	Dir string
	// Server reports server.crt (tls_mode: provided).
	Server bool
	// ClientCA reports client-ca.crt (tls_client_auth).
	ClientCA bool
}

var tlsExpiryDesc = prometheus.NewDesc(
	"haos_exporter_tls_certificate_expiry_timestamp_seconds",
	`When a provided certificate expires, in Unix seconds: cert="server" for server.crt, cert="client_ca" for the latest-expiring certificate in client-ca.crt.`,
	[]string{"cert"}, nil,
)

type tlsPart struct{ cfg TLSConfig }

func (tlsPart) name() string { return collectorTLS }

func (tlsPart) describe(ch chan<- *prometheus.Desc) { ch <- tlsExpiryDesc }

func (p tlsPart) update(_ *runState, b *batch) error {
	if p.cfg.Server {
		t, err := tlsfiles.ServerExpiry(p.cfg.Dir)
		if err != nil {
			return err
		}
		b.gauge(tlsExpiryDesc, unixSeconds(t), "server")
	}
	if p.cfg.ClientCA {
		t, err := tlsfiles.ClientCAExpiry(p.cfg.Dir)
		if err != nil {
			return err
		}
		b.gauge(tlsExpiryDesc, unixSeconds(t), "client_ca")
	}
	return nil
}
```

In `exporter.go`, add this field to `Config` after `Host`:

```go
	// TLS enables the provided-certificate collector. Nil, or neither
	// Server nor ClientCA set, disables it.
	TLS *TLSConfig
```

In `New`, add this just before `return e, nil`:

```go
	if cfg.TLS != nil && (cfg.TLS.Server || cfg.TLS.ClientCA) {
		e.live = append(e.live, tlsPart{cfg: *cfg.TLS})
	}
```

Also add `tls` to the package comment's list of live collectors. Its first paragraph becomes:

```go
// Collectors come in two kinds. The live ones (host, disk, pressure,
// core_probe, tls) run on every scrape and make no Supervisor calls. The
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/collector/`
Expected: PASS. The golden-file tests are unaffected, because their exporters have no `TLS` config.

- [ ] **Step 5: Commit**

```bash
git add haos_exporter/internal/collector
git commit -m "Report provided certificate expiry from a tls collector

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: Wire provided TLS into `main`, with end-to-end tests

**Files:**
- Modify: `haos_exporter/cmd/haos-exporter/main.go`
- Test: `haos_exporter/cmd/haos-exporter/main_test.go`

**Interfaces:**
- Consumes:
  - `tlsfiles.CheckServer`, `CheckClientCA`, `DefaultDir`, `ServerCertFile`, `ServerKeyFile` and `ClientCAFile` (Task 1);
  - `options.TLSProvided` and `Options.TLSClientAuth` (Task 2);
  - `webconfig.Config{CertFile, KeyFile, ClientCAFile}` (Task 3);
  - `collector.TLSConfig` and `collector.Config.TLS` (Task 4).
- Produces: the flag `--path.tls`, default `/config`, and the metric `haos_exporter_tls_info{mode, client_auth}`.

- [ ] **Step 1: Write the failing tests**

In `main_test.go`, add `"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"` to the imports, then append:

```go
func TestRunRefusesBadTLSFiles(t *testing.T) {
	h := testHash(t)
	now := time.Now()
	tests := []struct {
		name    string
		options map[string]any
		files   func(t *testing.T, dir string)
		want    string
	}{
		{"provided without files", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(*testing.T, string) {}, "server key"},
		{"provided with a group-readable key", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(t *testing.T, dir string) {
				p := testcerts.New(t, testcerts.Server("haos-exporter"))
				testcerts.WriteServer(t, dir, p)
				testcerts.WriteFile(t, filepath.Join(dir, "server.key"), p.KeyPEM, 0o640)
			}, "must not be readable by group or others"},
		{"provided with an expired certificate", map[string]any{"basic_auth_password_hash": h, "tls_mode": "provided"},
			func(t *testing.T, dir string) {
				s := testcerts.Server("haos-exporter")
				s.NotBefore, s.NotAfter = now.Add(-48*time.Hour), now.Add(-time.Hour)
				testcerts.WriteServer(t, dir, testcerts.New(t, s))
			}, "expired"},
		{"client auth without client-ca.crt", map[string]any{"basic_auth_password_hash": h, "tls_client_auth": true},
			func(*testing.T, string) {}, "client-ca.crt"},
		{"client auth with TLS off", map[string]any{"basic_auth_password_hash": h, "tls_mode": "off", "tls_client_auth": true},
			func(*testing.T, string) {}, "tls_client_auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsDir, configDir := t.TempDir(), t.TempDir()
			tt.files(t, tlsDir)
			var stderr lockedBuffer
			code := run(context.Background(), []string{
				"--supervisor.url=" + fakeSupervisor(t, tt.options),
				"--web.config-dir=" + configDir,
				"--web.listen-address=" + freeAddr(t),
				"--path.data=" + t.TempDir(),
				"--path.tls=" + tlsDir,
			}, getenv, &stderr)
			if code == 0 {
				t.Fatalf("run exited 0; log:\n%s", stderr.String())
			}
			log := stderr.String()
			if !strings.Contains(log, tt.want) {
				t.Fatalf("log does not mention %q:\n%s", tt.want, log)
			}
			for _, secret := range []string{testToken, h, "PRIVATE KEY-----"} {
				if strings.Contains(log, secret) {
					t.Fatalf("log leaks %q:\n%s", secret, log)
				}
			}
			if entries, _ := os.ReadDir(configDir); len(entries) != 0 {
				t.Fatalf("files written before refusing: %v", entries)
			}
		})
	}
}

// waitUp waits until addr accepts TCP connections, failing if run exits.
func waitUp(t *testing.T, addr string, done <-chan int, stderr *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		select {
		case code := <-done:
			t.Fatalf("run exited %d early:\n%s", code, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunProvidedTLSWithClientAuth(t *testing.T) {
	h := testHash(t)
	tlsDir, configDir := t.TempDir(), t.TempDir()
	server := testcerts.New(t, testcerts.Server("haos-exporter"))
	clientA := testcerts.New(t, testcerts.Client("prometheus"))
	clientB := testcerts.New(t, testcerts.Client("prometheus-next"))
	testcerts.WriteServer(t, tlsDir, server)
	testcerts.WriteFile(t, filepath.Join(tlsDir, "client-ca.crt"), clientA.CertPEM, 0o444)

	addr := freeAddr(t)
	var stderr lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{
			"--supervisor.url=" + fakeSupervisor(t, map[string]any{
				"basic_auth_password_hash": h, "tls_mode": "provided", "tls_client_auth": true,
			}),
			"--web.config-dir=" + configDir,
			"--web.listen-address=" + addr,
			"--path.data=" + t.TempDir(),
			"--path.tls=" + tlsDir,
		}, getenv, &stderr)
	}()
	waitUp(t, addr, done, &stderr)

	// Each request is a new connection, so file changes apply to it.
	scrape := func(pin *x509.Certificate, serverName string, client *testcerts.Pair) (int, []byte, error) {
		roots := x509.NewCertPool()
		roots.AddCert(pin)
		cfg := &tls.Config{RootCAs: roots, ServerName: serverName}
		if client != nil {
			cfg.Certificates = []tls.Certificate{client.TLS(t)}
		}
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: cfg}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
		req.SetBasicAuth("prometheus", testPassword)
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body, nil
	}

	code, body, err := scrape(server.Cert, "haos-exporter", &clientA)
	if err != nil || code != http.StatusOK {
		t.Fatalf("pinned scrape: %d, %v\n%s", code, err, stderr.String())
	}
	for _, want := range []string{
		`haos_exporter_tls_info{client_auth="true",mode="provided"} 1`,
		`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert="server"}`,
		`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert="client_ca"}`,
		`haos_exporter_collector_success{collector="tls"} 1`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("metrics lack %q", want)
		}
	}

	impostor := testcerts.New(t, testcerts.Server("haos-exporter"))
	for name, try := range map[string]func() (int, []byte, error){
		"no client certificate":   func() (int, []byte, error) { return scrape(server.Cert, "haos-exporter", nil) },
		"wrong pinned certificate": func() (int, []byte, error) { return scrape(impostor.Cert, "haos-exporter", &clientA) },
		"wrong server_name":       func() (int, []byte, error) { return scrape(server.Cert, "homeassistant", &clientA) },
		"client outside the CA":   func() (int, []byte, error) { return scrape(server.Cert, "haos-exporter", &clientB) },
	} {
		if _, _, err := try(); err == nil {
			t.Errorf("%s: served", name)
		}
	}
	if resp, err := http.Get("http://" + addr + "/metrics"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("plain HTTP served")
		}
	}

	// The web config references the key; it never holds it.
	wc, err := os.ReadFile(filepath.Join(configDir, "web-config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wc, []byte("PRIVATE KEY")) || !bytes.Contains(wc, []byte("cert_file")) {
		t.Fatalf("web config does not reference the files:\n%s", wc)
	}

	// Client rotation: client-ca.crt now trusts only B.
	testcerts.WriteFile(t, filepath.Join(tlsDir, "client-ca.crt"), clientB.CertPEM, 0o444)
	if code, _, err := scrape(server.Cert, "haos-exporter", &clientB); err != nil || code != http.StatusOK {
		t.Fatalf("rotated client: %d, %v", code, err)
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", &clientA); err == nil {
		t.Fatal("the retired client certificate was still served")
	}

	// Server rotation: the new pair is served without a restart.
	next := testcerts.New(t, testcerts.Server("haos-exporter"))
	testcerts.WriteServer(t, tlsDir, next)
	if code, _, err := scrape(next.Cert, "haos-exporter", &clientB); err != nil || code != http.StatusOK {
		t.Fatalf("rotated server: %d, %v", code, err)
	}
	if _, _, err := scrape(server.Cert, "haos-exporter", &clientB); err == nil {
		t.Fatal("the old server certificate was still served")
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d:\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown after cancel")
	}
	for _, secret := range []string{testToken, h, testPassword, "PRIVATE KEY-----"} {
		if strings.Contains(stderr.String(), secret) {
			t.Fatalf("log leaks %q", secret)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/... -run 'TestRunRefusesBadTLSFiles|TestRunProvidedTLSWithClientAuth'`
Expected: FAIL. `run` exits 2 with `unknown long flag '--path.tls'`.

- [ ] **Step 3: Write the implementation**

In `main.go`, make these changes.

Add to the imports `"path/filepath"`, `"strconv"` and `"github.com/TBording/haos-exporter/haos_exporter/internal/tlsfiles"`.

In the flag block, after `dataPath`, add:

```go
		tlsDir = app.Flag("path.tls", "The app's config folder, holding server.crt and server.key (tls_mode: provided) and client-ca.crt (tls_client_auth).").
			Default(tlsfiles.DefaultDir).String()
```

After `logger.Info("app options loaded", "options", opts)`, add:

```go
	if opts.TLSMode == options.TLSProvided {
		if err := tlsfiles.CheckServer(*tlsDir, time.Now()); err != nil {
			logger.Error("refusing to start: tls_mode is provided, but the server certificate cannot be served", "err", err)
			return 1
		}
	}
	if opts.TLSClientAuth {
		if err := tlsfiles.CheckClientCA(*tlsDir); err != nil {
			logger.Error("refusing to start: tls_client_auth is on, but client-ca.crt cannot be used", "err", err)
			return 1
		}
	}
```

In `collector.New(collector.Config{…})`, add the field:

```go
		TLS:        &collector.TLSConfig{Dir: *tlsDir, Server: opts.TLSMode == options.TLSProvided, ClientCA: opts.TLSClientAuth},
```

In `reg.MustRegister(…)`, add `tlsInfo(opts),` after `buildInfo(),`.

Replace the web-config block, from `wc := webconfig.Config{` through `wc.DNSNames = certNames(ctx, client, logger)` and its closing brace, with:

```go
	wc := webconfig.Config{
		Username:     opts.BasicAuthUsername,
		PasswordHash: opts.BasicAuthPasswordHash,
		TLS:          opts.TLSMode == options.TLSSelfSigned,
	}
	if wc.TLS {
		wc.DNSNames = certNames(ctx, client, logger)
	}
	if opts.TLSMode == options.TLSProvided {
		wc.CertFile = filepath.Join(*tlsDir, tlsfiles.ServerCertFile)
		wc.KeyFile = filepath.Join(*tlsDir, tlsfiles.ServerKeyFile)
	}
	if opts.TLSClientAuth {
		wc.ClientCAFile = filepath.Join(*tlsDir, tlsfiles.ClientCAFile)
	}
```

After `buildInfo`, add:

```go
// tlsInfo is haos_exporter_tls_info: the TLS mode and whether client
// certificates are required.
func tlsInfo(opts options.Options) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "haos_exporter",
		Name:      "tls_info",
		Help:      "The TLS configuration in use; the value is always 1.",
		ConstLabels: prometheus.Labels{
			"mode":        opts.TLSMode,
			"client_auth": strconv.FormatBool(opts.TLSClientAuth),
		},
	})
	g.Set(1)
	return g
}
```

- [ ] **Step 4: Run the whole module's tests**

Run: `go test -race -count=1 ./...`
Expected: PASS. The existing `self_signed` and `off` serving tests are unaffected. In those modes the tls collector is absent, and `tls_info` reports the mode.

Run: `gofmt -l . && go vet ./...`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add haos_exporter/cmd
git commit -m "Serve provided certificates and require client certificates

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: Manifest, AppArmor, UI strings and the CI manifest check

**Files:**
- Modify: `haos_exporter/config.yaml`
- Modify: `haos_exporter/apparmor.txt`
- Modify: `haos_exporter/translations/en.yaml`
- Modify: `haos_exporter/CHANGELOG.md`
- Modify: `ci/check_manifest.py`
- Create: `ci/test_check_manifest.py`
- Modify: `.github/workflows/ci.yml` (the `manifest` job)

**Interfaces:**
- Produces: `check_manifest.check(app_dir: Path) -> list[str]`, which is `main()`'s logic returning errors instead of printing them.

- [ ] **Step 1: Write the failing CI tests**

`ci/test_check_manifest.py`:

```python
"""Negative tests for check_manifest.py: each mutation of the real manifest
or profile must fail the check. Run: python3 -m unittest discover -s ci -p 'test_*.py'"""

import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

import check_manifest

APP = Path(__file__).resolve().parent.parent / "haos_exporter"


class CheckManifestTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.config = yaml.safe_load((APP / "config.yaml").read_text())
        self.profile = (APP / "apparmor.txt").read_text()

    def errors(self):
        (self.dir / "config.yaml").write_text(yaml.safe_dump(self.config))
        (self.dir / "apparmor.txt").write_text(self.profile)
        return check_manifest.check(self.dir)

    def assertFails(self, needle):
        errs = self.errors()
        self.assertTrue(any(needle in e for e in errs), f"no error mentions {needle!r}: {errs}")

    def test_real_manifest_passes(self):
        self.assertEqual(self.errors(), [])

    def test_writable_config_map(self):
        self.config["map"][0]["read_only"] = False
        self.assertFails("map must be exactly")

    def test_second_map_entry(self):
        self.config["map"].append({"type": "ssl", "read_only": True})
        self.assertFails("map must be exactly")

    def test_no_backup_exclude(self):
        del self.config["backup_exclude"]
        self.assertFails("backup_exclude")

    def test_client_auth_on_by_default(self):
        self.config["options"]["tls_client_auth"] = True
        self.assertFails("tls_client_auth")

    def test_config_write_rule(self):
        self.profile = self.profile.replace("/config/client-ca.crt r,", "/config/client-ca.crt rw,")
        self.assertFails("/config rules")

    def test_broader_config_rule(self):
        head, tail = self.profile.rsplit("}", 1)
        self.profile = head + "  /config/** r,\n}" + tail
        self.assertFails("/config rules")

    def test_key_rule_without_owner(self):
        self.profile = self.profile.replace("owner /config/server.key r,", "/config/server.key r,")
        self.assertFails("/config rules")

    def test_unknown_key(self):
        self.config["host_netwrk"] = True
        self.assertFails("ALLOWED_KEYS")

    def test_forbidden_key(self):
        self.config["ingress"] = True
        self.assertFails("must not be set")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest discover -s ci -p 'test_*.py'`
Expected: FAIL, with `AttributeError: module 'check_manifest' has no attribute 'check'`.

- [ ] **Step 3: Update the manifest, profile and strings**

`haos_exporter/config.yaml`. In the header comment, replace the line

```yaml
# - No docker_api / full_access / privileged / devices / uart / usb / map:
#   nothing needs them; /data is always mounted and statfs("/data") suffices.
```

with

```yaml
# - No docker_api / full_access / privileged / devices / uart / usb: nothing
#   needs them; /data is always mounted and statfs("/data") suffices.
# - map app_config read-only: the app's own config folder at /config, for
#   the operator-provided server.crt, server.key and client-ca.crt
#   (tls_mode: provided, tls_client_auth). No other map type.
# - backup_exclude *.key: the server key stays out of Home Assistant
#   backups; after a restore the operator generates a new one.
```

Set `version: "0.4.0"`. After `tmpfs: true`, add:

```yaml
map:
  - type: app_config
    read_only: true
backup_exclude:
  - "*.key"
```

In `options:`, after `tls_mode: self_signed`, add `tls_client_auth: false`. In `schema:`, replace the `tls_mode` line and add the new option:

```yaml
  tls_mode: "list(self_signed|provided|off)"
  tls_client_auth: bool
```

`haos_exporter/apparmor.txt`. Before the closing `}`, after the `/tmp` rules, add:

```
  # tls_mode: provided and tls_client_auth: the operator's files in the
  # app's read-only config folder (map: app_config). Exactly these three
  # reads. owner on the key: the profile refuses a key file that uid 65532
  # does not own, alongside the exporter's own mode check (no group or
  # other bits). ci/check_manifest.py pins these lines.
  /config/server.crt r,
  owner /config/server.key r,
  /config/client-ca.crt r,
```

`haos_exporter/translations/en.yaml`. Replace the `tls_mode` entry and add `tls_client_auth`:

```yaml
  tls_mode:
    name: TLS mode
    description: >-
      self_signed (default) serves HTTPS with a certificate generated in memory
      at every start; it protects the password on the network but does not
      prove the server's identity. "provided" serves server.crt and server.key
      from this app's config folder, so Prometheus can pin the certificate;
      see the Documentation tab. "off" serves plain HTTP and sends the
      password in clear text.
  tls_client_auth:
    name: Require client certificates
    description: >-
      Refuse any client that does not present a certificate trusted by
      client-ca.crt in this app's config folder. Needs TLS. Default: off.
```

`haos_exporter/CHANGELOG.md`. Above `## [0.3.1] - unreleased`, add:

```markdown
## [0.4.0] - unreleased

### Added

- `tls_mode: provided` serves `server.crt` and `server.key` from the app's
  config folder (`/config`, mapped read-only), so Prometheus can pin the
  certificate and an interceptor can no longer pose as the exporter
  (independent review, finding 1). The exporter refuses to start when the
  pair is missing, mismatched, expired, not yet valid, lacks `serverAuth` or
  a subject alternative name, or when the key is readable by group or
  others.
- `tls_client_auth` requires a client certificate trusted by
  `client-ca.crt`. A client without one is refused at the TLS handshake and
  never reaches the password check.
- `haos_exporter_tls_info{mode,client_auth}` and
  `haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}`, the latter
  from a new `tls` collector that re-reads the files on every scrape.

### Changed

- TLS 1.3 is the minimum version in every TLS mode.
- The manifest maps the app's own config folder read-only and excludes
  `*.key` from backups. After a restore, `provided` mode refuses to start
  until a new server key is generated.
- The AppArmor profile allows exactly three reads under `/config`.
```

- [ ] **Step 4: Update the check**

In `ci/check_manifest.py`, remove `"map",` from `FORBIDDEN_KEYS`, and add `"map",` and `"backup_exclude",` to `ALLOWED_KEYS`. Below `RE_PROFILE`, add:

```python
# The only rules the profile may have under /config (tls_mode: provided).
CONFIG_RULES = frozenset((
    "/config/server.crt r,",
    "owner /config/server.key r,",
    "/config/client-ca.crt r,",
))
```

Replace `main()` with `check()`, which returns the errors, plus a thin `main()`:

```python
def check(app_dir: Path) -> list[str]:
    """Return the manifest and profile errors in app_dir; empty means OK."""
    config = yaml.safe_load((app_dir / "config.yaml").read_text())
    errors = []

    def expect(key, want):
        got = config.get(key, "<missing>")
        if got != want:
            errors.append(f"config.yaml: {key} is {got!r}, want {want!r}")

    expect("hassio_api", True)
    expect("hassio_role", "default")
    expect("apparmor", True)
    expect("init", False)
    expect("tmpfs", True)

    for key in FORBIDDEN_KEYS:
        if key in config:
            errors.append(f"config.yaml: {key!r} must not be set (got {config[key]!r})")
    for key in sorted(set(config) - ALLOWED_KEYS - set(FORBIDDEN_KEYS)):
        errors.append(f"config.yaml: {key!r} is not in ALLOWED_KEYS (misspelled, or a new key to review)")

    if config.get("map") != [{"type": "app_config", "read_only": True}]:
        errors.append("config.yaml: map must be exactly [{type: app_config, read_only: true}]")
    if "*.key" not in (config.get("backup_exclude") or []):
        errors.append('config.yaml: backup_exclude must contain "*.key", so the server key stays out of backups')

    options = config.get("options", {})
    if options.get("basic_auth_password_hash", "<missing>") is not None:
        errors.append(
            "config.yaml: options.basic_auth_password_hash must default to null "
            "so the Supervisor refuses to start while it is unset"
        )
    if options.get("tls_mode") != "self_signed":
        errors.append("config.yaml: options.tls_mode must default to self_signed")
    if options.get("tls_client_auth") is not False:
        errors.append("config.yaml: options.tls_client_auth must default to false")

    profile = (app_dir / "apparmor.txt").read_text()
    names = [
        m.group(1)
        for m in (RE_PROFILE.match(line) for line in profile.splitlines())
        if m
    ]
    if len(names) != 1:
        errors.append(f"apparmor.txt: want exactly one ^profile line, found {len(names)}: {names}")
    if re.search(r"^\s*capability\b", profile, re.MULTILINE):
        errors.append("apparmor.txt: capability rules are not allowed")
    config_rules = {
        line.split("#", 1)[0].strip()
        for line in profile.splitlines()
        if "/config" in line.split("#", 1)[0]
    }
    if config_rules != CONFIG_RULES:
        errors.append(f"apparmor.txt: /config rules must be exactly {sorted(CONFIG_RULES)}, found {sorted(config_rules)}")
    return errors


def main() -> int:
    app_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "haos_exporter")
    errors = check(app_dir)
    for err in errors:
        print(f"FAIL {err}")
    if errors:
        return 1
    print(f"OK {app_dir}/config.yaml and apparmor.txt")
    return 0
```

In the module docstring, after the sentence ending `…cannot slip in unreviewed.`, add: `It also pins the read-only app_config map, the *.key backup exclusion and the three /config AppArmor rules.`

- [ ] **Step 5: Run the check and the tests**

Run: `python3 ci/check_manifest.py haos_exporter`
Expected: `OK haos_exporter/config.yaml and apparmor.txt`

Run: `python3 -m unittest discover -s ci -p 'test_*.py' -v`
Expected: 10 tests, all `ok`.

- [ ] **Step 6: Run the tests in CI**

In `.github/workflows/ci.yml`, in the `manifest` job's `Check config.yaml and apparmor.txt` step, add a fourth line to the `run:` block:

```yaml
          "$RUNNER_TEMP/venv/bin/python" -m unittest discover -s ci -p 'test_*.py' -v
```

- [ ] **Step 7: Commit**

```bash
git add haos_exporter/config.yaml haos_exporter/apparmor.txt haos_exporter/translations/en.yaml haos_exporter/CHANGELOG.md ci/ .github/workflows/ci.yml
git commit -m "Map the config folder read-only and pin it in CI (0.4.0)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: Documentation

**Files:**
- Modify: `README.md`
- Modify: `haos_exporter/DOCS.md`
- Modify: `DESIGN.md`
- Modify: `docs/public-flip-checklist.md`

No code. Each step names the exact text to replace. Run the scan in Step 5 before committing.

- [ ] **Step 1: README permission table and threat model**

In `README.md`'s "Requested" table, add after the `watchdog` row:

```markdown
| `map: app_config` (read-only) | This app's own config folder at `/config`, which no other app sees unless it maps every app's config folder | `tls_mode: provided` and `tls_client_auth` read `server.crt`, `server.key` and `client-ca.crt` there. The AppArmor profile allows exactly those three reads |
| `backup_exclude: ["*.key"]` | Leaves matching files out of Home Assistant backups | Not a privilege. The server key never enters a backup; after a restore, a new one is generated |
```

In the "Not requested" table, replace the `map` row with:

```markdown
| Any other `map` type, or `app_config` writable | Bind mounts of `homeassistant_config`, `share`, `backup`, `ssl`, `media` and so on, or write access to `/config` | Nothing; backup sizes come from the API, `/data` is always mounted, and the exporter only reads `/config` |
```

Under "### Assets", add this as item 4, after item 3 ("The metrics"):

```markdown
4. **The server key** (`tls_mode: provided`). `server.key` in the app's
   config folder, owned by uid 65532 with no group or other bits. It is
   readable by root on the host and by apps that map every app's config
   folder (Terminal & SSH, Studio Code Server, Samba). It is excluded from
   backups and never passes through the app options or the logs. With it,
   an interceptor could pose as the exporter.
```

In the LAN-attacker row, replace

```
It does not stop active interception: the scraper cannot verify the certificate (see Residual risks).
```

with

```
In `self_signed` mode that does not stop active interception, because the scraper cannot verify the certificate (see Residual risks). With `tls_mode: provided` the scraper pins the certificate, so an interceptor cannot pose as the exporter and never receives the password. With `tls_client_auth`, a client without a trusted certificate is refused at the TLS handshake, before any password check.
```

In "### Residual risks", replace the first bullet's opening sentence, `- **Self-signed TLS does not authenticate the server.** The certificate`, with:

```markdown
- **In `self_signed` mode, TLS does not authenticate the server.** Use
  `tls_mode: provided` to close this; the rest of this item applies only
  without it. The certificate
```

At the end of the "Failed logins…" bullet, after `(see DESIGN.md).`, add:

```markdown
  With `tls_client_auth`, a client without a trusted certificate never
  reaches bcrypt. A flood then costs one TLS 1.3 handshake per connection,
  hundreds of times cheaper than a bcrypt comparison, but it is not free.
```

- [ ] **Step 2: DOCS.md configuration, TLS and scrape config**

In the Configuration table, replace the `tls_mode` row and add `tls_client_auth`:

```markdown
| `tls_mode` | `self_signed` | `self_signed` serves HTTPS with a certificate generated in memory at every start. `provided` serves `server.crt` and `server.key` from this app's config folder (see Verified TLS). `off` serves plain HTTP. |
| `tls_client_auth` | `false` | Require a client certificate trusted by `client-ca.crt` in the config folder. Needs TLS. |
```

After the `### TLS` section's last paragraph (the one starting "`off` sends the password"), add:

````markdown
### Verified TLS (`provided`) and client certificates

With `tls_mode: provided`, Prometheus pins this app's certificate, so nothing
else can pose as the exporter. With `tls_client_auth: true`, the exporter
serves only a client that presents a certificate you issued. Use both.

The files live in this app's config folder. It is mounted read-only at
`/config` inside the app, and in the Terminal & SSH app it is
`/app_configs/<slug>`, where `<slug>` is the app's slug, for example
`local_haos_exporter` for a local install. Each private key is generated
where it is used: the server key on Home Assistant OS, and the client key
wherever Prometheus runs.

**1. The server pair**, in the Terminal & SSH app:

```sh
apk add openssl           # not installed by default; gone after the app restarts
D=/app_configs/<slug>
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj /CN=haos-exporter -addext subjectAltName=DNS:haos-exporter \
  -addext extendedKeyUsage=serverAuth -addext keyUsage=digitalSignature \
  -keyout "$D/server.key.new" -out "$D/server.crt.new"
chown 65532:65532 "$D/server.key.new" && chmod 0400 "$D/server.key.new"
chmod 0444 "$D/server.crt.new"
mv "$D/server.crt.new" "$D/server.crt" && mv "$D/server.key.new" "$D/server.key"
cat "$D/server.crt"       # public: copy it to Prometheus as its CA file
apk del openssl
```

The exporter refuses a key that it does not own, or that group or others can
read.

**2. The client pair**, on the machine that holds Prometheus's secrets:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj /CN=prometheus -addext extendedKeyUsage=clientAuth \
  -addext keyUsage=digitalSignature -keyout client.key -out client.crt
```

Copy only `client.crt` (public) to `/app_configs/<slug>/client-ca.crt`, mode
0444. `client.key` stays with Prometheus.

**3. Switch the options:** first `tls_mode: provided`, then, once Prometheus
presents its client certificate, `tls_client_auth: true`. Restart the app
after each change. The app refuses to start if a file is missing or wrong,
and its log says which.

**Rotation** needs no restart: the exporter re-reads the files on every
connection. Rotate the server certificate like this:
1. Generate the new pair as `*.new`.
2. Give Prometheus a CA file holding the old and the new certificate.
3. `mv` the new files into place.
4. Drop the old certificate from Prometheus's CA file.

The `mv` can fail one in-flight handshake, so at most one scrape fails. A
client rotation works the same way: `client-ca.crt` holds both certificates
while Prometheus switches.

`haos_exporter_tls_certificate_expiry_timestamp_seconds{cert}` reports both
expiry dates. Alert well before them.

**After a Home Assistant restore**, `server.key` is missing on purpose: it is
excluded from backups. The app refuses to start until you repeat step 1 and
give Prometheus the new certificate.
````

In "## Prometheus scrape config", replace the `tls_config:` block (the four comment lines and `insecure_skip_verify: true`) with:

```yaml
    tls_config:
      # tls_mode: provided. Pin the app's server.crt; its SAN is haos-exporter.
      ca_file: /etc/prometheus/secrets/haos-exporter/server.crt
      server_name: haos-exporter
      min_version: TLS13
      # tls_client_auth: true
      cert_file: /etc/prometheus/secrets/haos-exporter/client.crt
      key_file: /etc/prometheus/secrets/haos-exporter/client.key
      # With tls_mode: self_signed instead, there is nothing to verify: drop
      # the lines above and set insecure_skip_verify: true (see TLS).
```

Change the `password_file:` line in the same block to `password_file: /etc/prometheus/secrets/haos-exporter/password`.

In "## Security notes", replace the bullet that starts `- The exporter keeps no state.` with:

```markdown
- The exporter keeps no state. It writes nothing outside the `/tmp` tmpfs,
  `/data` holds nothing but what the Supervisor puts there, and `/config`
  is mounted read-only.
```

- [ ] **Step 3: DESIGN.md**

After the self-check table's closing paragraph (the one ending `` `ci/check_manifest.py` pins `hassio_role: default`. ``), add:

```markdown
### Verified TLS

`tls_mode: provided` and `tls_client_auth` are designed in
[`docs/superpowers/specs/2026-10-03-verified-tls-design.md`](docs/superpowers/specs/2026-10-03-verified-tls-design.md).
In short:

- **Where the key lives.** The exporter cannot write a key anywhere that
  persists (it is uid 65532, and `/data` is root's), so the operator places
  the key in the app's read-only `app_config` folder. `backup_exclude` keeps
  it out of backups.
- **Rotation.** exporter-toolkit re-reads the files on every connection, so
  both certificates rotate without a restart.
- **Failing closed.** The exporter refuses to start on a missing,
  mismatched, expired or over-readable pair.
```


- [ ] **Step 4: Public-flip checklist**

In `docs/public-flip-checklist.md`, section 4, after the item that adds `image:` to `config.yaml` (and its reinstall explanation), add:

```markdown
- [ ] **Place the TLS files again under the new slug.** The reinstall gives
      the app a new config folder, `/app_configs/<repo-prefix>_haos_exporter`.
      Generate a new server pair there (DOCS.md, Verified TLS), copy
      `client-ca.crt`, re-pin Prometheus, and delete the old
      `/app_configs/local_haos_exporter`, which survives uninstall and still
      holds the old key.
```

- [ ] **Step 5: Scan and commit**

Run: `python3 ~/.config/haos-exporter/public-flip-scan/scan.py ~/.config/haos-exporter/public-flip-scan/patterns.txt README.md haos_exporter/DOCS.md DESIGN.md docs/public-flip-checklist.md | grep -E ': [1-9]'`

Expected:
- Only the pre-existing hits of the Supervisor's own `172.30.32.0/23`.
- No address, hostname or domain introduced by this task. `haos-exporter` and `homeassistant` are product names, and the scan does not flag them.

```bash
git add README.md haos_exporter/DOCS.md DESIGN.md docs/public-flip-checklist.md
git commit -m "Document verified TLS, client certificates and rotation

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8: Full gates, image smoke test and the PR

**Files:** none new.

- [ ] **Step 1: Every CI gate locally**, from the repository root. Each must pass.

```sh
GO_IMAGE=golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
run_go() {
  docker run --rm -v "$PWD/haos_exporter:/src" -v haos-exporter-gomod:/go/pkg/mod \
    -w /src "$GO_IMAGE" sh -c "$1"
}
run_go 'test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }'
run_go 'go vet ./... && go test -race -count=1 ./...'
run_go 'go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...'
# manifest check and its tests
python3 ci/check_manifest.py haos_exporter
python3 -m unittest discover -s ci -p 'test_*.py'
# secrets, working tree and full history
gitleaks detect --source . --no-git --redact -v
gitleaks git --log-opts="--all" --redact -v .
```

- [ ] **Step 2: Image build and smoke test**

```sh
docker buildx build --platform linux/amd64 --build-arg BUILD_ARCH=amd64 \
  --build-arg BUILD_VERSION=0.4.0 --load -t haos-exporter:dev haos_exporter
docker run --rm --read-only --user 65532:65532 haos-exporter:dev --help 2>&1 | grep -- --path.tls
```

Expected: the help text lists `--path.tls`.

- [ ] **Step 3: Push and open the PR**

```bash
git push https://github.com/TBording/haos-exporter.git HEAD:verified-tls-spec
gh pr ready 11 -R TBording/haos-exporter
gh pr edit 11 -R TBording/haos-exporter --title "Verified TLS and mutual TLS for the metrics endpoint (0.4.0)"
```

Update the PR body:
- what 0.4.0 adds;
- the review-finding link;
- every test added, by name;
- "Not yet verified on a live Home Assistant OS host: see the monitor rollout plan."

- [ ] **Step 4: Wait for CI and merge**

Run: `gh pr checks 11 -R TBording/haos-exporter --watch`
Expected: all four checks pass. Then `gh pr merge 11 -R TBording/haos-exporter --squash --delete-branch`.

Merging does not finish the job. The live verification and rollout are in the monitor repo's plan, `docs/superpowers/plans/2026-10-03-haos-exporter-verified-tls-rollout.md`.
