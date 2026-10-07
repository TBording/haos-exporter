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
		{"key appended to server.crt", func(t *testing.T) string {
			dir, p := serverDir(t, testcerts.Server("haos-exporter"))
			both := append(append([]byte{}, p.CertPEM...), p.KeyPEM...)
			testcerts.WriteFile(t, filepath.Join(dir, ServerCertFile), both, 0o444)
			return dir
		}, "only certificates belong"},
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
			if strings.Contains(err.Error(), "-----BEGIN") {
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
