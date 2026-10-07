package webconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TBording/haos-exporter/haos_exporter/internal/testcerts"
	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v2"
	"golang.org/x/crypto/bcrypt"
)

const password = "scrape-password"

func testHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

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

func writeAndParse(t *testing.T, cfg Config) (string, parsed) {
	t.Helper()
	dir := t.TempDir()
	path, err := Write(dir, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, FileName) {
		t.Fatalf("path %s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("Write left %d files, want 1", len(entries))
	}
	b, _ := os.ReadFile(path)
	var p parsed
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return path, p
}

func TestTLSOff(t *testing.T) {
	h := testHash(t)
	path, p := writeAndParse(t, Config{Username: "prometheus", PasswordHash: h})
	if p.TLSServerConfig != nil {
		t.Fatal("tls_server_config present with TLS off")
	}
	if !reflect.DeepEqual(p.BasicAuthUsers, map[string]string{"prometheus": h}) {
		t.Fatalf("basic_auth_users %v", p.BasicAuthUsers)
	}
	if err := web.Validate(path); err != nil {
		t.Fatal(err)
	}
}

func TestSelfSigned(t *testing.T) {
	h := testHash(t)
	now := time.Now()
	path, p := writeAndParse(t, Config{
		Username: "user with space", PasswordHash: h, TLS: true,
		DNSNames: []string{"homeassistant", "homeassistant.local", "bad name", "", "-bad"},
	})
	if p.TLSServerConfig == nil {
		t.Fatal("tls_server_config missing")
	}
	if p.TLSServerConfig.MinVersion != "TLS13" {
		t.Fatalf("min_version %q, want TLS13", p.TLSServerConfig.MinVersion)
	}
	if p.TLSServerConfig.ClientAuthType != "" || p.TLSServerConfig.CertFile != "" {
		t.Fatalf("self-signed config has file or client-auth fields: %+v", *p.TLSServerConfig)
	}
	if p.BasicAuthUsers["user with space"] != h {
		t.Fatalf("basic_auth_users %v", p.BasicAuthUsers)
	}
	block, _ := pem.Decode([]byte(p.TLSServerConfig.Cert))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("key %T is not ECDSA P-256", cert.PublicKey)
	}
	if !reflect.DeepEqual(cert.DNSNames, []string{"homeassistant", "homeassistant.local"}) {
		t.Fatalf("SAN %v", cert.DNSNames)
	}
	if cert.NotBefore.After(now) || cert.NotAfter.Before(now.Add(364*24*time.Hour)) || cert.NotAfter.After(now.Add(CertValidity+time.Minute)) {
		t.Fatalf("validity %s - %s", cert.NotBefore, cert.NotAfter)
	}
	if cert.IsCA {
		t.Fatal("certificate is a CA")
	}
	if _, err := tls.X509KeyPair([]byte(p.TLSServerConfig.Cert), []byte(p.TLSServerConfig.Key)); err != nil {
		t.Fatal(err)
	}
	if err := web.Validate(path); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateChangesEveryStart(t *testing.T) {
	a, _, err := SelfSigned(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := SelfSigned(nil, time.Now())
	if string(a) == string(b) {
		t.Fatal("two certificates are identical")
	}
}

func TestWriteReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, FileName)
	if err := os.WriteFile(old, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := Write(dir, Config{Username: "prometheus", PasswordHash: testHash(t)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "stale") {
		t.Fatal("old content kept")
	}
}

func TestWriteRejectsIncompleteConfig(t *testing.T) {
	for _, cfg := range []Config{
		{Username: "", PasswordHash: "x"},
		{Username: "prometheus", PasswordHash: ""},
	} {
		if _, err := Write(t.TempDir(), cfg, time.Now()); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
	// A hash the toolkit cannot parse fails validation.
	if _, err := Write(t.TempDir(), Config{Username: "prometheus", PasswordHash: "not-bcrypt"}, time.Now()); err == nil {
		t.Error("invalid hash accepted")
	}
}

// TestServeRequiresBasicAuth serves through the toolkit with the generated
// file, as main does, and checks that authentication is enforced.
func TestServeRequiresBasicAuth(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "http"
		if useTLS {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			path, err := Write(t.TempDir(), Config{Username: "prometheus", PasswordHash: testHash(t), TLS: useTLS, DNSNames: []string{"localhost"}}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }), ReadHeaderTimeout: time.Second}
			flags := &web.FlagConfig{WebConfigFile: &path}
			done := make(chan error, 1)
			go func() { done <- web.Serve(l, srv, flags, slog.New(slog.DiscardHandler)) }()
			defer func() {
				srv.Close()
				<-done
			}()

			// Trust exactly the generated certificate, which also checks its SAN.
			roots := x509.NewCertPool()
			if useTLS {
				b, _ := os.ReadFile(path)
				var p parsed
				if err := yaml.Unmarshal(b, &p); err != nil {
					t.Fatal(err)
				}
				roots.AppendCertsFromPEM([]byte(p.TLSServerConfig.Cert))
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
			}}
			url := name + "://" + l.Addr().String() + "/metrics"
			for _, tt := range []struct {
				name       string
				user, pass string
				auth       bool
				want       int
			}{
				{"no credentials", "", "", false, http.StatusUnauthorized},
				{"wrong password", "prometheus", "wrong", true, http.StatusUnauthorized},
				{"wrong user", "other", password, true, http.StatusUnauthorized},
				{"right credentials", "prometheus", password, true, http.StatusOK},
			} {
				req, _ := http.NewRequest(http.MethodGet, url, nil)
				if tt.auth {
					req.SetBasicAuth(tt.user, tt.pass)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s: %v", tt.name, err)
				}
				resp.Body.Close()
				if resp.StatusCode != tt.want {
					t.Errorf("%s: status %d, want %d", tt.name, resp.StatusCode, tt.want)
				}
				if (resp.TLS != nil) != useTLS {
					t.Errorf("%s: TLS = %t, want %t", tt.name, resp.TLS != nil, useTLS)
				}
			}
		})
	}
}

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
		"self-signed and files":   {Username: "u", PasswordHash: h, TLS: true, CertFile: "/c", KeyFile: "/k"},
		"certificate without key": {Username: "u", PasswordHash: h, CertFile: "/c"},
		"client CA without TLS":   {Username: "u", PasswordHash: h, ClientCAFile: "/ca"},
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
	go func() {
		done <- web.Serve(l, srv, &web.FlagConfig{WebConfigFile: &path}, slog.New(slog.DiscardHandler))
	}()
	defer func() {
		srv.Close()
		<-done
	}()

	roots := x509.NewCertPool()
	roots.AddCert(server.Cert)
	stranger := testcerts.New(t, testcerts.Client("stranger"))
	// A certificate in Certificates is only sent when its issuer is one the
	// server advertises, so a stranger's would silently not be sent and the
	// server's chain check would go untested. GetClientCertificate always
	// sends it.
	get := func(cert *tls.Certificate) (int, error) {
		cfg := &tls.Config{RootCAs: roots, ServerName: "localhost"}
		if cert != nil {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
		}
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: cfg}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+l.Addr().String()+"/metrics", nil)
		req.SetBasicAuth("prometheus", password)
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	trusted, strangerCert := client.TLS(t), stranger.TLS(t)
	if code, err := get(&trusted); err != nil || code != http.StatusOK {
		t.Fatalf("trusted client: %d, %v", code, err)
	}
	if _, err := get(nil); err == nil || !strings.Contains(err.Error(), "certificate required") {
		t.Fatalf("a client without a certificate: err = %v, want certificate required", err)
	}
	// Sent, but not issued by client-ca.crt: refused by the chain check, not
	// for lack of a certificate.
	_, err = get(&strangerCert)
	if err == nil || strings.Contains(err.Error(), "certificate required") ||
		!(strings.Contains(err.Error(), "unknown certificate authority") || strings.Contains(err.Error(), "bad certificate")) {
		t.Fatalf("a client certificate outside client-ca.crt: err = %v, want a chain-verification alert", err)
	}
}
